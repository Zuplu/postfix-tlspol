/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type CacheStruct struct {
	DaneLastAttempt   time.Time
	MtaStsLastAttempt time.Time
	*cache.Expirable
	Policy  string // legacy/selected policy, retained for old cache files and dumps
	Report  string
	Dane    PolicyBranch
	MtaSts  PolicyBranch
	TTL     uint32
	Counter uint32
}

type PolicyBranch struct {
	ExpiresAt time.Time
	Policy    string
	Report    string
	TTL       uint32
}

func (p PolicyBranch) HasData() bool {
	return p.TTL != 0 || !p.ExpiresAt.IsZero()
}

func (p PolicyBranch) RemainingTTL(t ...time.Time) uint32 {
	if !p.HasData() {
		return 0
	}
	now := time.Now()
	if len(t) != 0 {
		now = t[0]
	}
	ttl := p.ExpiresAt.Sub(now).Seconds()
	if ttl < 0 {
		return 0
	}
	return uint32(ttl)
}

func (p PolicyBranch) Age(t ...time.Time) uint32 {
	if !p.HasData() {
		return 0
	}
	now := time.Now()
	if len(t) != 0 {
		now = t[0]
	}
	age := now.Sub(p.ExpiresAt).Seconds()
	if age < 0 {
		return 0
	}
	return uint32(age)
}

func (c *CacheStruct) hasBranches() bool {
	return c != nil && (c.Dane.HasData() || c.MtaSts.HasData())
}

func (c *CacheStruct) RemainingTTL(t ...time.Time) uint32 {
	if c == nil {
		return 0
	}
	if !c.hasBranches() {
		if c.Expirable == nil {
			return 0
		}
		return c.Expirable.RemainingTTL(t...)
	}
	return max(c.Dane.RemainingTTL(t...), c.MtaSts.RemainingTTL(t...))
}

func (c *CacheStruct) Age(t ...time.Time) uint32 {
	if c == nil {
		return 0
	}
	if !c.hasBranches() {
		if c.Expirable == nil {
			return 0
		}
		return c.Expirable.Age(t...)
	}
	daneAge, mtaStsAge := c.Dane.Age(t...), c.MtaSts.Age(t...)
	if !c.Dane.HasData() {
		return mtaStsAge
	}
	if !c.MtaSts.HasData() {
		return daneAge
	}
	return min(daneAge, mtaStsAge)
}

func (c *CacheStruct) noPolicyOnly() bool {
	if c == nil {
		return false
	}
	if !c.hasBranches() {
		return c.Policy == ""
	}
	if c.Dane.HasData() && c.Dane.Policy != "" {
		return false
	}
	if c.MtaSts.HasData() && c.MtaSts.Policy != "" {
		return false
	}
	return c.Dane.HasData() || c.MtaSts.HasData()
}

func (c *CacheStruct) policyStateEmpty() bool {
	return c != nil && c.Policy == "" && c.Report == "" && c.TTL == 0 && !c.Dane.HasData() && !c.MtaSts.HasData()
}

func statsOnlyCacheEntry(counter uint32) *CacheStruct {
	return &CacheStruct{
		Expirable: &cache.Expirable{},
		Counter:   counter,
	}
}

func discardCachedPolicyState(haveLock bool, key string, c *CacheStruct) {
	counter := uint32(0)
	if c != nil {
		counter = c.Counter
	}
	counter += drainCacheHitCounter(key)
	if counter == 0 {
		polCache.Remove(haveLock, key)
		cleanupCacheHitCounterIfUnused(haveLock, key)
		return
	}
	polCache.Update(haveLock, key, func(*CacheStruct, bool) (*CacheStruct, bool) {
		return statsOnlyCacheEntry(counter), true
	})
	cleanupCacheHitCounterIfUnused(haveLock, key)
}

func cachedEntryLocked(key string) (*CacheStruct, bool) {
	var current *CacheStruct
	var found bool
	polCache.Update(true, key, func(c *CacheStruct, ok bool) (*CacheStruct, bool) {
		current, found = c, ok
		return nil, false
	})
	return current, found
}

func discardCachedPolicyStateIfCurrent(key string, expected *CacheStruct) (*CacheStruct, bool) {
	polCache.Lock()
	defer polCache.Unlock()
	current, found := cachedEntryLocked(key)
	if !found || current != expected {
		return current, false
	}
	discardCachedPolicyState(true, key, current)
	return nil, true
}

func removeCacheEntryIfCurrent(key string, expected *CacheStruct) (*CacheStruct, bool) {
	polCache.Lock()
	defer polCache.Unlock()
	current, found := cachedEntryLocked(key)
	if !found || current != expected {
		return current, false
	}
	polCache.Remove(true, key)
	return nil, true
}

func cloneCacheStruct(c *CacheStruct) *CacheStruct {
	if c == nil {
		return &CacheStruct{
			Expirable: &cache.Expirable{},
		}
	}
	cloned := *c
	if c.Expirable == nil {
		cloned.Expirable = &cache.Expirable{}
	} else {
		expirable := *c.Expirable
		cloned.Expirable = &expirable
	}
	return &cloned
}

const (
	CACHE_NOTFOUND_TTL          uint32 = 1800
	CACHE_MIN_TTL               uint32 = 180
	CACHE_MAX_TTL               uint32 = 2592000
	CACHE_MAX_AGE               uint32 = 1800 // max age for stale queries (only for prefetching, not served to postfix)
	CACHE_MAX_ENTRIES                  = 50000
	CACHE_PRUNE_TARGET                 = 45000
	REQUEST_TIMEOUT                    = 2 * time.Second
	POLICY_ATTEMPTS                    = 3
	POLICY_RETRY_BASE                  = 250 * time.Millisecond
	POLICY_BRANCH_RECHECK              = 24 * time.Hour
	DNS_UDP_PAYLOAD_SIZE        uint16 = 1232
	SOCKETMAP_MAX_CONNECTIONS          = 128
	SOCKETMAP_MAX_REQUEST_BYTES        = 1024
	SOCKETMAP_READ_TIMEOUT             = 30 * time.Second
	SOCKETMAP_WRITE_TIMEOUT            = 30 * time.Second
	METRICS_MAX_CONNECTIONS            = 64
	METRICS_MAX_HEADER_BYTES           = 8 << 10
	METRICS_READ_HEADER_TIMEOUT        = 5 * time.Second
	METRICS_READ_TIMEOUT               = 10 * time.Second
	METRICS_WRITE_TIMEOUT              = 10 * time.Second
	METRICS_IDLE_TIMEOUT               = 30 * time.Second
)

var (
	Version           = "undefined"
	bgCtx             = context.Background()
	levelVar          = new(slog.LevelVar)
	queryGroup        singleflight.Group
	client            = dns.Client{UDPSize: DNS_UDP_PAYLOAD_SIZE, Timeout: REQUEST_TIMEOUT}
	config            Config
	polCache          *cache.Cache[*CacheStruct]
	NS_NOTFOUND       = netstring.Marshal("NOTFOUND ")
	NS_TEMP           = netstring.Marshal("TEMP ")
	NS_PERM           = netstring.Marshal("PERM ")
	NS_TIMEOUT        = netstring.Marshal("TIMEOUT ")
	listeners         []net.Listener
	listenersMu       sync.Mutex
	serverWg          sync.WaitGroup
	connectionWg      sync.WaitGroup
	activeConnections sync.Map
	cachePruneMu      sync.Mutex
	cacheHitCounters  sync.Map
	showVersion       = false
	showLicense       = false
	configFile        string
	cliConnMode       = false
	checkDanePolicy   = checkDane
	checkMtaStsPolicy = checkMtaSts
)

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showLicense, "license", false, "Show LICENSE")
	flag.StringVar(&configFile, "config", "/etc/postfix-tlspol/config.yaml", "Path to the config.yaml")
	flag.String("query", "", "Query a domain")
	flag.Bool("dump", false, "Dump cache with query counter")
	flag.Bool("export", false, "Dump cache in postfix hash format")
	flag.Bool("purge", false, "Manually clear the cache")
}

func StartDaemon(v string, licenseText string) error {
	Version = v
	curYear, _, _ := time.Now().Date()

	flag.Parse()

	if showVersion {
		fmt.Printf("postfix-tlspol v%s\n", Version)
		return nil
	}

	if showLicense {
		fmt.Printf("%s\n", licenseText)
		return nil
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	levelVar.Set(config.Server.LogLevel)
	handlerOpts := &slog.HandlerOptions{
		Level: levelVar,
	}
	var handler slog.Handler
	if strings.ToLower(strings.TrimSpace(config.Server.LogFormat)) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	}
	slog.SetDefault(slog.New(handler))

	flag.Visit(flagCliConnFunc)

	if cliConnMode {
		return cliErr
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return nil
	}

	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — v%s\nThis program is licensed under the MIT License.\n", curYear, Version)

	if err := readEnv(); err != nil {
		return err
	}
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Duration(600*time.Second))
	_ = tidyCache()
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	bgCtx = daemonCtx
	defer cancelDaemon()
	listenForSignals(daemonCtx, cancelDaemon)

	var prefetchWg sync.WaitGroup
	prefetchWg.Add(1)
	go func() {
		defer prefetchWg.Done()
		startPrefetching(daemonCtx)
	}()
	serverErr := startServer()
	cancelDaemon()
	closeActiveConnections()
	connectionWg.Wait()
	prefetchWg.Wait()
	_ = tidyCache()
	cacheErr := polCache.CloseWithError()
	return errors.Join(serverErr, cacheErr)
}

func listenForSignals(ctx context.Context, cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		defer signal.Stop(signals)
		for {
			var sig os.Signal
			select {
			case sig = <-signals:
			case <-ctx.Done():
				return
			}
			if sig == syscall.SIGHUP {
				slog.Info("Received signal, saving cache", "signal", sig)
				_ = tidyCache()
				if err := polCache.ForceSave(false); err != nil {
					slog.Error("Could not save cache", "error", err)
				}
				continue
			}
			slog.Info("Received signal, shutting down", "signal", sig)
			cancel()
			closeActiveListeners()
			closeActiveConnections()
			return
		}
	}()
}

func readEnv() error {
	envPrefetch, envExists := os.LookupEnv("TLSPOL_PREFETCH")
	if envExists {
		if envPrefetch != "0" && envPrefetch != "1" {
			return fmt.Errorf("TLSPOL_PREFETCH must be 0 or 1")
		}
		config.Server.Prefetch = envPrefetch == "1"
	}
	envTlsRpt, envExists := os.LookupEnv("TLSPOL_TLSRPT")
	if envExists {
		if envTlsRpt != "0" && envTlsRpt != "1" {
			return fmt.Errorf("TLSPOL_TLSRPT must be 0 or 1")
		}
		config.Server.TlsRpt = envTlsRpt == "1"
	}
	return nil
}

func listenSystemdSocket() ([]net.Listener, bool, error) {
	listenPID, ok := os.LookupEnv("LISTEN_PID")
	if !ok {
		return nil, false, nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(listenPID))
	if err != nil || pid != os.Getpid() {
		return nil, false, nil
	}

	listenFDS, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		return nil, false, nil
	}
	fds, err := strconv.Atoi(strings.TrimSpace(listenFDS))
	if err != nil || fds < 1 {
		return nil, false, nil
	}

	listeners := make([]net.Listener, 0, fds)
	for i := 0; i < fds; i++ {
		fdNum := uintptr(3 + i)
		fdFile := os.NewFile(fdNum, fmt.Sprintf("systemd-listen-fd-%d", fdNum))
		if fdFile == nil {
			for _, existing := range listeners {
				existing.Close()
			}
			return nil, false, fmt.Errorf("could not open inherited systemd socket fd %d", fdNum)
		}

		l, err := net.FileListener(fdFile)
		fdFile.Close()
		if err != nil {
			for _, existing := range listeners {
				existing.Close()
			}
			return nil, false, fmt.Errorf("failed to inherit socket activation fd %d: %w", fdNum, err)
		}
		listeners = append(listeners, l)
	}

	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")

	return listeners, true, nil
}

func configuredAddressProvidedBySystemd(address string, addressConfigured bool, listeners []net.Listener) bool {
	address = strings.TrimSpace(address)
	if !addressConfigured || address == "" {
		return true
	}
	for _, listener := range listeners {
		if listener != nil && listenerAddressMatchesConfigured(address, listener.Addr()) {
			return true
		}
	}
	return false
}

func listenerAddressMatchesConfigured(address string, listenerAddress net.Addr) bool {
	if listenerAddress == nil {
		return false
	}
	if strings.HasPrefix(address, "unix:") {
		return strings.HasPrefix(listenerAddress.Network(), "unix") && address[5:] == listenerAddress.String()
	}
	if !strings.HasPrefix(listenerAddress.Network(), "tcp") {
		return false
	}
	if address == listenerAddress.String() {
		return true
	}

	tcpAddress, ok := listenerAddress.(*net.TCPAddr)
	if !ok {
		return false
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != tcpAddress.Port {
		return false
	}
	if host == "" {
		return tcpAddress.IP.IsUnspecified()
	}
	if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex >= 0 {
		if host[zoneIndex+1:] != tcpAddress.Zone {
			return false
		}
		host = host[:zoneIndex]
	}
	configuredIP := net.ParseIP(host)
	return configuredIP != nil && configuredIP.Equal(tcpAddress.IP)
}

func serveSocketmapListener(l net.Listener) {
	defer serverWg.Done()
	limited := newLimitedListener(l, SOCKETMAP_MAX_CONNECTIONS)

	for {
		conn, err := limited.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				break
			}
			addr := l.Addr()
			if addr == nil {
				slog.Error("Error accepting connection", "error", err, "network", "<unknown>", "address", "<unknown>")
			} else {
				slog.Error("Error accepting connection", "error", err, "network", addr.Network(), "address", addr.String())
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		connectionWg.Add(1)
		activeConnections.Store(conn, struct{}{})
		go func() {
			defer func() {
				activeConnections.Delete(conn)
				connectionWg.Done()
			}()
			handleConnection(conn)
		}()
	}
}

func serveMetricsListener(l net.Listener) {
	defer serverWg.Done()

	server := newMetricsHTTPServer(metricsHTTPServerConfig{
		ReadHeaderTimeout: METRICS_READ_HEADER_TIMEOUT,
		ReadTimeout:       METRICS_READ_TIMEOUT,
		WriteTimeout:      METRICS_WRITE_TIMEOUT,
		IdleTimeout:       METRICS_IDLE_TIMEOUT,
		MaxHeaderBytes:    METRICS_MAX_HEADER_BYTES,
	})
	err := server.Serve(newLimitedListener(l, METRICS_MAX_CONNECTIONS))
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		addr := l.Addr()
		if addr == nil {
			slog.Error("Metrics HTTP server terminated with error", "error", err, "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Error("Metrics HTTP server terminated with error", "error", err, "network", addr.Network(), "address", addr.String())
		}
	}
}

type metricsHTTPServerConfig struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

func newMetricsHTTPServer(cfg metricsHTTPServerConfig) *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(handleMetricsOnlyHTTPRequest),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

type limitedListener struct {
	net.Listener
	closeErr  error
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitedListener(l net.Listener, limit int) net.Listener {
	if limit <= 0 {
		return l
	}
	return &limitedListener{
		Listener: l,
		sem:      make(chan struct{}, limit),
		done:     make(chan struct{}),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{
		Conn:    conn,
		release: func() { <-l.sem },
	}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

type writeDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *writeDeadlineConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func listenConfiguredAddress(address string, permissions os.FileMode) (net.Listener, error) {
	if strings.HasPrefix(address, "unix:") {
		socketPath := address[5:]
		err := os.Remove(socketPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		l, err := net.Listen("unix", socketPath)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(socketPath, permissions); err != nil {
			l.Close()
			return nil, err
		}
		return l, nil
	}
	return net.Listen("tcp", address)
}

func closeListeners(toClose []net.Listener) {
	for _, l := range toClose {
		if l != nil {
			l.Close()
		}
	}
}

func setActiveListeners(active []net.Listener) {
	listenersMu.Lock()
	listeners = append([]net.Listener(nil), active...)
	listenersMu.Unlock()
}

func clearActiveListeners() {
	listenersMu.Lock()
	listeners = nil
	listenersMu.Unlock()
}

func closeActiveListeners() {
	listenersMu.Lock()
	active := append([]net.Listener(nil), listeners...)
	listenersMu.Unlock()
	closeListeners(active)
}

func closeActiveConnections() {
	activeConnections.Range(func(conn, _ any) bool {
		if c, ok := conn.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
}

func startServer() error {
	var err error
	socketmapListeners, inherited, err := listenSystemdSocket()
	if err != nil {
		return fmt.Errorf("inherit systemd-activated socket: %w", err)
	}

	if !inherited {
		if strings.TrimSpace(config.Server.Address) == "" {
			return errors.New("start socketmap server: server.address must not be empty without systemd socket activation")
		}
		var directListener net.Listener
		directListener, err = listenConfiguredAddress(config.Server.Address, config.Server.SocketPermissions)
		if err == nil {
			socketmapListeners = []net.Listener{directListener}
		}
	} else {
		slog.Info("Using systemd socket activation")
	}
	if err != nil {
		return fmt.Errorf("start socketmap server: %w", err)
	}

	if len(socketmapListeners) == 0 {
		return errors.New("start socketmap server: no listeners available")
	}

	if inherited {
		for _, l := range socketmapListeners {
			addr := l.Addr()
			if addr == nil {
				slog.Info("Server listening", "activation", "systemd", "network", "<unknown>", "address", "<unknown>")
				continue
			}
			slog.Info("Server listening", "activation", "systemd", "network", addr.Network(), "address", addr.String())
		}
		if !configuredAddressProvidedBySystemd(config.Server.Address, config.Server.addressConfigured, socketmapListeners) {
			slog.Warn("Ignoring configured server.address because systemd socket activation is active", "configured_address", config.Server.Address)
		}
		slog.Info("Listening on all systemd-provided sockets", "count", len(socketmapListeners))
	} else {
		addr := socketmapListeners[0].Addr()
		if addr == nil {
			slog.Info("Server listening", "activation", "direct", "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Info("Server listening", "activation", "direct", "network", addr.Network(), "address", addr.String())
		}
	}

	activeListeners := append([]net.Listener(nil), socketmapListeners...)

	var metricsListener net.Listener
	if metricsAddress := strings.TrimSpace(config.Server.MetricsAddress); metricsAddress != "" {
		metricsListener, err = listenConfiguredAddress(metricsAddress, config.Server.SocketPermissions)
		if err != nil {
			closeListeners(activeListeners)
			return fmt.Errorf("start metrics HTTP server: %w", err)
		}
		activeListeners = append(activeListeners, metricsListener)
		addr := metricsListener.Addr()
		if addr == nil {
			slog.Info("Metrics HTTP server listening", "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Info("Metrics HTTP server listening", "network", addr.Network(), "address", addr.String())
		}
	}

	setActiveListeners(activeListeners)
	defer clearActiveListeners()
	if bgCtx.Err() != nil {
		closeListeners(activeListeners)
		return nil
	}

	serverWg.Add(len(socketmapListeners))
	for _, l := range socketmapListeners {
		go serveSocketmapListener(l)
	}
	if metricsListener != nil {
		serverWg.Add(1)
		go serveMetricsListener(metricsListener)
	}
	serverWg.Wait()

	slog.Info("Servers terminated")
	return nil
}

func tryCachedPolicy(conn net.Conn, domain string, withTlsRpt bool) (*CacheStruct, bool) {
	c, found := polCache.Get(domain)
	if found {
		policy, report, ttl, ok := selectCachedPolicy(c, time.Now())
		if ok {
			var delivered bool
			switch policy {
			case "":
				slog.Debug("No policy found", "origin", "cache", "domain", domain, "ttl", ttl)
				delivered = writeConnectionResponse(conn, NS_NOTFOUND)
			default:
				slog.Debug("Evaluated policy", "origin", "cache", "domain", domain, "policy", firstWord(policy), "ttl", ttl)
				var res string
				if withTlsRpt {
					res = policy + " " + report
				} else {
					res = policy
				}
				delivered = writeConnectionResponse(conn, netstring.Marshal("OK "+res))
			}
			if delivered {
				observePolicy(policy)
			}
			observeCacheRequest(true)
			addCacheHitCounter(domain)
			return c, true
		}
	}
	return c, false
}

func addCacheHitCounter(domain string) {
	counter, _ := cacheHitCounters.LoadOrStore(domain, &atomic.Uint32{})
	counter.(*atomic.Uint32).Add(1)
}

func drainCacheHitCounter(domain string) uint32 {
	counter, ok := cacheHitCounters.Load(domain)
	if !ok {
		return 0
	}
	return counter.(*atomic.Uint32).Swap(0)
}

func cacheEntryCounter(domain string, c *CacheStruct) uint32 {
	if c == nil {
		return 0
	}
	counter := c.Counter
	if pending, ok := cacheHitCounters.Load(domain); ok {
		counter += pending.(*atomic.Uint32).Load()
	}
	return counter
}

func flushCacheHitCounters(haveLock bool) {
	cacheHitCounters.Range(func(key any, value any) bool {
		domain, ok := key.(string)
		if !ok {
			cacheHitCounters.Delete(key)
			return true
		}
		counter, ok := value.(*atomic.Uint32)
		if !ok {
			cacheHitCounters.Delete(domain)
			return true
		}
		delta := counter.Swap(0)
		if delta == 0 {
			cleanupCacheHitCounterIfUnused(haveLock, domain)
			return true
		}
		polCache.Update(haveLock, domain, func(c *CacheStruct, found bool) (*CacheStruct, bool) {
			if !found || c == nil {
				return nil, false
			}
			updated := cloneCacheStruct(c)
			updated.Counter += delta
			return updated, true
		})
		cleanupCacheHitCounterIfUnused(haveLock, domain)
		return true
	})
}

func cachedPolicyExists(haveLock bool, domain string) bool {
	exists := false
	polCache.Update(haveLock, domain, func(c *CacheStruct, found bool) (*CacheStruct, bool) {
		exists = found && cacheStructHasPolicy(c)
		return nil, false
	})
	return exists
}

func cacheStructHasPolicy(c *CacheStruct) bool {
	return c != nil && (c.Policy != "" || c.Dane.Policy != "" || c.MtaSts.Policy != "")
}

func cleanupCacheHitCounterIfUnused(haveLock bool, domain string) {
	value, ok := cacheHitCounters.Load(domain)
	if !ok {
		return
	}
	counter, ok := value.(*atomic.Uint32)
	if !ok {
		cacheHitCounters.Delete(domain)
		return
	}
	if counter.Load() != 0 || cachedPolicyExists(haveLock, domain) {
		return
	}
	if counter.Load() == 0 {
		cacheHitCounters.Delete(domain)
	}
}

func selectCachedPolicy(c *CacheStruct, now time.Time) (string, string, uint32, bool) {
	if c == nil {
		return "", "", 0, false
	}
	if !c.hasBranches() {
		if c.Expirable == nil || c.Expirable.RemainingTTL(now) == 0 {
			return "", "", 0, false
		}
		if c.Policy == "dane" || c.Policy == "dane-only" {
			return c.Policy, c.Report, c.Expirable.RemainingTTL(now), true
		}
		return "", "", 0, false
	}

	daneTTL := c.Dane.RemainingTTL(now)
	mtaStsTTL := c.MtaSts.RemainingTTL(now)
	if daneTTL == 0 {
		return "", "", 0, false
	}
	if c.Dane.Policy != "" {
		return c.Dane.Policy, c.Dane.Report, daneTTL, true
	}
	if mtaStsTTL != 0 {
		ttl := minPositive(daneTTL, mtaStsTTL)
		return c.MtaSts.Policy, c.MtaSts.Report, ttl, true
	}
	return "", "", 0, false
}

func minPositive(a uint32, b uint32) uint32 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

func normalizePolicyTTL(policy string, ttl uint32) (uint32, bool) {
	if policy == "TEMP" {
		return 0, false
	}
	if policy == "" && ttl == 0 {
		ttl = CACHE_NOTFOUND_TTL
	}
	if ttl < CACHE_MIN_TTL {
		ttl = CACHE_MIN_TTL
	} else if ttl > CACHE_MAX_TTL {
		ttl = CACHE_MAX_TTL
	}
	return ttl, true
}

func branchFromResult(policy string, report string, ttl uint32) PolicyBranch {
	ttl, ok := normalizePolicyTTL(policy, ttl)
	if !ok {
		return PolicyBranch{}
	}
	return PolicyBranch{
		Policy: policy,
		Report: report,
		TTL:    ttl,
	}
}

func mtaStsBranchFromResult(policy string, report string, ttl uint32) PolicyBranch {
	if policy == "TEMP" {
		return PolicyBranch{}
	}
	if policy == "" && ttl == 0 {
		ttl = CACHE_NOTFOUND_TTL
	}
	if ttl > CACHE_MAX_TTL {
		ttl = CACHE_MAX_TTL
	}
	return PolicyBranch{
		Policy: policy,
		Report: report,
		TTL:    ttl,
	}
}

func expireBranch(branch PolicyBranch, now time.Time) PolicyBranch {
	if !branch.HasData() {
		return branch
	}
	branch.ExpiresAt = now.Add(time.Duration(branch.TTL+rand.Uint32N(20)) * time.Second)
	return branch
}

func expireMtaStsBranch(branch PolicyBranch, now time.Time) PolicyBranch {
	if !branch.HasData() {
		return branch
	}
	branch.ExpiresAt = now.Add(time.Duration(branch.TTL) * time.Second)
	return branch
}

func selectedPolicyFromBranches(dane PolicyBranch, mtaSts PolicyBranch, daneTemp bool) (string, string, uint32) {
	if daneTemp {
		return "TEMP", "", 0
	}
	if dane.HasData() {
		if dane.Policy != "" {
			return dane.Policy, dane.Report, dane.TTL
		}
		if mtaSts.HasData() {
			return mtaSts.Policy, mtaSts.Report, minPositive(dane.TTL, mtaSts.TTL)
		}
		return "", "", 0
	}
	return "TEMP", "", 0
}

func mergeCacheResult(c *CacheStruct, result domainResult, now time.Time) *CacheStruct {
	cs := cloneCacheStruct(c)
	resultDane := result.Dane
	resultMtaSts := result.MtaSts
	if resultDane.HasData() {
		dane := resultDane
		mtaStsPolicy := cs.MtaSts.Policy
		if resultMtaSts.HasData() {
			mtaStsPolicy = resultMtaSts.Policy
		}
		if dane.Policy == "" && mtaStsPolicy != "" {
			dane.TTL = policyBranchRecheckTTL()
		}
		cs.Dane = expireBranch(dane, now)
	}
	if resultMtaSts.HasData() {
		mtaSts := resultMtaSts
		danePolicy := cs.Dane.Policy
		if resultDane.HasData() {
			danePolicy = resultDane.Policy
		}
		if mtaSts.Policy == "" && danePolicy != "" {
			mtaSts.TTL = policyBranchRecheckTTL()
		}
		cs.MtaSts = expireMtaStsBranch(mtaSts, now)
	}
	if result.DaneAttempted {
		cs.DaneLastAttempt = now
	}
	if result.MtaStsAttempted {
		cs.MtaStsLastAttempt = now
	}
	policy, report, ttl, ok := selectCachedPolicy(cs, now)
	if ok {
		cs.Policy = policy
		cs.Report = report
		cs.TTL = ttl
		cs.Expirable.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
	} else {
		cs.Policy = result.Policy
		cs.Report = result.Report
		cs.TTL = result.TTL
	}
	return cs
}

func policyBranchRecheckTTL() uint32 {
	return uint32(POLICY_BRANCH_RECHECK / time.Second)
}

type DanePolicy struct {
	Policy string  `json:"policy"`
	Time   float64 `json:"time"`
	TTL    uint32  `json:"ttl"`
}
type MtaStsPolicy struct {
	Policy string  `json:"policy"`
	Report string  `json:"report"`
	Time   float64 `json:"time"`
	TTL    uint32  `json:"ttl"`
}
type Result struct {
	Version string       `json:"version"`
	Domain  string       `json:"domain"`
	Dane    DanePolicy   `json:"dane"`
	MtaSts  MtaStsPolicy `json:"mta-sts"`
}

func replyJson(ctx context.Context, conn net.Conn, domain string) {
	ta := time.Now()
	var (
		wg    sync.WaitGroup
		tb    time.Time = ta
		dPol  string
		dTTL  uint32
		tc    time.Time = ta
		msPol string
		msRpt string
		msTTL uint32
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dPol, dTTL = checkDanePolicy(ctx, domain, true)
		tb = time.Now()
	}()
	go func() {
		defer wg.Done()
		msPol, msRpt, msTTL = checkMtaStsPolicy(ctx, domain, true)
		tc = time.Now()
	}()
	wg.Wait()
	r := Result{
		Version: Version,
		Domain:  domain,
		Dane: DanePolicy{
			Policy: dPol,
			TTL:    dTTL,
			Time:   tb.Sub(ta).Truncate(time.Millisecond).Seconds(),
		},
		MtaSts: MtaStsPolicy{
			Policy: msPol,
			TTL:    msTTL,
			Report: msRpt,
			Time:   tc.Sub(ta).Truncate(time.Millisecond).Seconds(),
		},
	}

	b, err := json.Marshal(r)
	if err != nil {
		slog.Error("Could not marshal JSON", "error", err)
		return
	}

	writeConnectionResponse(conn, append(b, '\n'))
}

func replySocketmap(conn net.Conn, domain string, policy string, report string, ttl uint32, withTlsRpt bool) {
	var delivered bool
	switch policy {
	case "":
		slog.Debug("No policy found", "origin", "network", "domain", domain, "ttl", ttl)
		delivered = writeConnectionResponse(conn, NS_NOTFOUND)
	case "TEMP":
		slog.Warn("Evaluating policy failed temporarily", "origin", "network", "domain", domain, "ttl", ttl)
		delivered = writeConnectionResponse(conn, NS_TEMP)
	default:
		slog.Debug("Evaluated policy", "origin", "network", "domain", domain, "policy", firstWord(policy), "ttl", ttl)
		res := policy
		if withTlsRpt {
			res = res + " " + report
		}
		delivered = writeConnectionResponse(conn, netstring.Marshal("OK "+res))
	}
	if delivered {
		observePolicy(policy)
	}
}

func writeConnectionResponse(conn net.Conn, response []byte) bool {
	if err := writeConnection(conn, response); err != nil {
		slog.Debug("Could not write connection response", "error", err)
		return false
	}
	return true
}

func writeConnection(conn net.Conn, response []byte) error {
	for len(response) != 0 {
		n, err := conn.Write(response)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(response) {
			return io.ErrShortWrite
		}
		response = response[n:]
	}
	return nil
}

func isLikelyHTTP(reader *bufio.Reader) bool {
	b, err := reader.ReadByte()
	if err != nil {
		return false
	}
	_ = reader.UnreadByte()
	if b >= '0' && b <= '9' {
		return false
	}
	if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
		return true
	}
	return false
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(SOCKETMAP_READ_TIMEOUT)); err != nil {
		return
	}
	reader := bufio.NewReader(conn)
	if isLikelyHTTP(reader) {
		handleHTTPConnection(conn, reader)
		return
	}
	handleSocketmapConnection(&writeDeadlineConn{Conn: conn, timeout: SOCKETMAP_WRITE_TIMEOUT}, reader)
}

func handleHTTPConnection(conn net.Conn, reader *bufio.Reader) {
	if err := conn.SetReadDeadline(time.Now().Add(METRICS_READ_HEADER_TIMEOUT)); err != nil {
		return
	}

	limitedReader := bufio.NewReader(io.LimitReader(reader, int64(METRICS_MAX_HEADER_BYTES)))
	writer := bufio.NewWriter(conn)

	req, err := http.ReadRequest(limitedReader)
	if err != nil {
		return
	}

	resp := &http.Response{
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     make(http.Header),
		Close:      true,
	}
	resp.Header.Set("Connection", "close")

	if req.URL.Path == "/metrics" && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		body := buildMetricsText()
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		resp.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		resp.ContentLength = int64(len(body))
		if req.Method == http.MethodGet {
			resp.Body = io.NopCloser(strings.NewReader(body))
		} else {
			resp.Body = http.NoBody
		}
	} else {
		body := "not found\n"
		resp.StatusCode = http.StatusNotFound
		resp.Status = "404 Not Found"
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp.ContentLength = int64(len(body))
		if req.Method == http.MethodHead {
			resp.Body = http.NoBody
		} else {
			resp.Body = io.NopCloser(strings.NewReader(body))
		}
	}

	if err := conn.SetWriteDeadline(time.Now().Add(METRICS_WRITE_TIMEOUT)); err != nil {
		return
	}
	if err := resp.Write(writer); err != nil {
		return
	}
	if err := writer.Flush(); err != nil {
		return
	}
}

func handleMetricsOnlyHTTPRequest(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/metrics" && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
		body := buildMetricsText()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = io.WriteString(w, body)
		}
		return
	}

	body := "not found\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusNotFound)
	if req.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

//gocyclo:ignore
func handleSocketmapConnection(conn net.Conn, reader io.Reader) {
	ns := netstring.NewScanner(reader)
	ns.Buffer(make([]byte, 512), SOCKETMAP_MAX_REQUEST_BYTES)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(SOCKETMAP_READ_TIMEOUT)); err != nil {
			return
		}
		if !ns.Scan() {
			return
		}
		query := ns.Text()
		rawCommand, argument, hasArgument := strings.Cut(query, " ")
		cmd := canonicalSocketmapCommand(rawCommand)
		if isControlCommand(cmd) && !isLocalControlConnection(conn) {
			slog.Warn("Rejected non-local control command", "command", cmd, "remote", conn.RemoteAddr())
			writeConnectionResponse(conn, NS_PERM)
			return
		}
		withTlsRpt := config.Server.TlsRpt
		switch cmd {
		case "QUERYWITHTLSRPT": // QUERYwithTLSRPT
			withTlsRpt = true
			addMetricQuery()
		case "QUERY":
			addMetricQuery()
		case "JSON":
		case "DUMP":
			dumpCachedPolicies(conn, false)
			return
		case "EXPORT":
			dumpCachedPolicies(conn, true)
			return
		case "PURGE":
			purgeCache(conn)
			return
		default:
			slog.Warn("Unknown command", "query", query)
			writeConnectionResponse(conn, NS_PERM)
			return
		}
		if !hasArgument { // empty query
			writeConnectionResponse(conn, NS_NOTFOUND)
			continue
		}

		domain := normalizeDomain(argument)
		if !valid.IsDNSName(domain) || strings.HasPrefix(domain, ".") {
			writeConnectionResponse(conn, NS_NOTFOUND)
			continue
		}

		if cmd == "JSON" {
			ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT)
			replyJson(ctx, conn, domain)
			cancel()
			continue
		}

		c, found := tryCachedPolicy(conn, domain, withTlsRpt)
		if found {
			continue
		}
		observeCacheRequest(false)

		result := refreshDomain(domain, c)

		replySocketmap(conn, domain, result.Policy, result.Report, result.TTL, withTlsRpt)

		if result.TTL != 0 || result.Dane.HasData() || result.MtaSts.HasData() ||
			(c != nil && (result.DaneAttempted || result.MtaStsAttempted)) {
			now := time.Now()
			cs := mergeCacheResult(c, result, now)
			cs.Counter += drainCacheHitCounter(domain) + 1
			polCache.Set(domain, cs)
			enforceCacheLimit()
			if _, _, _, ok := selectCachedPolicy(cs, now); ok {
				resetCachedPolicyPrefetchFailures(domain)
			}
			scheduleCachedPolicyPrefetch(domain, cs, now)
		}
	}
}

func canonicalSocketmapCommand(command string) string {
	switch command {
	case "QUERYWITHTLSRPT", "QUERY", "JSON", "DUMP", "EXPORT", "PURGE":
		return command
	}
	return strings.ToUpper(command)
}

func isControlCommand(cmd string) bool {
	switch cmd {
	case "JSON", "DUMP", "EXPORT", "PURGE":
		return true
	default:
		return false
	}
}

func isLocalControlConnection(conn net.Conn) bool {
	addr := conn.RemoteAddr()
	if addr == nil {
		return false
	}
	switch a := addr.(type) {
	case *net.UnixAddr:
		return true
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	}
	if strings.HasPrefix(addr.Network(), "unix") {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	return err == nil && net.ParseIP(host).IsLoopback()
}

type domainResult struct {
	Policy          string
	Report          string
	Dane            PolicyBranch
	MtaSts          PolicyBranch
	TTL             uint32
	DaneTemp        bool
	DaneAttempted   bool
	MtaStsAttempted bool
}

var queryDomainOnce = queryDomainOnceImpl
var refreshDomainOnce = refreshDomainOnceImpl
var prefetchDomainOnce = prefetchDomainOnceImpl

type queryBranchOptions struct {
	renewBefore uint32
	prefetch    bool
}

type policyLookupLogContextKey struct{}

func withPrefetchPolicyLookupLogging(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLookupLogContextKey{}, true)
}

func policyLookupLogLevel(ctx context.Context) slog.Level {
	if prefetch, _ := ctx.Value(policyLookupLogContextKey{}).(bool); prefetch {
		return slog.LevelDebug
	}
	return slog.LevelWarn
}

func logPolicyLookupFailure(ctx context.Context, message string, args ...any) {
	slog.Log(ctx, policyLookupLogLevel(ctx), message, args...)
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func queryDomain(domain string) domainResult {
	res, _, _ := queryGroup.Do(domain, func() (any, error) {
		return queryDomainOnce(domain), nil
	})
	return res.(domainResult)
}

func queryDomainOnceImpl(domain string) domainResult {
	return queryDomainBranches(domain, nil, time.Now())
}

func refreshDomain(domain string, c *CacheStruct) domainResult {
	res, _, _ := queryGroup.Do(domain, func() (any, error) {
		return refreshDomainOnce(domain, c), nil
	})
	return res.(domainResult)
}

func refreshDomainOnceImpl(domain string, c *CacheStruct) domainResult {
	return queryDomainBranches(domain, c, time.Now())
}

func prefetchDomain(domain string, c *CacheStruct) domainResult {
	return prefetchDomainOnce(domain, c)
}

func prefetchDomainOnceImpl(domain string, c *CacheStruct) domainResult {
	return queryDomainBranchesWithOptions(domain, c, time.Now(), queryBranchOptions{
		renewBefore: PREFETCH_INTERVAL,
		prefetch:    true,
	})
}

func freshBranchForSelection(branch PolicyBranch, now time.Time) (PolicyBranch, bool) {
	ttl := branch.RemainingTTL(now)
	if ttl == 0 {
		return PolicyBranch{}, false
	}
	branch.TTL = ttl
	return branch, true
}

func daneBranchForSelection(c *CacheStruct, now time.Time) (PolicyBranch, bool) {
	branch, ok := freshBranchForSelection(c.Dane, now)
	if ok {
		return branch, true
	}
	if c.Dane.HasData() && c.Dane.Policy == "" && c.MtaSts.Policy != "" && !c.DaneLastAttempt.IsZero() {
		nextAttempt := c.DaneLastAttempt.Add(POLICY_BRANCH_RECHECK)
		if now.Before(nextAttempt) {
			branch := c.Dane
			branch.TTL = uint32(nextAttempt.Sub(now).Seconds())
			branch.ExpiresAt = nextAttempt
			return branch, true
		}
	}
	return PolicyBranch{}, false
}

func queryDomainBranches(domain string, c *CacheStruct, now time.Time) domainResult {
	return queryDomainBranchesWithOptions(domain, c, now, queryBranchOptions{})
}

func queryDomainBranchesWithOptions(domain string, c *CacheStruct, now time.Time, opts queryBranchOptions) domainResult {
	ctx, cancel := context.WithTimeout(bgCtx, time.Duration(POLICY_ATTEMPTS)*REQUEST_TIMEOUT+time.Second)
	defer cancel()
	if opts.prefetch {
		ctx = withPrefetchPolicyLookupLogging(ctx)
	}
	var wg sync.WaitGroup
	var (
		danePolicy        string
		daneTTL           uint32
		mtaStsPol         string
		mtaStsRpt         string
		mtaStsTTL         uint32
		daneForSelection  PolicyBranch
		mtaStsForSelected PolicyBranch
		daneForQuery      PolicyBranch
		mtaStsForQuery    PolicyBranch
	)

	if c != nil {
		mtaStsForSelected, _ = freshBranchForSelection(c.MtaSts, now)
		daneForSelection, _ = daneBranchForSelection(c, now)
		mtaStsForQuery = branchForQuerySuppression(mtaStsForSelected, opts.renewBefore)
		daneForQuery = branchForQuerySuppression(daneForSelection, opts.renewBefore)
	}

	queryDane := shouldQueryDane(c, daneForQuery, mtaStsForQuery, now, opts.renewBefore)
	queryMtaSts := shouldQueryMtaSts(c, daneForQuery, mtaStsForQuery, now, opts.renewBefore)

	switch {
	case queryDane && queryMtaSts:
		wg.Add(2)
		go func() {
			defer wg.Done()
			danePolicy, daneTTL = checkDanePolicy(ctx, domain, true)
		}()
		go func() {
			defer wg.Done()
			mtaStsPol, mtaStsRpt, mtaStsTTL = checkMtaStsPolicy(ctx, domain, true)
		}()
		wg.Wait()
	case queryDane:
		danePolicy, daneTTL = checkDanePolicy(ctx, domain, true)
	case queryMtaSts:
		mtaStsPol, mtaStsRpt, mtaStsTTL = checkMtaStsPolicy(ctx, domain, true)
	}

	daneTemp := danePolicy == "TEMP"
	refreshedDane := PolicyBranch{}
	if queryDane {
		refreshedDane = branchFromResult(danePolicy, "", daneTTL)
		daneForSelection = refreshedDane
	}
	refreshedMtaSts := PolicyBranch{}
	if queryMtaSts {
		candidate := mtaStsBranchFromResult(mtaStsPol, mtaStsRpt, mtaStsTTL)
		livePolicyUnavailable := mtaStsPol == "TEMP" || mtaStsPol == "" && mtaStsTTL == 0
		if !livePolicyUnavailable || !mtaStsForSelected.HasData() {
			refreshedMtaSts = candidate
			mtaStsForSelected = candidate
		}
	}
	policy, report, ttl := selectedPolicyFromBranches(daneForSelection, mtaStsForSelected, daneTemp)
	return domainResult{
		Policy:          policy,
		Report:          report,
		TTL:             ttl,
		Dane:            refreshedDane,
		MtaSts:          refreshedMtaSts,
		DaneTemp:        daneTemp,
		DaneAttempted:   queryDane,
		MtaStsAttempted: queryMtaSts,
	}
}

func branchForQuerySuppression(branch PolicyBranch, renewBefore uint32) PolicyBranch {
	if renewBefore != 0 && branch.HasData() && branch.TTL <= renewBefore {
		return PolicyBranch{}
	}
	return branch
}

func beforeBranchRecheck(lastAttempt time.Time, now time.Time, renewBefore uint32) bool {
	if lastAttempt.IsZero() {
		return false
	}
	nextAttempt := lastAttempt.Add(POLICY_BRANCH_RECHECK)
	if renewBefore != 0 {
		return now.Add(time.Duration(renewBefore) * time.Second).Before(nextAttempt)
	}
	return now.Before(nextAttempt)
}

func shouldQueryDane(c *CacheStruct, daneForSelection PolicyBranch, mtaStsForSelection PolicyBranch, now time.Time, renewBefore uint32) bool {
	if daneForSelection.HasData() {
		return false
	}
	if c != nil && c.MtaSts.Policy != "" && c.Dane.HasData() && c.Dane.Policy == "" &&
		beforeBranchRecheck(c.DaneLastAttempt, now, renewBefore) {
		return false
	}
	return true
}

func shouldQueryMtaSts(c *CacheStruct, daneForSelection PolicyBranch, mtaStsForSelection PolicyBranch, now time.Time, renewBefore uint32) bool {
	if mtaStsForSelection.HasData() {
		return false
	}
	if c != nil && !c.MtaStsLastAttempt.IsZero() && now.Before(c.MtaStsLastAttempt.Add(MTA_STS_FETCH_RETRY_INTERVAL)) {
		return false
	}
	if c != nil && c.Dane.Policy != "" && beforeBranchRecheck(c.MtaStsLastAttempt, now, renewBefore) {
		return false
	}
	return true
}

func dumpCachedPolicies(conn net.Conn, export bool) {
	items := tidyCache()
	counters := sortCacheEntriesByCounter(items)
	writer := bufio.NewWriterSize(conn, 64<<10)
	defer func() {
		if err := writer.Flush(); err != nil {
			slog.Debug("Could not flush cached policy dump", "error", err)
		}
	}()
	now := time.Now()
	for i, entry := range items {
		policy, _, remainingTTL, ok := selectCachedPolicy(entry.Value, now)
		if !ok || policy == "" || remainingTTL < PREFETCH_INTERVAL+1 {
			continue
		}
		var err error
		if export {
			_, err = fmt.Fprintf(writer, "%-28s %s\n", entry.Key, policy)
		} else {
			_, err = fmt.Fprintf(writer, "%-28s  %6d  %s\n", entry.Key, counters[i], policy)
		}
		if err != nil {
			slog.Debug("Could not write cached policy dump", "error", err)
			return
		}
	}
}

func purgeCache(conn net.Conn) {
	err := polCache.Purge()
	flushCacheHitCounters(false)
	clearPrefetchSchedule()
	if err != nil {
		slog.Error("Could not persist purged cache", "error", err)
		fmt.Fprintf(conn, "ERROR: cache purge is not durable: %v\n", err)
		return
	}
	fmt.Fprintln(conn, "OK")
}

func tidyCache() []cache.Entry[*CacheStruct] {
	flushCacheHitCounters(false)
	items := polCache.Items(false)
	now := time.Now()
	entries := make([]cache.Entry[*CacheStruct], 0, len(items))
	for _, entry := range items {
		removeEmptyStats := entry.Value.policyStateEmpty() && entry.Value.Counter == 0
		removeExpiredNoPolicy := !entry.Value.policyStateEmpty() && entry.Value.noPolicyOnly() && entry.Value.RemainingTTL(now) == 0
		removeStalePolicy := !entry.Value.policyStateEmpty() && entry.Value.Age(now) >= CACHE_MAX_AGE
		removeLegacyBadPolicy := strings.Contains(entry.Value.Report, "mx_host_pattern=.") ||
			strings.Contains(entry.Value.Policy, "match= ") ||
			strings.Contains(entry.Value.MtaSts.Report, "mx_host_pattern=.") ||
			strings.Contains(entry.Value.MtaSts.Policy, "match= ")
		if removeEmptyStats || removeExpiredNoPolicy || removeStalePolicy || removeLegacyBadPolicy {
			current, removed := discardCachedPolicyStateIfCurrent(entry.Key, entry.Value)
			if removed {
				unscheduleCachedPolicyPrefetch(entry.Key)
			} else if current != nil {
				entries = append(entries, cache.Entry[*CacheStruct]{Key: entry.Key, Value: current})
			}
		} else {
			entries = append(entries, entry)
		}
	}
	entries, evicted := partitionCacheEntriesForLimit(entries, now, CACHE_MAX_ENTRIES, CACHE_PRUNE_TARGET)
	pruned := 0
	for _, entry := range evicted {
		current, removed := removeCacheEntryIfCurrent(entry.Key, entry.Value)
		if removed {
			pruned++
			cacheHitCounters.Delete(entry.Key)
			unscheduleCachedPolicyPrefetch(entry.Key)
		} else if current != nil {
			entries = append(entries, cache.Entry[*CacheStruct]{Key: entry.Key, Value: current})
		}
	}
	for _, entry := range entries {
		scheduleCachedPolicyPrefetch(entry.Key, entry.Value, now)
	}
	if pruned != 0 {
		slog.Warn("Pruned policy cache to entry limit", "removed", pruned, "remaining", len(entries))
	}
	if err := polCache.Save(false); err != nil {
		slog.Error("Could not save cache", "error", err)
	}
	return entries
}

func enforceCacheLimit() {
	if polCache.Len() <= CACHE_MAX_ENTRIES || !cachePruneMu.TryLock() {
		return
	}
	defer cachePruneMu.Unlock()
	if polCache.Len() > CACHE_MAX_ENTRIES {
		_ = tidyCache()
	}
}

type cacheEvictionScore struct {
	counter   uint32
	ttl       uint32
	hasPolicy bool
}

type cacheCounterSorter struct {
	entries  []cache.Entry[*CacheStruct]
	counters []uint32
}

func (s cacheCounterSorter) Len() int {
	return len(s.entries)
}

func (s cacheCounterSorter) Less(i int, j int) bool {
	if s.counters[i] != s.counters[j] {
		return s.counters[i] > s.counters[j]
	}
	return s.entries[i].Key < s.entries[j].Key
}

func (s cacheCounterSorter) Swap(i int, j int) {
	s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
	s.counters[i], s.counters[j] = s.counters[j], s.counters[i]
}

func sortCacheEntriesByCounter(entries []cache.Entry[*CacheStruct]) []uint32 {
	counters := make([]uint32, len(entries))
	for i, entry := range entries {
		counters[i] = cacheEntryCounter(entry.Key, entry.Value)
	}
	sort.Sort(cacheCounterSorter{entries: entries, counters: counters})
	return counters
}

type cacheEntrySorter struct {
	entries []cache.Entry[*CacheStruct]
	scores  []cacheEvictionScore
}

func (s cacheEntrySorter) Len() int {
	return len(s.entries)
}

func (s cacheEntrySorter) Less(i int, j int) bool {
	if s.scores[i].hasPolicy != s.scores[j].hasPolicy {
		return !s.scores[i].hasPolicy
	}
	if s.scores[i].counter != s.scores[j].counter {
		return s.scores[i].counter < s.scores[j].counter
	}
	if s.scores[i].ttl != s.scores[j].ttl {
		return s.scores[i].ttl < s.scores[j].ttl
	}
	return s.entries[i].Key < s.entries[j].Key
}

func (s cacheEntrySorter) Swap(i int, j int) {
	s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
	s.scores[i], s.scores[j] = s.scores[j], s.scores[i]
}

func partitionCacheEntriesForLimit(entries []cache.Entry[*CacheStruct], now time.Time, maxEntries int, targetEntries int) ([]cache.Entry[*CacheStruct], []cache.Entry[*CacheStruct]) {
	if len(entries) <= maxEntries {
		return entries, nil
	}
	scores := make([]cacheEvictionScore, len(entries))
	for i, entry := range entries {
		scores[i] = cacheEvictionScore{
			counter:   cacheEntryCounter(entry.Key, entry.Value),
			ttl:       entry.Value.RemainingTTL(now),
			hasPolicy: cacheStructHasPolicy(entry.Value),
		}
	}
	sort.Sort(cacheEntrySorter{entries: entries, scores: scores})
	evictCount := len(entries) - targetEntries
	return entries[evictCount:], entries[:evictCount]
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}
