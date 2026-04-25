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
	*cache.Expirable
	Policy  string // legacy/selected policy, retained for old cache files and dumps
	Report  string
	TTL     uint32
	Dane    PolicyBranch
	MtaSts  PolicyBranch
	Counter uint32
}

type PolicyBranch struct {
	Policy    string
	Report    string
	TTL       uint32
	ExpiresAt time.Time
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
	CACHE_NOTFOUND_TTL uint32 = 600
	CACHE_MIN_TTL      uint32 = 180
	CACHE_MAX_TTL      uint32 = 2592000
	CACHE_MAX_AGE      uint32 = 1800 // max age for stale queries (only for prefetching, not served to postfix)
	REQUEST_TIMEOUT           = 2 * time.Second
	POLICY_ATTEMPTS           = 3
	POLICY_RETRY_BASE         = 250 * time.Millisecond
)

var (
	Version           = "undefined"
	bgCtx             = context.Background()
	levelVar          = new(slog.LevelVar)
	queryGroup        singleflight.Group
	client            = dns.Client{UDPSize: 4096, Timeout: REQUEST_TIMEOUT}
	config            Config
	polCache          *cache.Cache[*CacheStruct]
	NS_NOTFOUND       = netstring.Marshal("NOTFOUND ")
	NS_TEMP           = netstring.Marshal("TEMP ")
	NS_PERM           = netstring.Marshal("PERM ")
	NS_TIMEOUT        = netstring.Marshal("TIMEOUT ")
	listeners         []net.Listener
	serverWg          sync.WaitGroup
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

func StartDaemon(v string, licenseText string) {
	Version = v
	curYear, _, _ := time.Now().Date()

	flag.Parse()

	if showVersion {
		fmt.Printf("postfix-tlspol v%s\n", Version)
		return
	}

	if showLicense {
		fmt.Printf("%s\n", licenseText)
		return
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(configFile)
	if err != nil {
		slog.Error("Error loading config", "error", err)
		return
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
		return
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — v%s\nThis program is licensed under the MIT License.\n", curYear, Version)

	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Duration(600*time.Second))
	defer polCache.Close()
	_ = tidyCache()
	listenForSignals()

	readEnv()

	go startPrefetching()
	go startServer()

	select {}
}

func listenForSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		for {
			sig := <-signals
			slog.Info("Received signal, saving cache...", "signal", sig)
			_ = tidyCache()
			if err := polCache.ForceSave(false); err != nil {
				slog.Error("Could not save cache", "error", err)
			}
			if sig == syscall.SIGHUP {
				continue
			}
			polCache.Close()
			if len(listeners) > 0 {
				for _, l := range listeners {
					if l != nil {
						l.Close()
					}
				}
				serverWg.Wait()
			}
			os.Exit(0)
			break
		}
	}()
}

func readEnv() {
	envPrefetch, envExists := os.LookupEnv("TLSPOL_PREFETCH")
	if envExists {
		config.Server.Prefetch = envPrefetch == "1"
	}
	envTlsRpt, envExists := os.LookupEnv("TLSPOL_TLSRPT")
	if envExists {
		config.Server.TlsRpt = envTlsRpt == "1"
	}
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

func serveSocketmapListener(l net.Listener) {
	defer serverWg.Done()

	for {
		conn, err := l.Accept()
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
			break
		}
		go handleConnection(conn)
	}
}

func serveMetricsListener(l net.Listener) {
	defer serverWg.Done()

	server := &http.Server{
		Handler: http.HandlerFunc(handleMetricsOnlyHTTPRequest),
	}
	err := server.Serve(l)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		addr := l.Addr()
		if addr == nil {
			slog.Error("Metrics HTTP server terminated with error", "error", err, "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Error("Metrics HTTP server terminated with error", "error", err, "network", addr.Network(), "address", addr.String())
		}
	}
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

func startServer() {
	var err error
	socketmapListeners, inherited, err := listenSystemdSocket()
	if err != nil {
		slog.Error("Error inheriting systemd-activated socket", "error", err)
		os.Exit(1)
	}

	if !inherited {
		var directListener net.Listener
		directListener, err = listenConfiguredAddress(config.Server.Address, config.Server.SocketPermissions)
		if err == nil {
			socketmapListeners = []net.Listener{directListener}
		}
	} else {
		slog.Info("Using systemd socket activation")
	}
	if err != nil {
		slog.Error("Error starting socketmap server", "error", err)
		os.Exit(1)
	}

	if len(socketmapListeners) == 0 {
		slog.Error("Error starting socketmap server", "error", "no listeners available")
		os.Exit(1)
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
		slog.Warn("Ignoring configured server.address because systemd socket activation is active", "configured_address", config.Server.Address)
		slog.Info("Listening on all systemd-provided sockets", "count", len(socketmapListeners))
	} else {
		addr := socketmapListeners[0].Addr()
		if addr == nil {
			slog.Info("Server listening", "activation", "direct", "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Info("Server listening", "activation", "direct", "network", addr.Network(), "address", addr.String())
		}
	}

	listeners = append([]net.Listener(nil), socketmapListeners...)

	var metricsListener net.Listener
	if metricsAddress := strings.TrimSpace(config.Server.MetricsAddress); metricsAddress != "" {
		metricsListener, err = listenConfiguredAddress(metricsAddress, config.Server.SocketPermissions)
		if err != nil {
			closeListeners(listeners)
			slog.Error("Error starting metrics HTTP server", "error", err)
			os.Exit(1)
		}
		listeners = append(listeners, metricsListener)
		addr := metricsListener.Addr()
		if addr == nil {
			slog.Info("Metrics HTTP server listening", "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Info("Metrics HTTP server listening", "network", addr.Network(), "address", addr.String())
		}
	}

	defer func() {
		listeners = nil
	}()

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
}

func tryCachedPolicy(conn net.Conn, domain string, withTlsRpt bool) (*CacheStruct, bool) {
	c, found := polCache.Get(domain)
	if found {
		policy, report, ttl, ok := selectCachedPolicy(c, time.Now())
		if ok {
			switch policy {
			case "":
				slog.Info("No policy found", "origin", "cache", "domain", domain, "ttl", ttl)
				conn.Write(NS_NOTFOUND)
			default:
				slog.Info("Evaluated policy", "origin", "cache", "domain", domain, "policy", firstWord(policy), "ttl", ttl)
				var res string
				if withTlsRpt {
					res = policy + " " + report
				} else {
					res = policy
				}
				conn.Write(netstring.Marshal("OK " + res))
			}
			observePolicy(policy)
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
			return true
		}
		delta := value.(*atomic.Uint32).Swap(0)
		if delta == 0 {
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
		return true
	})
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

func expireBranch(branch PolicyBranch, now time.Time) PolicyBranch {
	if !branch.HasData() {
		return branch
	}
	branch.ExpiresAt = now.Add(time.Duration(branch.TTL+rand.Uint32N(20)) * time.Second)
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
	if result.Dane.HasData() {
		cs.Dane = expireBranch(result.Dane, now)
	}
	if result.MtaSts.HasData() {
		cs.MtaSts = expireBranch(result.MtaSts, now)
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

	conn.Write(append(b, '\n'))
}

func replySocketmap(conn net.Conn, domain string, policy string, report string, ttl uint32, withTlsRpt bool) {
	switch policy {
	case "":
		slog.Info("No policy found", "origin", "network", "domain", domain, "ttl", ttl)
		conn.Write(NS_NOTFOUND)
	case "TEMP":
		slog.Warn("Evaluating policy failed temporarily", "origin", "network", "domain", domain, "ttl", ttl)
		conn.Write(NS_TEMP)
	default:
		slog.Info("Evaluated policy", "origin", "network", "domain", domain, "policy", firstWord(policy), "ttl", ttl)
		res := policy
		if withTlsRpt {
			res = res + " " + report
		}
		conn.Write(netstring.Marshal("OK " + res))
	}
	observePolicy(policy)
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

	reader := bufio.NewReader(conn)
	if isLikelyHTTP(reader) {
		handleHTTPConnection(conn, reader)
		return
	}
	handleSocketmapConnection(conn, reader)
}

func handleHTTPConnection(conn net.Conn, reader *bufio.Reader) {
	writer := bufio.NewWriter(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()

		shouldClose := req.Close || (req.ProtoMajor == 1 && req.ProtoMinor == 0 && !strings.EqualFold(req.Header.Get("Connection"), "keep-alive"))
		resp := &http.Response{
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Header:     make(http.Header),
			Close:      shouldClose,
		}

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

		if err := resp.Write(writer); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
		if shouldClose {
			return
		}
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

	for ns.Scan() {
		query := ns.Text()
		parts := strings.SplitN(query, " ", 2)
		cmd := strings.ToUpper(parts[0])
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
			conn.Write(NS_PERM)
			return
		}
		if len(parts) != 2 { // empty query
			conn.Write(NS_NOTFOUND)
			continue
		}

		domain := normalizeDomain(parts[1])

		if cmd == "JSON" {
			ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT)
			replyJson(ctx, conn, domain)
			cancel()
			continue
		}

		if !valid.IsDNSName(domain) || strings.HasPrefix(domain, ".") {
			conn.Write(NS_NOTFOUND)
			continue
		}

		c, found := tryCachedPolicy(conn, domain, withTlsRpt)
		if found {
			continue
		}

		result := refreshDomain(domain, c)

		replySocketmap(conn, domain, result.Policy, result.Report, result.TTL, withTlsRpt)

		if result.TTL != 0 || result.Dane.HasData() || result.MtaSts.HasData() {
			now := time.Now()
			cs := mergeCacheResult(c, result, now)
			cs.Counter += drainCacheHitCounter(domain) + 1
			polCache.Set(domain, cs)
		}
	}
}

type domainResult struct {
	Policy   string
	Report   string
	TTL      uint32
	Dane     PolicyBranch
	MtaSts   PolicyBranch
	DaneTemp bool
}

var queryDomainOnce = queryDomainOnceImpl
var refreshDomainOnce = refreshDomainOnceImpl

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

func freshBranchForSelection(branch PolicyBranch, now time.Time) (PolicyBranch, bool) {
	ttl := branch.RemainingTTL(now)
	if ttl == 0 {
		return PolicyBranch{}, false
	}
	branch.TTL = ttl
	return branch, true
}

func queryDomainBranches(domain string, c *CacheStruct, now time.Time) domainResult {
	ctx, cancel := context.WithTimeout(bgCtx, time.Duration(POLICY_ATTEMPTS)*REQUEST_TIMEOUT+time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var (
		danePolicy        string
		daneTTL           uint32
		mtaStsPol         string
		mtaStsRpt         string
		mtaStsTTL         uint32
		daneForSelection  PolicyBranch
		mtaStsForSelected PolicyBranch
	)

	if c != nil {
		daneForSelection, _ = freshBranchForSelection(c.Dane, now)
		mtaStsForSelected, _ = freshBranchForSelection(c.MtaSts, now)
	}

	queryDane := !daneForSelection.HasData()
	queryMtaSts := !mtaStsForSelected.HasData()

	if queryDane {
		wg.Add(1)
		go func() {
			defer wg.Done()
			danePolicy, daneTTL = checkDanePolicy(ctx, domain, true)
		}()
	}

	if queryMtaSts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mtaStsPol, mtaStsRpt, mtaStsTTL = checkMtaStsPolicy(ctx, domain, true)
		}()
	}
	wg.Wait()

	daneTemp := danePolicy == "TEMP"
	refreshedDane := PolicyBranch{}
	if queryDane {
		refreshedDane = branchFromResult(danePolicy, "", daneTTL)
		daneForSelection = refreshedDane
	}
	refreshedMtaSts := PolicyBranch{}
	if queryMtaSts {
		refreshedMtaSts = branchFromResult(mtaStsPol, mtaStsRpt, mtaStsTTL)
		mtaStsForSelected = refreshedMtaSts
	}
	policy, report, ttl := selectedPolicyFromBranches(daneForSelection, mtaStsForSelected, daneTemp)
	return domainResult{
		Policy:   policy,
		Report:   report,
		TTL:      ttl,
		Dane:     refreshedDane,
		MtaSts:   refreshedMtaSts,
		DaneTemp: daneTemp,
	}
}

func dumpCachedPolicies(conn net.Conn, export bool) {
	items := tidyCache()
	sort.Slice(items, func(i, j int) bool {
		iCounter := cacheEntryCounter(items[i].Key, items[i].Value)
		jCounter := cacheEntryCounter(items[j].Key, items[j].Value)
		if iCounter != jCounter {
			return iCounter > jCounter
		}
		return items[i].Key < items[j].Key
	})
	now := time.Now()
	for _, entry := range items {
		policy, _, remainingTTL, ok := selectCachedPolicy(entry.Value, now)
		if !ok || policy == "" || remainingTTL < PREFETCH_INTERVAL+1 {
			continue
		}
		if export {
			fmt.Fprintf(conn, "%-28s %s\n", entry.Key, policy)
		} else {
			fmt.Fprintf(conn, "%-28s  %6d  %s\n", entry.Key, cacheEntryCounter(entry.Key, entry.Value), policy)
		}
	}
}

func purgeCache(conn net.Conn) {
	polCache.Purge()
	fmt.Fprintln(conn, "OK")
}

func tidyCache() []cache.Entry[*CacheStruct] {
	polCache.Lock()
	flushCacheHitCounters(true)
	items := polCache.Items(true)
	now := time.Now()
	var entries []cache.Entry[*CacheStruct]
	for _, entry := range items {
		removeExpiredNoPolicy := entry.Value.noPolicyOnly() && entry.Value.RemainingTTL(now) == 0
		removeStalePolicy := entry.Value.Age(now) >= CACHE_MAX_AGE
		removeLegacyBadPolicy := strings.Contains(entry.Value.Report, "mx_host_pattern=.") ||
			strings.Contains(entry.Value.Policy, "match= ") ||
			strings.Contains(entry.Value.MtaSts.Report, "mx_host_pattern=.") ||
			strings.Contains(entry.Value.MtaSts.Policy, "match= ")
		if removeExpiredNoPolicy || removeStalePolicy || removeLegacyBadPolicy {
			polCache.Remove(true, entry.Key)
		} else {
			entries = append(entries, entry)
		}
	}
	polCache.Unlock()
	if err := polCache.Save(false); err != nil {
		slog.Error("Could not save cache", "error", err)
	}
	return entries
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}
