/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

type scriptedAcceptResult struct {
	conn net.Conn
	err  error
}

type scriptedListener struct {
	addr    net.Addr
	accepts chan scriptedAcceptResult
}

type notifyingListener struct {
	net.Listener
	acceptCalled chan struct{}
}

func (l *notifyingListener) Accept() (net.Conn, error) {
	l.acceptCalled <- struct{}{}
	return l.Listener.Accept()
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	result := <-l.accepts
	return result.conn, result.err
}

func (l *scriptedListener) Close() error {
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return l.addr
}

type staticAddr string

func TestConfiguredAddressProvidedBySystemd(t *testing.T) {
	tcp4 := &scriptedListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8642}}
	tcp6 := &scriptedListener{addr: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 8642, Zone: "lo"}}
	unix := &scriptedListener{addr: &net.UnixAddr{Name: "/run/postfix-tlspol/tlspol.sock", Net: "unix"}}

	tests := []struct {
		name              string
		address           string
		addressConfigured bool
		listeners         []net.Listener
		want              bool
	}{
		{name: "unset address", address: "127.0.0.1:9999", listeners: []net.Listener{tcp4}, want: true},
		{name: "empty address", addressConfigured: true, listeners: []net.Listener{tcp4}, want: true},
		{name: "matching first TCP listener", address: "127.0.0.1:8642", addressConfigured: true, listeners: []net.Listener{tcp4, unix}, want: true},
		{name: "matching later Unix listener", address: "unix:/run/postfix-tlspol/tlspol.sock", addressConfigured: true, listeners: []net.Listener{tcp4, unix}, want: true},
		{name: "matching scoped IPv6 listener", address: "[fe80::1%lo]:8642", addressConfigured: true, listeners: []net.Listener{tcp6}, want: true},
		{name: "different TCP port", address: "127.0.0.1:8643", addressConfigured: true, listeners: []net.Listener{tcp4}, want: false},
		{name: "different TCP address", address: "127.0.0.2:8642", addressConfigured: true, listeners: []net.Listener{tcp4}, want: false},
		{name: "different Unix path", address: "unix:/run/postfix-tlspol/other.sock", addressConfigured: true, listeners: []net.Listener{unix}, want: false},
		{name: "no active listeners", address: "127.0.0.1:8642", addressConfigured: true, want: false},
		{name: "nil listener", address: "127.0.0.1:8642", addressConfigured: true, listeners: []net.Listener{nil}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredAddressProvidedBySystemd(tt.address, tt.addressConfigured, tt.listeners); got != tt.want {
				t.Fatalf("configuredAddressProvidedBySystemd(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestPolicyLookupLogLevel(t *testing.T) {
	if got := policyLookupLogLevel(context.Background()); got != slog.LevelWarn {
		t.Fatalf("ordinary policy lookup log level = %s, want WARN", got)
	}
	if got := policyLookupLogLevel(withPrefetchPolicyLookupLogging(context.Background())); got != slog.LevelDebug {
		t.Fatalf("prefetch policy lookup log level = %s, want DEBUG", got)
	}
}

func TestPrefetchedPolicyDowngradeTransitions(t *testing.T) {
	policies := map[string]string{
		"dane-only": "dane-only",
		"dane":      "dane",
		"sts":       "secure match=mx.example servername=hostname",
		"none":      "",
	}
	warnings := map[string]bool{
		"dane-only>dane": true,
		"dane-only>sts":  true,
		"dane-only>none": true,
		"dane>sts":       true,
		"dane>none":      true,
		"sts>none":       true,
	}

	for previousName, previous := range policies {
		for currentName, current := range policies {
			transition := previousName + ">" + currentName
			_, _, got := isPrefetchedPolicyDowngrade(previous, current)
			if got != warnings[transition] {
				t.Errorf("transition %s warning = %v, want %v", transition, got, warnings[transition])
			}
		}
	}
	if _, _, got := isPrefetchedPolicyDowngrade("TEMP", ""); got {
		t.Fatal("temporary lookup result must not be treated as a downgrade")
	}
}

func TestCachedPolicyForPrefetchTransitionRetainsExpiredDaneHistory(t *testing.T) {
	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-25 * time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-25 * time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example servername=hostname",
			TTL:       86400,
			ExpiresAt: now.Add(time.Hour),
		},
	}
	if got := cachedPolicyForPrefetchTransition(cached, now); got != "dane-only" {
		t.Fatalf("historical policy = %q, want dane-only", got)
	}
}

func clearCacheHitCountersForTest() {
	cacheHitCounters.Range(func(key, _ any) bool {
		cacheHitCounters.Delete(key)
		return true
	})
}

func (a staticAddr) Network() string {
	return "test"
}

func (a staticAddr) String() string {
	return string(a)
}

type eofConn struct {
	closed chan struct{}
	once   sync.Once
}

func newEOFConn() *eofConn {
	return &eofConn{closed: make(chan struct{})}
}

func (c *eofConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *eofConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *eofConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *eofConn) LocalAddr() net.Addr {
	return staticAddr("local")
}

func (c *eofConn) RemoteAddr() net.Addr {
	return staticAddr("remote")
}

func (c *eofConn) SetDeadline(time.Time) error {
	return nil
}

func (c *eofConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *eofConn) SetWriteDeadline(time.Time) error {
	return nil
}

type recordingConn struct {
	writes        bytes.Buffer
	readDeadline  time.Time
	writeDeadline time.Time
}

type partialWriteConn struct {
	recordingConn
	maxWrite int
	writeErr error
}

func (c *partialWriteConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.maxWrite == 0 {
		return 0, nil
	}
	if len(b) > c.maxWrite {
		b = b[:c.maxWrite]
	}
	return c.recordingConn.Write(b)
}

func (c *recordingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *recordingConn) Write(b []byte) (int, error) {
	return c.writes.Write(b)
}

func (c *recordingConn) Close() error {
	return nil
}

func (c *recordingConn) LocalAddr() net.Addr {
	return staticAddr("local")
}

func (c *recordingConn) RemoteAddr() net.Addr {
	return staticAddr("remote")
}

func (c *recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (c *recordingConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func TestIsLikelyHTTP(t *testing.T) {
	if !isLikelyHTTP(bufio.NewReader(strings.NewReader("GET /metrics HTTP/1.1\r\n"))) {
		t.Fatal("expected HTTP request to be detected")
	}
	if isLikelyHTTP(bufio.NewReader(strings.NewReader("14:QUERY example,"))) {
		t.Fatal("expected netstring payload not to be detected as HTTP")
	}
}

func TestServeSocketmapListenerContinuesAfterAcceptError(t *testing.T) {
	conn := newEOFConn()
	accepts := make(chan scriptedAcceptResult, 3)
	accepts <- scriptedAcceptResult{err: errors.New("temporary accept failure")}
	accepts <- scriptedAcceptResult{conn: conn}
	accepts <- scriptedAcceptResult{err: net.ErrClosed}
	listener := &scriptedListener{
		addr:    staticAddr("listener"),
		accepts: accepts,
	}

	serverWg.Add(1)
	go serveSocketmapListener(listener)

	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("expected connection after transient accept error to be handled")
	}

	done := make(chan struct{})
	go func() {
		serverWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected listener to terminate after net.ErrClosed")
	}
}

func TestObservePolicyMetrics(t *testing.T) {
	metricDaneTotal.Store(0)
	metricDaneOnlyTotal.Store(0)
	metricSecureTotal.Store(0)
	metricNoPolicyTotal.Store(0)

	observePolicy("dane-only")
	observePolicy("dane")
	observePolicy("secure match=mx.example")
	observePolicy("")

	if metricDaneTotal.Load() != 2 {
		t.Fatalf("expected dane total to be 2, got %d", metricDaneTotal.Load())
	}
	if metricDaneOnlyTotal.Load() != 1 {
		t.Fatalf("expected dane-only total to be 1, got %d", metricDaneOnlyTotal.Load())
	}
	if metricSecureTotal.Load() != 1 {
		t.Fatalf("expected secure total to be 1, got %d", metricSecureTotal.Load())
	}
	if metricNoPolicyTotal.Load() != 1 {
		t.Fatalf("expected no-policy total to be 1, got %d", metricNoPolicyTotal.Load())
	}
}

func TestBuildMetricsTextIncludesExpectedMetrics(t *testing.T) {
	metricQueriesTotal.Store(12)
	metricDaneTotal.Store(7) // includes dane-only
	metricDaneOnlyTotal.Store(3)
	metricSecureTotal.Store(4)
	metricNoPolicyTotal.Store(9)
	metricCacheHits.Store(10)
	metricCacheMisses.Store(2)
	metricPrefetchOK.Store(5)
	metricPrefetchFail.Store(3)
	metricPrefetchDrop.Store(1)

	metrics := buildMetricsText()
	for _, expected := range []string{
		"postfix_tlspol_queries_total 12",
		"postfix_tlspol_policy_total{policy=\"dane\"} 4",
		"postfix_tlspol_policy_total{policy=\"dane-only\"} 3",
		"postfix_tlspol_policy_total{policy=\"secure\"} 4",
		"postfix_tlspol_policy_total{policy=\"no-policy\"} 9",
		"postfix_tlspol_cache_requests_total{result=\"hit\"} 10",
		"postfix_tlspol_cache_requests_total{result=\"miss\"} 2",
		"postfix_tlspol_cache_entries 0",
		"postfix_tlspol_prefetch_total{result=\"success\"} 5",
		"postfix_tlspol_prefetch_total{result=\"failure\"} 3",
		"postfix_tlspol_prefetch_total{result=\"discard\"} 1",
		"postfix_tlspol_go_goroutines ",
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("expected metrics output to contain %q", expected)
		}
	}
}

func TestWriteConnectionResponseHandlesPartialAndFailedWrites(t *testing.T) {
	partial := &partialWriteConn{maxWrite: 2}
	if !writeConnectionResponse(partial, []byte("response")) {
		t.Fatal("expected partial writes to be completed")
	}
	if got := partial.writes.String(); got != "response" {
		t.Fatalf("written response = %q, want response", got)
	}
	if writeConnectionResponse(&partialWriteConn{}, []byte("response")) {
		t.Fatal("expected a zero-byte write to fail")
	}
	if writeConnectionResponse(&partialWriteConn{maxWrite: 2, writeErr: io.ErrClosedPipe}, []byte("response")) {
		t.Fatal("expected a write error to fail")
	}
}

func TestCanonicalSocketmapCommand(t *testing.T) {
	for _, command := range []string{"QUERY", "query", "Query", "QUERYWITHTLSRPT", "json", "Dump", "EXPORT", "purge"} {
		canonical := canonicalSocketmapCommand(command)
		if canonical != strings.ToUpper(command) {
			t.Fatalf("canonicalSocketmapCommand(%q) = %q", command, canonical)
		}
	}
	if got := canonicalSocketmapCommand("unknown"); got != "UNKNOWN" {
		t.Fatalf("unknown command changed to %q", got)
	}
}

func BenchmarkCanonicalSocketmapCommand(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if canonicalSocketmapCommand("QUERY") != "QUERY" {
			b.Fatal("unexpected command")
		}
	}
}

func BenchmarkSingleBranchPolicyRefresh(b *testing.B) {
	originalDane := checkDanePolicy
	originalMtaSts := checkMtaStsPolicy
	b.Cleanup(func() {
		checkDanePolicy = originalDane
		checkMtaStsPolicy = originalMtaSts
	})
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		b.Fatal("unexpected MTA-STS refresh")
		return "", "", 0
	}
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example",
			TTL:       3600,
			ExpiresAt: now.Add(time.Hour),
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := queryDomainBranchesWithOptions("example.com", cached, now, queryBranchOptions{})
		if !result.DaneAttempted || result.MtaStsAttempted {
			b.Fatal("unexpected refresh branches")
		}
	}
}

func BenchmarkBuildMetricsText(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildMetricsText()
	}
}

func TestLimitedListenerAppliesBackpressureBeforeAccept(t *testing.T) {
	server1, client1 := net.Pipe()
	server2, client2 := net.Pipe()
	t.Cleanup(func() {
		_ = client1.Close()
		_ = client2.Close()
	})

	accepts := make(chan scriptedAcceptResult, 2)
	accepts <- scriptedAcceptResult{conn: server1}
	accepts <- scriptedAcceptResult{conn: server2}
	acceptCalled := make(chan struct{}, 2)
	listener := &notifyingListener{
		Listener:     &scriptedListener{accepts: accepts},
		acceptCalled: acceptCalled,
	}
	limited := newLimitedListener(listener, 1)
	t.Cleanup(func() { _ = limited.Close() })

	first, err := limited.Accept()
	if err != nil {
		t.Fatalf("first accept failed: %v", err)
	}
	<-acceptCalled

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	secondResult := make(chan acceptResult, 1)
	go func() {
		conn, err := limited.Accept()
		secondResult <- acceptResult{conn: conn, err: err}
	}()

	select {
	case <-acceptCalled:
		t.Fatal("underlying listener accepted while the connection limit was full")
	case <-time.After(20 * time.Millisecond):
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	select {
	case <-acceptCalled:
	case <-time.After(time.Second):
		t.Fatal("underlying accept did not resume after capacity was released")
	}
	select {
	case result := <-secondResult:
		if result.err != nil {
			t.Fatalf("second accept failed: %v", result.err)
		}
		_ = result.conn.Close()
	case <-time.After(time.Second):
		t.Fatal("second accept did not complete")
	}
}

func TestLimitedListenerCloseUnblocksSaturatedAccept(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	accepts := make(chan scriptedAcceptResult, 1)
	accepts <- scriptedAcceptResult{conn: server}
	limited := newLimitedListener(&scriptedListener{accepts: accepts}, 1)

	first, err := limited.Accept()
	if err != nil {
		t.Fatalf("first accept failed: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	result := make(chan error, 1)
	go func() {
		_, err := limited.Accept()
		result <- err
	}()
	if err := limited.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("saturated accept did not unblock on close")
	}
}

func TestMetricsOnlyHTTPHandler(t *testing.T) {
	metricQueriesTotal.Store(12)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handleMetricsOnlyHTTPRequest(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "postfix_tlspol_queries_total 12") {
		t.Fatalf("expected metrics body, got %q", string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected content type %q", got)
	}
}

func TestMetricsOnlyHTTPHandlerDoesNotExposeSocketmap(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/socketmap", nil)
	rec := httptest.NewRecorder()

	handleMetricsOnlyHTTPRequest(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestSocketmapHTTPHandlerUsesMetricsDefenses(t *testing.T) {
	metricQueriesTotal.Store(12)
	conn := &recordingConn{}
	reader := bufio.NewReader(strings.NewReader("GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"))

	handleHTTPConnection(conn, reader)

	if conn.readDeadline.IsZero() {
		t.Fatal("expected socketmap HTTP handler to set a read deadline")
	}
	if conn.writeDeadline.IsZero() {
		t.Fatal("expected socketmap HTTP handler to set a write deadline")
	}

	response := conn.writes.String()
	if !strings.Contains(response, "200 OK") {
		t.Fatalf("expected metrics response, got %q", response)
	}
	if !strings.Contains(response, "Connection: close") {
		t.Fatalf("expected socketmap HTTP response to force close, got %q", response)
	}
	if !strings.Contains(response, "postfix_tlspol_queries_total 12") {
		t.Fatalf("expected metrics body, got %q", response)
	}
}

func TestSocketmapHTTPHandlerLimitsHeaderBytes(t *testing.T) {
	conn := &recordingConn{}
	reader := bufio.NewReader(strings.NewReader(
		"GET /metrics HTTP/1.1\r\nHost: localhost\r\nX-Large: " +
			strings.Repeat("a", 2*METRICS_MAX_HEADER_BYTES) + "\r\n\r\n",
	))

	handleHTTPConnection(conn, reader)

	if conn.readDeadline.IsZero() {
		t.Fatal("expected socketmap HTTP handler to set a read deadline")
	}
	if conn.writes.Len() != 0 {
		t.Fatalf("expected oversized HTTP headers to be rejected before response, got %q", conn.writes.String())
	}
}

func TestMetricsHTTPServerHasDefensiveLimits(t *testing.T) {
	server := newMetricsHTTPServer(metricsHTTPServerConfig{
		ReadHeaderTimeout: METRICS_READ_HEADER_TIMEOUT,
		ReadTimeout:       METRICS_READ_TIMEOUT,
		WriteTimeout:      METRICS_WRITE_TIMEOUT,
		IdleTimeout:       METRICS_IDLE_TIMEOUT,
		MaxHeaderBytes:    METRICS_MAX_HEADER_BYTES,
	})
	if server.ReadHeaderTimeout == 0 {
		t.Fatal("expected metrics HTTP server to set ReadHeaderTimeout")
	}
	if server.ReadTimeout == 0 {
		t.Fatal("expected metrics HTTP server to set ReadTimeout")
	}
	if server.WriteTimeout == 0 {
		t.Fatal("expected metrics HTTP server to set WriteTimeout")
	}
	if server.IdleTimeout == 0 {
		t.Fatal("expected metrics HTTP server to set IdleTimeout")
	}
	if server.MaxHeaderBytes == 0 {
		t.Fatal("expected metrics HTTP server to limit header bytes")
	}
	if METRICS_MAX_CONNECTIONS == 0 {
		t.Fatal("expected metrics listener to limit connections")
	}
}

func TestMetricsHTTPServerClosesIncompleteHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start listener: %v", err)
	}

	server := newMetricsHTTPServer(metricsHTTPServerConfig{
		ReadHeaderTimeout: 50 * time.Millisecond,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    METRICS_MAX_HEADER_BYTES,
	})
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(newLimitedListener(listener, 4))
	}()
	defer func() {
		_ = server.Close()
		<-done
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("could not connect to metrics listener: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: slow")); err != nil {
		t.Fatalf("could not write partial request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("could not set read deadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected incomplete metrics HTTP headers to be closed")
	}
}

func TestLimitedListenerCapsActiveConnections(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start listener: %v", err)
	}
	defer base.Close()

	limited := newLimitedListener(base, 1)
	firstClient, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("could not open first client: %v", err)
	}
	defer firstClient.Close()
	firstServer, err := limited.Accept()
	if err != nil {
		t.Fatalf("could not accept first connection: %v", err)
	}
	defer firstServer.Close()

	secondClient, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("could not open second client: %v", err)
	}
	defer secondClient.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := limited.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("expected active connection limit to hold second accept")
	case err := <-acceptErr:
		t.Fatalf("unexpected accept error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := firstServer.Close(); err != nil {
		t.Fatalf("could not close first server connection: %v", err)
	}
	thirdClient, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("could not open third client: %v", err)
	}
	defer thirdClient.Close()

	select {
	case conn := <-accepted:
		conn.Close()
	case err := <-acceptErr:
		t.Fatalf("unexpected accept error after releasing slot: %v", err)
	case <-time.After(time.Second):
		t.Fatal("expected listener to accept after active slot was released")
	}
}

func TestPolicyCacheClosePersistsCacheDB(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cache.db")
	now := time.Now()

	c1 := cache.New[*CacheStruct](tmpFile, time.Hour)
	c1.Set("example.org", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       300,
			ExpiresAt: now.Add(5 * time.Minute),
		},
		TTL:     300,
		Counter: 2,
	})
	c1.Close()

	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("expected cache.db to be saved on close: %v", err)
	}

	c2 := cache.New[*CacheStruct](tmpFile, time.Hour)
	defer c2.Close()

	got, ok := c2.Get("example.org")
	if !ok {
		t.Fatal("expected cached policy after reload")
	}
	if got.Policy != "dane" || got.TTL != 300 || got.Counter != 2 {
		t.Fatalf("unexpected cached policy after reload: %+v", got)
	}
}

func TestTidyCacheRemovesExpiredNoPolicyAndOldStalePolicy(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	defer polCache.Close()

	now := time.Now()
	polCache.Set("expired-empty.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Second)},
		Policy:    "",
	})
	polCache.Set("old-stale.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Duration(CACHE_MAX_AGE+1) * time.Second)},
		Policy:    "dane",
	})
	polCache.Set("expired-no-policy-with-stats.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Second)},
		Dane: PolicyBranch{
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			TTL:       600,
			ExpiresAt: now.Add(-time.Second),
		},
		Counter: 7,
	})
	polCache.Set("recent-stale.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Minute)},
		Policy:    "dane",
	})
	polCache.Set("fresh.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Minute)},
		Policy:    "dane",
	})

	entries := tidyCache()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Key] = true
	}

	for _, removed := range []string{"expired-empty.example", "old-stale.example"} {
		if seen[removed] {
			t.Fatalf("expected %s to be removed", removed)
		}
		if _, ok := polCache.Get(removed); ok {
			t.Fatalf("expected %s to be absent from cache", removed)
		}
	}
	statsOnly, ok := polCache.Get("expired-no-policy-with-stats.example")
	if !ok {
		t.Fatal("expected expired no-policy stats to be retained")
	}
	if !statsOnly.policyStateEmpty() || statsOnly.Counter != 7 {
		t.Fatalf("expected stats-only cache entry, got %+v", statsOnly)
	}
	for _, kept := range []string{"recent-stale.example", "fresh.example"} {
		if !seen[kept] {
			t.Fatalf("expected %s to be retained", kept)
		}
	}
}

func TestPartitionCacheEntriesPrefersUsefulPolicies(t *testing.T) {
	now := time.Now()
	entry := func(key string, policy string, counter uint32, ttl time.Duration) cache.Entry[*CacheStruct] {
		return cache.Entry[*CacheStruct]{
			Key: key,
			Value: &CacheStruct{
				Expirable: &cache.Expirable{ExpiresAt: now.Add(ttl)},
				Policy:    policy,
				Counter:   counter,
			},
		}
	}
	entries := []cache.Entry[*CacheStruct]{
		entry("unused-policy.example", "dane", 0, time.Minute),
		entry("popular-policy.example", "dane-only", 20, time.Hour),
		entry("unused-miss.example", "", 0, time.Minute),
		entry("popular-miss.example", "", 20, time.Hour),
	}

	kept, evicted := partitionCacheEntriesForLimit(entries, now, 3, 2)
	if len(kept) != 2 || len(evicted) != 2 {
		t.Fatalf("unexpected partition sizes: kept=%d evicted=%d", len(kept), len(evicted))
	}
	for _, removed := range evicted {
		if cacheStructHasPolicy(removed.Value) {
			t.Fatalf("expected no-policy entries to be evicted first, got %q", removed.Key)
		}
	}
	keptKeys := map[string]bool{}
	for _, retained := range kept {
		keptKeys[retained.Key] = true
	}
	for _, want := range []string{"unused-policy.example", "popular-policy.example"} {
		if !keptKeys[want] {
			t.Fatalf("expected policy entry %q to be retained", want)
		}
	}
}

func TestSortCacheEntriesByCounter(t *testing.T) {
	clearCacheHitCountersForTest()
	t.Cleanup(clearCacheHitCountersForTest)
	entries := []cache.Entry[*CacheStruct]{
		{Key: "low.example", Value: &CacheStruct{Counter: 2}},
		{Key: "z.example", Value: &CacheStruct{Counter: 10}},
		{Key: "a.example", Value: &CacheStruct{Counter: 10}},
	}
	counters := sortCacheEntriesByCounter(entries)
	wantKeys := []string{"a.example", "z.example", "low.example"}
	wantCounters := []uint32{10, 10, 2}
	for i := range entries {
		if entries[i].Key != wantKeys[i] || counters[i] != wantCounters[i] {
			t.Fatalf("entry %d = %s/%d, want %s/%d", i, entries[i].Key, counters[i], wantKeys[i], wantCounters[i])
		}
	}
}

func TestCacheMaintenancePreservesConcurrentReplacement(t *testing.T) {
	oldPolCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
	}()

	stale := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(-time.Hour)},
		Policy:    "dane",
	}
	fresh := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Hour)},
		Policy:    "dane-only",
	}
	polCache.Set("example.com", stale)
	polCache.Set("example.com", fresh)

	current, changed := discardCachedPolicyStateIfCurrent("example.com", stale)
	if changed || current != fresh {
		t.Fatal("stale maintenance snapshot replaced a refreshed cache entry")
	}
	current, changed = removeCacheEntryIfCurrent("example.com", stale)
	if changed || current != fresh {
		t.Fatal("stale eviction snapshot removed a refreshed cache entry")
	}
	stored, ok := polCache.Get("example.com")
	if !ok || stored != fresh {
		t.Fatal("refreshed cache entry was not preserved")
	}
}

func BenchmarkPartitionCacheEntries50K(b *testing.B) {
	const entryCount = 50_001
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	base := make([]cache.Entry[*CacheStruct], entryCount)
	for i := range base {
		policy := ""
		if i%2 == 0 {
			policy = "dane"
		}
		base[i] = cache.Entry[*CacheStruct]{
			Key: "domain-" + strconv.Itoa(i) + ".example",
			Value: &CacheStruct{
				Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Duration(i%3600+1) * time.Second)},
				Policy:    policy,
				Counter:   uint32(i % 100),
			},
		}
	}
	work := make([]cache.Entry[*CacheStruct], entryCount)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		copy(work, base)
		b.StartTimer()
		kept, evicted := partitionCacheEntriesForLimit(work, now, 50_000, 45_000)
		if len(kept) != 45_000 || len(evicted) != 5_001 {
			b.Fatalf("unexpected partition sizes: kept=%d evicted=%d", len(kept), len(evicted))
		}
	}
}

func BenchmarkSortCacheEntriesByCounter50K(b *testing.B) {
	const entryCount = 50_000
	base := make([]cache.Entry[*CacheStruct], entryCount)
	for i := range base {
		base[i] = cache.Entry[*CacheStruct]{
			Key: "domain-" + strconv.Itoa(i) + ".example",
			Value: &CacheStruct{
				Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Hour)},
				Policy:    "dane",
				Counter:   uint32(i % 100),
			},
		}
	}
	work := make([]cache.Entry[*CacheStruct], entryCount)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		copy(work, base)
		b.StartTimer()
		if counters := sortCacheEntriesByCounter(work); len(counters) != entryCount {
			b.Fatal("unexpected counter count")
		}
	}
}

func TestTryCachedPolicyDoesNotRewriteCacheEntry(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	clearCacheHitCountersForTest()
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
		clearCacheHitCountersForTest()
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	defer polCache.Close()

	original := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       60,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	polCache.Set("example.com", original)

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(c2)
		close(done)
	}()

	updated, ok := tryCachedPolicy(c1, "example.com", false)
	c1.Close()
	c2.Close()
	<-done

	if !ok {
		t.Fatal("expected cached policy to be used")
	}
	if original.Counter != 0 {
		t.Fatalf("expected original cached pointer to remain unchanged, got counter %d", original.Counter)
	}
	if updated != original {
		t.Fatal("expected cache hit to return the stored entry without rewriting it")
	}
	stored, ok := polCache.Get("example.com")
	if !ok {
		t.Fatal("expected cache entry to remain stored")
	}
	if stored.Counter != 0 {
		t.Fatalf("expected stored counter to remain 0 before flush, got %d", stored.Counter)
	}
	if got := cacheEntryCounter("example.com", stored); got != 1 {
		t.Fatalf("expected combined counter to be 1, got %d", got)
	}
}

func TestCacheHitCounterCleanupRequiresZeroAndNoCachedPolicy(t *testing.T) {
	oldPolCache := polCache
	clearCacheHitCountersForTest()
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
		clearCacheHitCountersForTest()
	}()

	zeroNoPolicy := &atomic.Uint32{}
	cacheHitCounters.Store("zero-no-policy.example", zeroNoPolicy)
	cleanupCacheHitCounterIfUnused(false, "zero-no-policy.example")
	if _, ok := cacheHitCounters.Load("zero-no-policy.example"); ok {
		t.Fatal("expected zero counter without cached policy to be removed")
	}

	nonzeroNoPolicy := &atomic.Uint32{}
	nonzeroNoPolicy.Add(1)
	cacheHitCounters.Store("nonzero-no-policy.example", nonzeroNoPolicy)
	cleanupCacheHitCounterIfUnused(false, "nonzero-no-policy.example")
	if _, ok := cacheHitCounters.Load("nonzero-no-policy.example"); !ok {
		t.Fatal("expected nonzero counter without cached policy to be retained")
	}

	polCache.Set("zero-with-policy.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       60,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	})
	zeroWithPolicy := &atomic.Uint32{}
	cacheHitCounters.Store("zero-with-policy.example", zeroWithPolicy)
	flushCacheHitCounters(false)
	if _, ok := cacheHitCounters.Load("zero-with-policy.example"); !ok {
		t.Fatal("expected zero counter with cached policy to be retained")
	}
}

func TestTidyCacheRemovesUnusedHitCounterAfterPolicyDiscard(t *testing.T) {
	oldPolCache := polCache
	clearCacheHitCountersForTest()
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
		clearCacheHitCountersForTest()
	}()

	now := time.Now()
	polCache.Set("stale-policy.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Duration(CACHE_MAX_AGE+1) * time.Second)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       60,
			ExpiresAt: now.Add(-time.Duration(CACHE_MAX_AGE+1) * time.Second),
		},
	})
	cacheHitCounters.Store("stale-policy.example", &atomic.Uint32{})

	_ = tidyCache()

	if _, ok := cacheHitCounters.Load("stale-policy.example"); ok {
		t.Fatal("expected zero counter to be removed after stale policy discard")
	}
}

func TestPurgeCacheRemovesFlushedHitCounters(t *testing.T) {
	oldPolCache := polCache
	clearCacheHitCountersForTest()
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
		clearCacheHitCountersForTest()
	}()

	polCache.Set("purged.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       60,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	})
	counter := &atomic.Uint32{}
	counter.Add(1)
	cacheHitCounters.Store("purged.example", counter)

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(c2)
		close(done)
	}()
	purgeCache(c1)
	c1.Close()
	c2.Close()
	<-done

	if _, ok := cacheHitCounters.Load("purged.example"); ok {
		t.Fatal("expected purge to remove flushed hit counter without cached policy")
	}
}

func TestReadEnvRejectsInvalidBooleanValues(t *testing.T) {
	original := config
	defer func() { config = original }()

	tests := []struct {
		name     string
		prefetch string
		tlsrpt   string
		wantErr  bool
	}{
		{name: "valid disabled", prefetch: "0", tlsrpt: "0"},
		{name: "valid enabled", prefetch: "1", tlsrpt: "1"},
		{name: "invalid prefetch", prefetch: "true", tlsrpt: "0", wantErr: true},
		{name: "invalid tlsrpt", prefetch: "0", tlsrpt: "yes", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TLSPOL_PREFETCH", tt.prefetch)
			t.Setenv("TLSPOL_TLSRPT", tt.tlsrpt)
			config = Config{}
			err := readEnv()
			if (err != nil) != tt.wantErr {
				t.Fatalf("readEnv() error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestQueryDomainSingleflight(t *testing.T) {
	origFn := queryDomainOnce
	queryGroup.Forget("example.com")
	defer func() {
		queryDomainOnce = origFn
		queryGroup.Forget("example.com")
	}()

	var calls atomic.Int32
	block := make(chan struct{})
	queryDomainOnce = func(domain string) domainResult {
		calls.Add(1)
		<-block
		return domainResult{
			Policy: "dane",
			TTL:    300,
			Dane:   branchFromResult("dane", "", 300),
		}
	}

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			queryDomain("example.com")
		}()
	}

	// Allow goroutines to block inside the first call
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected single underlying call, got %d", got)
	}
}

func TestSelectCachedPolicyPrioritizesFreshDane(t *testing.T) {
	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example servername=hostname",
			Report:    "policy_type=sts",
			TTL:       3600,
			ExpiresAt: now.Add(time.Hour),
		},
	}

	if _, _, _, ok := selectCachedPolicy(c, now); ok {
		t.Fatal("expected MTA-STS-only cache entry to miss without fresh DANE state")
	}

	c.Dane = PolicyBranch{
		TTL:       300,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	policy, report, ttl, ok := selectCachedPolicy(c, now)
	if !ok {
		t.Fatal("expected MTA-STS to be usable with fresh no-DANE state")
	}
	if policy != c.MtaSts.Policy || report != c.MtaSts.Report || ttl != 300 {
		t.Fatalf("unexpected MTA-STS selection: policy=%q report=%q ttl=%d", policy, report, ttl)
	}

	c.Dane = PolicyBranch{
		Policy:    "dane-only",
		TTL:       600,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	policy, _, ttl, ok = selectCachedPolicy(c, now)
	if !ok || policy != "dane-only" || ttl != 600 {
		t.Fatalf("expected fresh DANE to override MTA-STS, got policy=%q ttl=%d ok=%v", policy, ttl, ok)
	}
}

func TestMtaStsBranchHonorsMaxAge(t *testing.T) {
	now := time.Now()
	branch := mtaStsBranchFromResult("secure match=mx.example servername=hostname", "policy_type=sts", 1)
	if branch.TTL != 1 {
		t.Fatalf("expected one-second MTA-STS max_age to remain unchanged, got %d", branch.TTL)
	}
	branch = expireMtaStsBranch(branch, now)
	if want := now.Add(time.Second); !branch.ExpiresAt.Equal(want) {
		t.Fatalf("MTA-STS expiry = %s, want %s", branch.ExpiresAt, want)
	}

	zero := mtaStsBranchFromResult("secure match=mx.example servername=hostname", "policy_type=sts", 0)
	if zero.HasData() {
		t.Fatalf("expected max_age=0 policy not to be cached, got %+v", zero)
	}
}

func TestShouldQueryMtaStsBacksOffRecentFailure(t *testing.T) {
	now := time.Now()
	cached := &CacheStruct{MtaStsLastAttempt: now.Add(-time.Minute)}
	if shouldQueryMtaSts(cached, PolicyBranch{}, PolicyBranch{}, now, 0) {
		t.Fatal("expected a recent failed MTA-STS fetch to be throttled")
	}

	cached.MtaStsLastAttempt = now.Add(-MTA_STS_FETCH_RETRY_INTERVAL - time.Second)
	if !shouldQueryMtaSts(cached, PolicyBranch{}, PolicyBranch{}, now, 0) {
		t.Fatal("expected MTA-STS fetch to resume after the retry interval")
	}
}

func TestQueryDomainDaneTempDoesNotDowngradeToMtaSts(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "TEMP", 0
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 86400
	}

	result := queryDomainOnceImpl("example.com")
	if result.Policy != "TEMP" || result.TTL != 0 {
		t.Fatalf("expected temporary DANE failure to win over MTA-STS, got %+v", result)
	}
	if result.MtaSts.Policy == "" || result.MtaSts.TTL != 86400 {
		t.Fatalf("expected MTA-STS branch to be retained for cache, got %+v", result.MtaSts)
	}
}

func TestQueryDomainUsesMtaStsOnlyAfterFreshNoDane(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 86400
	}

	result := queryDomainOnceImpl("example.com")
	if result.Policy != "secure match=mx.example servername=hostname" || result.Report != "policy_type=sts" || result.TTL != 300 {
		t.Fatalf("unexpected selected policy: %+v", result)
	}
}

func TestRefreshDomainReusesFreshMtaStsBranch(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(10 * time.Minute),
		},
	}

	result := refreshDomainOnceImpl("example.com", cached)
	if daneCalls.Load() != 1 {
		t.Fatalf("expected one DANE refresh, got %d", daneCalls.Load())
	}
	if mtaStsCalls.Load() != 0 {
		t.Fatalf("expected fresh MTA-STS branch to be reused, got %d refreshes", mtaStsCalls.Load())
	}
	if result.Policy != cached.MtaSts.Policy {
		t.Fatalf("expected cached MTA-STS policy, got %q", result.Policy)
	}
	if !result.Dane.HasData() {
		t.Fatal("expected refreshed no-DANE branch to be returned for cache merge")
	}
	if result.MtaSts.HasData() {
		t.Fatal("expected fresh MTA-STS branch not to be returned as refreshed data")
	}
}

func TestPrefetchDomainRenewsNearExpiryMtaStsBranch(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 86400
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(20 * time.Second)},
		Dane: PolicyBranch{
			TTL:       policyBranchRecheckTTL(),
			ExpiresAt: now.Add(POLICY_BRANCH_RECHECK),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(20 * time.Second),
		},
		DaneLastAttempt: now,
	}

	refresh := refreshDomainOnceImpl("example.com", cached)
	if mtaStsCalls.Load() != 0 {
		t.Fatalf("expected normal refresh to reuse positive-TTL MTA-STS, got %d calls", mtaStsCalls.Load())
	}
	if refresh.MtaSts.HasData() {
		t.Fatalf("expected normal refresh not to return refreshed MTA-STS data, got %+v", refresh)
	}

	mtaStsCalls.Store(0)
	prefetch := prefetchDomainOnceImpl("example.com", cached)
	if mtaStsCalls.Load() != 1 || !prefetch.MtaStsAttempted || !prefetch.MtaSts.HasData() {
		t.Fatalf("expected prefetch to renew near-expiry MTA-STS, calls=%d result=%+v", mtaStsCalls.Load(), prefetch)
	}

	daneCalls.Store(0)
	mtaStsCalls.Store(0)
	uncached := queryDomainOnceImpl("example.com")
	if daneCalls.Load() != 1 || mtaStsCalls.Load() != 1 || !uncached.Dane.HasData() || !uncached.MtaSts.HasData() {
		t.Fatalf("expected uncached query path to refresh both branches, dane=%d mtasts=%d result=%+v", daneCalls.Load(), mtaStsCalls.Load(), uncached)
	}

	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "TEMP", "", 0
	}
	expired := cloneCacheStruct(cached)
	expired.Expirable.ExpiresAt = now.Add(-time.Second)
	expired.MtaSts.ExpiresAt = now.Add(-time.Second)
	mtaStsCalls.Store(0)
	afterExpiry := queryDomainBranches("example.com", expired, now)
	if mtaStsCalls.Load() != 1 || afterExpiry.Policy != "" || afterExpiry.MtaSts.HasData() {
		t.Fatalf("expected expired MTA-STS plus fetch failure to fall back without refreshed data, calls=%d result=%+v", mtaStsCalls.Load(), afterExpiry)
	}
}

func TestPrefetchDomainRetainsUnexpiredMtaStsWhenLivePolicyUnavailable(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "", 86400
	}
	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(20 * time.Second)},
		Dane: PolicyBranch{
			TTL:       policyBranchRecheckTTL(),
			ExpiresAt: now.Add(POLICY_BRANCH_RECHECK),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(20 * time.Second),
		},
		DaneLastAttempt: now,
	}

	tests := []struct {
		name   string
		policy string
		ttl    uint32
	}{
		{name: "missing live policy"},
		{name: "temporary fetch failure", policy: "TEMP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
				return tt.policy, "", tt.ttl
			}
			result := prefetchDomainOnceImpl("example.com", cached)
			if result.Policy != cached.MtaSts.Policy || result.Report != cached.MtaSts.Report {
				t.Fatalf("expected cached policy to remain selected, got %+v", result)
			}
			if result.MtaSts.HasData() {
				t.Fatalf("expected unavailable live policy not to replace cached branch, got %+v", result.MtaSts)
			}
		})
	}

	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "", "", 600 // A valid mode=none/testing policy has a nonzero max_age.
	}
	result := prefetchDomainOnceImpl("example.com", cached)
	if result.Policy != "" || !result.MtaSts.HasData() || result.MtaSts.TTL != 600 {
		t.Fatalf("expected valid no-enforcement policy to replace cached branch, got %+v", result)
	}
}

func TestQueryDomainThrottlesMtaStsWhenDanePolicyCached(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "dane-only", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "TEMP", "", 0
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Second)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaStsLastAttempt: now.Add(-time.Hour),
	}

	result := queryDomainBranches("example.com", cached, now)
	if daneCalls.Load() != 1 {
		t.Fatalf("expected DANE to refresh, got %d calls", daneCalls.Load())
	}
	if mtaStsCalls.Load() != 0 || result.MtaStsAttempted {
		t.Fatalf("expected MTA-STS retry to be throttled, calls=%d result=%+v", mtaStsCalls.Load(), result)
	}
	if result.Policy != "dane-only" {
		t.Fatalf("expected refreshed DANE policy, got %+v", result)
	}
}

func TestQueryDomainRetriesMtaStsAfterDailyDanePolicyWindow(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "dane-only", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "TEMP", "", 0
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Second)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaStsLastAttempt: now.Add(-POLICY_BRANCH_RECHECK - time.Second),
	}

	result := queryDomainBranches("example.com", cached, now)
	if mtaStsCalls.Load() != 1 || !result.MtaStsAttempted {
		t.Fatalf("expected MTA-STS retry after daily window, calls=%d result=%+v", mtaStsCalls.Load(), result)
	}
}

func TestQueryDomainThrottlesDaneWhenMtaStsPolicyCachedAndDaneMissing(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "dane-only", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(time.Hour),
		},
		DaneLastAttempt: now.Add(-time.Hour),
	}

	result := queryDomainBranches("example.com", cached, now)
	if daneCalls.Load() != 0 || result.DaneAttempted {
		t.Fatalf("expected DANE retry to be throttled, calls=%d result=%+v", daneCalls.Load(), result)
	}
	if mtaStsCalls.Load() != 0 || result.MtaStsAttempted {
		t.Fatalf("expected fresh MTA-STS branch to be reused, calls=%d result=%+v", mtaStsCalls.Load(), result)
	}
	if result.Policy != cached.MtaSts.Policy {
		t.Fatalf("expected cached MTA-STS policy, got %+v", result)
	}
}

func TestQueryDomainDoesNotThrottlePreviouslyAvailableDaneWhenMtaStsPolicyCached(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "dane-only", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(time.Hour),
		},
		DaneLastAttempt: now.Add(-time.Hour),
	}

	result := queryDomainBranches("example.com", cached, now)
	if daneCalls.Load() != 1 || !result.DaneAttempted {
		t.Fatalf("expected previously available DANE to refresh normally, calls=%d result=%+v", daneCalls.Load(), result)
	}
	if result.Policy != "dane-only" {
		t.Fatalf("expected refreshed DANE policy, got %+v", result)
	}
}

func TestQueryDomainRetriesDaneAfterDailyMtaStsPolicyWindow(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			TTL:       300,
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(time.Hour),
		},
		DaneLastAttempt: now.Add(-POLICY_BRANCH_RECHECK - time.Second),
	}

	result := queryDomainBranches("example.com", cached, now)
	if daneCalls.Load() != 1 || !result.DaneAttempted {
		t.Fatalf("expected DANE retry after daily window, calls=%d result=%+v", daneCalls.Load(), result)
	}
}

func TestMergeCacheResultUsesDailyRecheckForMissingSecondaryBranches(t *testing.T) {
	now := time.Now()
	mtaStsOnly := mergeCacheResult(nil, domainResult{
		Dane: PolicyBranch{
			TTL: 300,
		},
		MtaSts: PolicyBranch{
			Policy: "secure match=mx.example servername=hostname",
			Report: "policy_type=sts",
			TTL:    600,
		},
		DaneAttempted:   true,
		MtaStsAttempted: true,
	}, now)
	if mtaStsOnly.Dane.TTL != policyBranchRecheckTTL() {
		t.Fatalf("expected missing DANE branch to use daily recheck TTL, got %d", mtaStsOnly.Dane.TTL)
	}
	if !mtaStsOnly.DaneLastAttempt.Equal(now) || !mtaStsOnly.MtaStsLastAttempt.Equal(now) {
		t.Fatalf("expected branch attempts to be recorded, got dane=%s mtasts=%s", mtaStsOnly.DaneLastAttempt, mtaStsOnly.MtaStsLastAttempt)
	}

	daneOnly := mergeCacheResult(nil, domainResult{
		Dane: PolicyBranch{
			Policy: "dane-only",
			TTL:    300,
		},
		MtaSts: PolicyBranch{
			TTL: 600,
		},
		DaneAttempted:   true,
		MtaStsAttempted: true,
	}, now)
	if daneOnly.MtaSts.TTL != policyBranchRecheckTTL() {
		t.Fatalf("expected missing MTA-STS branch to use daily recheck TTL, got %d", daneOnly.MtaSts.TTL)
	}
}

func TestNextPrefetchTime(t *testing.T) {
	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       300,
			ExpiresAt: now.Add(5 * time.Minute),
		},
	}

	due, ok := nextPrefetchTime(c, now)
	if !ok {
		t.Fatal("expected policy to be scheduled for prefetch")
	}
	assertPolicyPrefetchDueInWindow(t, due, now, 300)

	c.Dane.ExpiresAt = now.Add(-time.Second)
	due, ok = nextPrefetchTime(c, now)
	if ok {
		t.Fatalf("expected expired policy not to be scheduled for background prefetch, got %s", due)
	}

	c.Dane = PolicyBranch{
		TTL:       300,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	c.MtaSts = PolicyBranch{
		Policy:    "secure match=mx.example servername=hostname",
		Report:    "policy_type=sts",
		TTL:       600,
		ExpiresAt: now.Add(-time.Second),
	}
	due, ok = nextPrefetchTime(c, now)
	if ok {
		t.Fatalf("expected unservable split cache entry not to be scheduled, got %s", due)
	}
}

func TestFreshNoPolicyDoesNotEnterPrefetchLoop(t *testing.T) {
	oldScheduler := activePrefetchScheduler.Load()
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	defer activePrefetchScheduler.Store(oldScheduler)

	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Duration(CACHE_NOTFOUND_TTL) * time.Second)},
		Dane: PolicyBranch{
			TTL:       CACHE_NOTFOUND_TTL,
			ExpiresAt: now.Add(time.Duration(CACHE_NOTFOUND_TTL) * time.Second),
		},
		MtaSts: PolicyBranch{
			TTL:       CACHE_NOTFOUND_TTL,
			ExpiresAt: now.Add(time.Duration(CACHE_NOTFOUND_TTL) * time.Second),
		},
	}

	if due, ok := nextPrefetchTime(c, now); ok {
		t.Fatalf("expected fresh no-policy entry not to schedule prefetch, got %s", due)
	}
	if shouldRetryCachedPolicyPrefetch(c, now) {
		t.Fatal("expected fresh no-policy entry not to enter retry prefetch")
	}
	if due, ok := nextPrefetchTimeAfterMiss(c, now); ok {
		t.Fatalf("expected fresh no-policy miss not to schedule another prefetch, got %s", due)
	}

	scheduleCachedPolicyPrefetch("fresh-no-policy.example", c, now)
	if due, ok := scheduler.nextDue(); ok {
		t.Fatalf("expected no scheduled prefetch for fresh no-policy entry, got %s", due)
	}
}

func assertPolicyPrefetchDueInWindow(t *testing.T, due time.Time, now time.Time, ttl uint32) {
	t.Helper()
	earliest := now.Add(time.Duration(ttl-PREFETCH_INTERVAL) * time.Second)
	expiry := now.Add(time.Duration(ttl) * time.Second)
	if due.Before(earliest) || due.After(expiry) {
		t.Fatalf("expected prefetch due between %s and %s, got %s", earliest, expiry, due)
	}
	if !due.Equal(due.Truncate(PREFETCH_SLOT_INTERVAL)) {
		t.Fatalf("expected prefetch due time to align to %s slot, got %s", PREFETCH_SLOT_INTERVAL, due)
	}
}

func TestNextPrefetchTimeAfterMissWaitsForUsablePolicyExpiry(t *testing.T) {
	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(20 * time.Second)},
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       300,
			ExpiresAt: now.Add(20 * time.Second),
		},
	}

	due, ok := nextPrefetchTimeAfterMiss(c, now)
	if !ok {
		t.Fatal("expected still-usable policy to be retried at expiry")
	}
	expectedEarliest := now.Add(20 * time.Second)
	if due.Before(expectedEarliest) || due.After(expectedEarliest.Add(PREFETCH_SLOT_INTERVAL)) {
		t.Fatalf("unexpected retry time: got %s want about %s", due, expectedEarliest)
	}
	if !due.Equal(due.Truncate(PREFETCH_SLOT_INTERVAL)) {
		t.Fatalf("expected retry time to align to %s slot, got %s", PREFETCH_SLOT_INTERVAL, due)
	}

	c.Dane.ExpiresAt = now.Add(-time.Second)
	due, ok = nextPrefetchTimeAfterMiss(c, now)
	if ok {
		t.Fatalf("expected expired policy miss not to be retried, got %s", due)
	}
}

func TestScheduleCachedPolicyPrefetchRetriesUnusableSplitEntry(t *testing.T) {
	oldScheduler := activePrefetchScheduler.Load()
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	defer activePrefetchScheduler.Store(oldScheduler)

	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Dane: PolicyBranch{
			TTL:       300,
			ExpiresAt: now.Add(5 * time.Minute),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example servername=hostname",
			Report:    "policy_type=sts",
			TTL:       600,
			ExpiresAt: now.Add(-time.Second),
		},
	}

	scheduleCachedPolicyPrefetch("split.example", c, now)

	due, ok := scheduler.nextDue()
	if !ok {
		t.Fatal("expected unservable split entry to enter prefetch retry")
	}
	if due.Before(now) || due.After(now.Add(PREFETCH_SLOT_INTERVAL)) {
		t.Fatalf("expected split entry retry in the next slot, got %s from %s", due, now)
	}
	if !due.Equal(due.Truncate(PREFETCH_SLOT_INTERVAL)) {
		t.Fatalf("expected split entry retry to align to %s slot, got %s", PREFETCH_SLOT_INTERVAL, due)
	}
}

func TestPrefetchDuePoliciesExtendsNearExpiryMtaSts(t *testing.T) {
	oldPolCache := polCache
	oldScheduler := activePrefetchScheduler.Load()
	oldSemaphore := semaphore
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	semaphore = make(chan struct{}, 1)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
		activePrefetchScheduler.Store(oldScheduler)
		semaphore = oldSemaphore
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 0
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	key := "prefetch-mtasts.example"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(20 * time.Second)},
		Dane: PolicyBranch{
			TTL:       policyBranchRecheckTTL(),
			ExpiresAt: now.Add(time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(20 * time.Second),
		},
		DaneLastAttempt: now,
	})
	scheduler.schedule(key, now.Add(-time.Second))

	prefetchDuePolicies(scheduler)
	if daneCalls.Load() != 0 {
		t.Fatalf("expected DANE not to refresh while no-DANE branch is still outside the prefetch window, calls=%d", daneCalls.Load())
	}

	stored, found := polCache.Get(key)
	if !found {
		t.Fatal("expected cache entry to remain after prefetch")
	}
	if stored.MtaSts.Policy != "secure match=mx.example servername=hostname" {
		t.Fatalf("expected MTA-STS branch to be refreshed, got %+v", stored.MtaSts)
	}
	if ttl := stored.MtaSts.RemainingTTL(time.Now()); ttl < 500 {
		t.Fatalf("expected MTA-STS expiry to be extended, remaining TTL=%d", ttl)
	}
}

func TestPrefetchDuePoliciesBacksOffNearExpiryMtaStsFailure(t *testing.T) {
	oldPolCache := polCache
	oldScheduler := activePrefetchScheduler.Load()
	oldSemaphore := semaphore
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	semaphore = make(chan struct{}, 1)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
		activePrefetchScheduler.Store(oldScheduler)
		semaphore = oldSemaphore
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 0
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "TEMP", "", 0
	}

	now := time.Now()
	key := "prefetch-mtasts-fail.example"
	cachedPolicy := "secure match=mx.cached.example servername=hostname"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(20 * time.Second)},
		Dane: PolicyBranch{
			TTL:       policyBranchRecheckTTL(),
			ExpiresAt: now.Add(time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy:    cachedPolicy,
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(20 * time.Second),
		},
		DaneLastAttempt: now,
	})
	scheduler.schedule(key, now.Add(-time.Second))

	prefetchDuePolicies(scheduler)
	if daneCalls.Load() != 0 {
		t.Fatalf("expected DANE not to refresh while no-DANE branch is still outside the prefetch window, calls=%d", daneCalls.Load())
	}

	stored, found := polCache.Get(key)
	if !found || stored.MtaSts.Policy != cachedPolicy {
		t.Fatalf("expected failed prefetch to keep cached MTA-STS during retry, found=%v entry=%+v", found, stored)
	}
	failure, found := scheduler.failures[key]
	if !found || failure.attempts != 1 {
		t.Fatalf("expected first prefetch failure to be tracked, found=%v failure=%+v", found, failure)
	}
	due, ok := scheduler.nextDue()
	if !ok {
		t.Fatal("expected failed MTA-STS prefetch to be rescheduled")
	}
	delay := due.Sub(now)
	expectedDelay := time.Duration(PREFETCH_INTERVAL) * time.Second
	if delay < expectedDelay || delay > expectedDelay+PREFETCH_SLOT_INTERVAL {
		t.Fatalf("expected first retry after about %d seconds, got %s", PREFETCH_INTERVAL, delay)
	}
}

func TestPrefetchRetryBackoffAndDiscardDeadline(t *testing.T) {
	now := time.Unix(1000, 0)
	scheduler := newPrefetchScheduler()
	key := "failed.example"

	due, attempts, delay, ok := scheduler.scheduleRetry(key, now)
	if !ok || attempts != 1 || delay != 30*time.Second || !due.Equal(now.Add(30*time.Second)) {
		t.Fatalf("unexpected first retry: due=%s attempts=%d delay=%s ok=%v", due, attempts, delay, ok)
	}

	due, attempts, delay, ok = scheduler.scheduleRetry(key, now.Add(30*time.Second))
	if !ok || attempts != 2 || delay != time.Minute || !due.Equal(now.Add(90*time.Second)) {
		t.Fatalf("unexpected second retry: due=%s attempts=%d delay=%s ok=%v", due, attempts, delay, ok)
	}

	due, attempts, delay, ok = scheduler.scheduleRetry(key, now.Add(90*time.Second))
	if !ok || attempts != 3 || delay != 2*time.Minute || !due.Equal(now.Add(210*time.Second)) {
		t.Fatalf("unexpected third retry: due=%s attempts=%d delay=%s ok=%v", due, attempts, delay, ok)
	}

	due, attempts, delay, ok = scheduler.scheduleRetry(key, now.Add(29*time.Minute))
	if !ok || attempts != 4 || delay != time.Minute || !due.Equal(now.Add(PREFETCH_RETRY_MAX_AGE)) {
		t.Fatalf("expected retry to clamp at discard deadline: due=%s attempts=%d delay=%s ok=%v", due, attempts, delay, ok)
	}

	_, _, _, ok = scheduler.scheduleRetry(key, now.Add(PREFETCH_RETRY_MAX_AGE))
	if ok {
		t.Fatal("expected retry window to expire at the 30-minute deadline")
	}
	if _, found := scheduler.failures[key]; found {
		t.Fatal("expected retry state to be cleared after discard deadline")
	}
	if _, ok := scheduler.nextDue(); ok {
		t.Fatal("expected scheduled retry to be removed after discard deadline")
	}
}

func TestScheduleFailedPolicyPrefetchDiscardsCacheAfterRetryWindow(t *testing.T) {
	oldPolCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
	}()

	now := time.Now()
	key := "discard.example"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       3600,
			ExpiresAt: now.Add(time.Hour),
		},
	})

	scheduler := newPrefetchScheduler()
	scheduler.schedule(key, now)
	scheduler.failures[key] = prefetchFailure{
		firstFailed: now.Add(-PREFETCH_RETRY_MAX_AGE),
		attempts:    8,
	}

	cached, _ := polCache.Get(key)
	scheduleFailedPolicyPrefetch(scheduler, key, cached, domainResult{}, now)

	if _, found := polCache.Get(key); found {
		t.Fatal("expected failed cached domain to be discarded")
	}
	if _, found := scheduler.failures[key]; found {
		t.Fatal("expected retry state to be cleared")
	}
	if _, ok := scheduler.nextDue(); ok {
		t.Fatal("expected failed domain to be unscheduled")
	}
}

func TestScheduleFailedPolicyPrefetchPreservesStatsOnDiscard(t *testing.T) {
	oldPolCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
	}()

	now := time.Now()
	key := "stats-discard.example"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       3600,
			ExpiresAt: now.Add(time.Hour),
		},
		Counter: 11,
	})

	scheduler := newPrefetchScheduler()
	scheduler.schedule(key, now)
	scheduler.failures[key] = prefetchFailure{
		firstFailed: now.Add(-PREFETCH_RETRY_MAX_AGE),
		attempts:    8,
	}
	cached, _ := polCache.Get(key)
	scheduleFailedPolicyPrefetch(scheduler, key, cached, domainResult{}, now)

	stored, found := polCache.Get(key)
	if !found {
		t.Fatal("expected stats-only entry after policy discard")
	}
	if !stored.policyStateEmpty() || stored.Counter != 11 {
		t.Fatalf("expected stats-only entry with counter, got %+v", stored)
	}
	if _, ok := scheduler.nextDue(); ok {
		t.Fatal("expected stats-only entry not to be scheduled")
	}
}

func TestScheduleFailedPolicyPrefetchKeepsFormerDaneDuringGrace(t *testing.T) {
	oldPolCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
	}()

	now := time.Now()
	key := "dane-grace.example"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example servername=hostname",
			Report:    "policy_type=sts",
			TTL:       86400,
			ExpiresAt: now.Add(time.Hour),
		},
	})

	scheduler := newPrefetchScheduler()
	scheduler.schedule(key, now)
	scheduler.failures[key] = prefetchFailure{
		firstFailed: now.Add(-PREFETCH_RETRY_MAX_AGE),
		attempts:    8,
	}
	cached, _ := polCache.Get(key)
	scheduleFailedPolicyPrefetch(scheduler, key, cached, domainResult{DaneAttempted: true}, now)

	stored, found := polCache.Get(key)
	if !found {
		t.Fatal("expected cache entry to remain during DANE grace")
	}
	if stored.Dane.Policy != "dane-only" {
		t.Fatalf("expected DANE policy to remain during grace, got %+v", stored.Dane)
	}
	if _, ok := scheduler.nextDue(); !ok {
		t.Fatal("expected another retry to be scheduled during grace")
	}
}

func TestScheduleFailedPolicyPrefetchClearsFormerDaneAfterGrace(t *testing.T) {
	oldPolCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	defer func() {
		polCache.Close()
		polCache = oldPolCache
	}()

	now := time.Now()
	key := "dane-after-grace.example"
	mtaStsPolicy := "secure match=mx.example servername=hostname"
	polCache.Set(key, &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-25 * time.Hour)},
		Dane: PolicyBranch{
			Policy:    "dane-only",
			TTL:       300,
			ExpiresAt: now.Add(-25 * time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy:    mtaStsPolicy,
			Report:    "policy_type=sts",
			TTL:       86400,
			ExpiresAt: now.Add(time.Hour),
		},
	})

	scheduler := newPrefetchScheduler()
	scheduler.schedule(key, now)
	scheduler.failures[key] = prefetchFailure{
		firstFailed: now.Add(-PREFETCH_RETRY_MAX_AGE),
		attempts:    8,
	}
	cached, _ := polCache.Get(key)
	scheduleFailedPolicyPrefetch(scheduler, key, cached, domainResult{DaneAttempted: true}, now)

	stored, found := polCache.Get(key)
	if !found {
		t.Fatal("expected MTA-STS cache entry to remain after DANE grace")
	}
	if stored.Dane.Policy != "" || stored.Dane.TTL != policyBranchRecheckTTL() {
		t.Fatalf("expected DANE to be cleared to daily missing state, got %+v", stored.Dane)
	}
	if stored.Policy != mtaStsPolicy {
		t.Fatalf("expected selected policy to switch to cached MTA-STS, got %q", stored.Policy)
	}
}
