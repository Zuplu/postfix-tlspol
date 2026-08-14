/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
)

type securityTestAddr struct {
	network string
	address string
}

func (a securityTestAddr) Network() string { return a.network }
func (a securityTestAddr) String() string  { return a.address }

type securityTestConn struct {
	input               *bytes.Reader
	output              bytes.Buffer
	remote              net.Addr
	maxRead             int
	readDeadline        time.Time
	readDeadlines       []time.Time
	readDeadlinesAtRead []time.Time
	writeDeadline       time.Time
	writeDeadlines      []time.Time
}

func newSecurityTestConn(input []byte, remote net.Addr) *securityTestConn {
	return &securityTestConn{input: bytes.NewReader(input), remote: remote}
}

func (c *securityTestConn) Read(p []byte) (int, error) {
	c.readDeadlinesAtRead = append(c.readDeadlinesAtRead, c.readDeadline)
	if c.maxRead > 0 && len(p) > c.maxRead {
		p = p[:c.maxRead]
	}
	return c.input.Read(p)
}
func (c *securityTestConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *securityTestConn) Close() error                { return nil }
func (c *securityTestConn) LocalAddr() net.Addr {
	return securityTestAddr{network: "tcp", address: "127.0.0.1:8642"}
}
func (c *securityTestConn) RemoteAddr() net.Addr        { return c.remote }
func (c *securityTestConn) SetDeadline(time.Time) error { return nil }
func (c *securityTestConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	c.readDeadlines = append(c.readDeadlines, deadline)
	return nil
}
func (c *securityTestConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	c.writeDeadlines = append(c.writeDeadlines, deadline)
	return nil
}

func TestHandleSocketmapRejectsInvalidJSONDomain(t *testing.T) {
	conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	handleSocketmapConnection(conn, bufio.NewReader(bytes.NewReader(netstring.Marshal("JSON bad@domain"))))

	if !bytes.Equal(conn.output.Bytes(), NS_NOTFOUND) {
		t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_NOTFOUND)
	}
}

func TestHandleSocketmapRejectsRemoteControlCommands(t *testing.T) {
	for _, query := range []string{"JSON example.com", "DUMP", "EXPORT", "PURGE"} {
		t.Run(strings.Fields(query)[0], func(t *testing.T) {
			conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345})
			handleSocketmapConnection(conn, bufio.NewReader(bytes.NewReader(netstring.Marshal(query))))
			if !bytes.Equal(conn.output.Bytes(), NS_PERM) {
				t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_PERM)
			}
		})
	}
}

func TestSocketmapLimitsMatchPostfixWithGrace(t *testing.T) {
	if SOCKETMAP_MAX_QUERY_BYTES != 10_000 {
		t.Fatalf("maximum query payload = %d, want 10000", SOCKETMAP_MAX_QUERY_BYTES)
	}
	if SOCKETMAP_MAX_REPLY_BYTES != 100_000 {
		t.Fatalf("maximum reply payload = %d, want 100000", SOCKETMAP_MAX_REPLY_BYTES)
	}
	if SOCKETMAP_IO_TIMEOUT != 102*time.Second {
		t.Fatalf("socketmap I/O timeout = %s, want 102s", SOCKETMAP_IO_TIMEOUT)
	}
}

func TestHandleConnectionAppliesActiveSocketmapDeadlinesWithoutIdleTimeout(t *testing.T) {
	conn := newSecurityTestConn(netstring.Marshal("QUERY invalid_domain"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	conn.maxRead = 1
	handleConnection(conn)

	if len(conn.readDeadlinesAtRead) < 3 {
		t.Fatalf("connection reads = %d, want at least 3", len(conn.readDeadlinesAtRead))
	}
	if !conn.readDeadlinesAtRead[0].IsZero() {
		t.Fatal("expected no read deadline while waiting for initial activity")
	}
	if conn.readDeadlinesAtRead[1].IsZero() {
		t.Fatal("expected an active request read deadline after initial activity")
	}
	readTimeout := time.Until(conn.readDeadlinesAtRead[1])
	if readTimeout < SOCKETMAP_IO_TIMEOUT-time.Second || readTimeout > SOCKETMAP_IO_TIMEOUT {
		t.Fatalf("socketmap read timeout = %s, want approximately %s", readTimeout, SOCKETMAP_IO_TIMEOUT)
	}
	if !conn.readDeadlinesAtRead[len(conn.readDeadlinesAtRead)-1].IsZero() {
		t.Fatal("expected no read deadline while waiting for the next request")
	}
	if len(conn.writeDeadlines) == 0 {
		t.Fatal("expected a socketmap write deadline")
	}
	writeTimeout := time.Until(conn.writeDeadlines[0])
	if writeTimeout < SOCKETMAP_IO_TIMEOUT-time.Second || writeTimeout > SOCKETMAP_IO_TIMEOUT {
		t.Fatalf("socketmap write timeout = %s, want approximately %s", writeTimeout, SOCKETMAP_IO_TIMEOUT)
	}
	if !bytes.Equal(conn.output.Bytes(), NS_NOTFOUND) {
		t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_NOTFOUND)
	}
}

func TestHandleSocketmapProcessesPersistentQueries(t *testing.T) {
	input := append(netstring.Marshal("QUERY invalid_one"), netstring.Marshal("QUERY invalid_two")...)
	conn := newSecurityTestConn(input, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	handleConnection(conn)

	want := append(append([]byte(nil), NS_NOTFOUND...), NS_NOTFOUND...)
	if !bytes.Equal(conn.output.Bytes(), want) {
		t.Fatalf("responses = %q, want %q", conn.output.Bytes(), want)
	}
}

func TestHandleSocketmapEnforcesPostfixQueryBoundary(t *testing.T) {
	for _, test := range []struct {
		name       string
		payloadLen int
		wantReply  []byte
	}{
		{name: "boundary", payloadLen: SOCKETMAP_MAX_QUERY_BYTES, wantReply: NS_PERM},
		{name: "one byte over", payloadLen: SOCKETMAP_MAX_QUERY_BYTES + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := strings.Repeat("X", test.payloadLen)
			conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
			handleSocketmapConnection(conn, bufio.NewReader(bytes.NewReader(netstring.Marshal(payload))))
			if !bytes.Equal(conn.output.Bytes(), test.wantReply) {
				t.Fatalf("response = %q, want %q", conn.output.Bytes(), test.wantReply)
			}
		})
	}
}

func TestWriteSocketmapReplyEnforcesPostfixReplyBoundary(t *testing.T) {
	for _, test := range []struct {
		name       string
		payloadLen int
		wantPrefix string
	}{
		{name: "boundary", payloadLen: SOCKETMAP_MAX_REPLY_BYTES, wantPrefix: "100000:"},
		{name: "one byte over", payloadLen: SOCKETMAP_MAX_REPLY_BYTES + 1, wantPrefix: string(NS_TEMP)},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
			writeSocketmapReply(conn, strings.Repeat("X", test.payloadLen))
			if !strings.HasPrefix(conn.output.String(), test.wantPrefix) {
				t.Fatalf("response prefix = %q, want %q", conn.output.String()[:min(16, conn.output.Len())], test.wantPrefix)
			}
		})
	}
}

func TestIsLocalControlConnection(t *testing.T) {
	tests := []struct {
		name   string
		remote net.Addr
		want   bool
	}{
		{name: "IPv4 loopback", remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, want: true},
		{name: "IPv6 loopback", remote: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1}, want: true},
		{name: "remote TCP", remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, want: false},
		{name: "Unix socket", remote: &net.UnixAddr{Name: "/run/postfix-tlspol/client.sock", Net: "unix"}, want: true},
		{name: "unknown", remote: securityTestAddr{network: "pipe", address: "pipe"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newSecurityTestConn(nil, tt.remote)
			if got := isLocalControlConnection(conn); got != tt.want {
				t.Fatalf("isLocalControlConnection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloseActiveConnections(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	activeConnections.Store(server, struct{}{})
	defer activeConnections.Delete(server)

	closeActiveConnections()
	done := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected peer close after shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("active connection was not closed")
	}
}

var _ net.Conn = (*securityTestConn)(nil)
var _ io.Reader = (*securityTestConn)(nil)
