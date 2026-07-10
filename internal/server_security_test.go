/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
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
	input          *bytes.Reader
	output         bytes.Buffer
	remote         net.Addr
	readDeadlines  int
	writeDeadlines int
}

func newSecurityTestConn(input []byte, remote net.Addr) *securityTestConn {
	return &securityTestConn{input: bytes.NewReader(input), remote: remote}
}

func (c *securityTestConn) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *securityTestConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *securityTestConn) Close() error                { return nil }
func (c *securityTestConn) LocalAddr() net.Addr {
	return securityTestAddr{network: "tcp", address: "127.0.0.1:8642"}
}
func (c *securityTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *securityTestConn) SetDeadline(time.Time) error      { return nil }
func (c *securityTestConn) SetReadDeadline(time.Time) error  { c.readDeadlines++; return nil }
func (c *securityTestConn) SetWriteDeadline(time.Time) error { c.writeDeadlines++; return nil }

func TestHandleSocketmapRejectsInvalidJSONDomain(t *testing.T) {
	conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	handleSocketmapConnection(conn, bytes.NewReader(netstring.Marshal("JSON bad@domain")))

	if !bytes.Equal(conn.output.Bytes(), NS_NOTFOUND) {
		t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_NOTFOUND)
	}
}

func TestHandleSocketmapRejectsRemoteControlCommands(t *testing.T) {
	for _, query := range []string{"JSON example.com", "DUMP", "EXPORT", "PURGE"} {
		t.Run(strings.Fields(query)[0], func(t *testing.T) {
			conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345})
			handleSocketmapConnection(conn, bytes.NewReader(netstring.Marshal(query)))
			if !bytes.Equal(conn.output.Bytes(), NS_PERM) {
				t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_PERM)
			}
		})
	}
}

func TestHandleConnectionAppliesSocketmapDeadlines(t *testing.T) {
	conn := newSecurityTestConn(netstring.Marshal("QUERY invalid_domain"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	handleConnection(conn)

	if conn.readDeadlines < 2 {
		t.Fatalf("read deadline calls = %d, want at least 2", conn.readDeadlines)
	}
	if conn.writeDeadlines == 0 {
		t.Fatal("expected a socketmap write deadline")
	}
	if !bytes.Equal(conn.output.Bytes(), NS_NOTFOUND) {
		t.Fatalf("response = %q, want %q", conn.output.Bytes(), NS_NOTFOUND)
	}
}

func TestHandleSocketmapRejectsOversizedRequest(t *testing.T) {
	payload := "QUERY " + strings.Repeat("a", SOCKETMAP_MAX_REQUEST_BYTES)
	conn := newSecurityTestConn(nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	handleSocketmapConnection(conn, bytes.NewReader(netstring.Marshal(payload)))
	if conn.output.Len() != 0 {
		t.Fatalf("unexpected response to oversized request: %q", conn.output.Bytes())
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
