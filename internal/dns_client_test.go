/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// Exercise fresh shared clients, not the already-initialized package client.
// Regressions: https://codeberg.org/miekg/dns/issues/1189 and /issues/1162.
func TestDNSClientConcurrentFirstUse(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address := startDNSClientTestServer(t, network, dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
				reply := new(dns.Msg)
				setDNSReply(reply, r)
				if err := writeDNSMsg(w, reply); err != nil {
					t.Errorf("write reply: %v", err)
				}
			}))

			for range 4 {
				c := newDNSClientForTest()
				start := make(chan struct{})
				var ready, done sync.WaitGroup
				const queries = 16
				ready.Add(queries)
				done.Add(queries)
				for i := range queries {
					go func() {
						defer done.Done()
						request := newDNSQuery("first-use.test", dns.TypeA, false)
						request.ID = uint16(i + 1)
						ready.Done()
						<-start
						reply, _, err := c.Exchange(t.Context(), request, network, address)
						if err != nil {
							t.Errorf("query %d: %v", request.ID, err)
							return
						}
						if reply == nil || reply.ID != request.ID {
							t.Errorf("query %d received the wrong reply: %+v", request.ID, reply)
						}
					}()
				}
				ready.Wait()
				close(start)
				done.Wait()
				assertDNSClientIdle(t, c)
			}
		})
	}
}

func TestDNSClientRejectsMismatchedID(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address := startDNSClientTestServer(t, network, dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
				reply := new(dns.Msg)
				setDNSReply(reply, r)
				reply.ID++
				if err := writeDNSMsg(w, reply); err != nil {
					t.Errorf("write reply: %v", err)
				}
			}))
			c := newDNSClientForTest()
			request := newDNSQuery("wrong-id.test", dns.TypeA, false)
			request.ID = 1234
			if _, _, err := c.Exchange(t.Context(), request, network, address); !errors.Is(err, dns.ErrID) {
				t.Errorf("mismatched reply error = %v, want dns.ErrID", err)
			}
			assertDNSClientIdle(t, c)
		})
	}
}

func TestDNSClientIndependentExchanges(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, wrongID := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrong-id=%t", network, wrongID), func(t *testing.T) {
				pending := make(chan struct{})
				release := make(chan struct{})
				address := startDNSClientTestServer(t, network, dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
					reply := new(dns.Msg)
					setDNSReply(reply, r)
					switch dnsQuestion(r).Name {
					case "slow.test.":
						close(pending)
						<-release
					case "fast.test.":
						if wrongID {
							reply.ID++
						}
					}
					if err := writeDNSMsg(w, reply); err != nil {
						t.Errorf("write reply: %v", err)
					}
				}))
				c := newDNSClientForTest()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				// Initialize before overlapping calls to isolate I/O and cleanup bugs
				// from the first-use race covered above.
				if _, _, err := c.Exchange(ctx, newDNSQuery("warmup.test", dns.TypeA, false), network, address); err != nil {
					t.Fatal(err)
				}
				slowDone := make(chan error, 1)
				go func() {
					request := newDNSQuery("slow.test", dns.TypeA, false)
					request.ID = 1234
					reply, _, err := c.Exchange(ctx, request, network, address)
					if err == nil && (reply == nil || reply.ID != request.ID) {
						err = fmt.Errorf("wrong slow reply: %+v", reply)
					}
					slowDone <- err
				}()
				defer func() {
					close(release)
					if err := <-slowDone; err != nil {
						t.Errorf("independent slow query failed: %v", err)
					}
					assertDNSClientIdle(t, c)
				}()
				select {
				case <-pending:
				case <-ctx.Done():
					t.Fatal("slow query never reached the server")
				}

				// This must finish while the other connection is still waiting for
				// its reply, without clearing that connection's in-flight request.
				request := newDNSQuery("fast.test", dns.TypeA, false)
				request.ID = 5678
				reply, _, err := c.Exchange(ctx, request, network, address)
				if wrongID {
					if !errors.Is(err, dns.ErrID) {
						t.Errorf("mismatched reply error = %v, want dns.ErrID", err)
					}
				} else if err != nil || reply == nil || reply.ID != request.ID {
					t.Errorf("independent fast query failed: reply=%+v, error=%v", reply, err)
				}
			})
		}
	}
}

func newDNSClientForTest() *dns.Client {
	// Match production's client literal: NewClient would hide lazy-init races.
	return &dns.Client{Transport: &dns.Transport{
		Dialer:       &net.Dialer{Timeout: 2 * time.Second},
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}}
}

func assertDNSClientIdle(t *testing.T, c *dns.Client) {
	t.Helper()
	// v0.6.119 has no in-flight tracking or Err method. Check newer clients
	// through their public API so these regressions also run on that baseline.
	if state, ok := any(c).(interface{ Err() error }); ok {
		if err := state.Err(); err != nil {
			t.Errorf("completed exchange left in-flight requests: %v", err)
		}
	}
}

func startDNSClientTestServer(t *testing.T, network string, handler dns.Handler) string {
	t.Helper()
	server := &dns.Server{Handler: handler}
	var address string
	if network == "udp" {
		conn, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn = conn
		address = conn.LocalAddr().String()
	} else {
		listener, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
		address = listener.Addr().String()
	}
	startTestDNSServer(t, server)
	return address
}
