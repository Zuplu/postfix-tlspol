/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func init() {
	address := "8.8.8.8:53"
	config = Config{
		Server: ServerConfig{},
		Dns: DnsConfig{
			Address: &address,
		},
	}
}

func TestDane(t *testing.T) {
	t.Parallel()
	domains := []string{"ietf.org", "ripe.net", "nlnet.nl", "denic.de", "bund.de", "zuplu.com", "mailbox.org", "protonmail.com"}

	passedOnce := false
	for _, domain := range domains {
		func(domain string) {
			t.Run(fmt.Sprintf("Domain=%q", domain), func(t *testing.T) {
				if passedOnce && testing.Short() {
					t.SkipNow()
					return
				}
				policy, _ := checkDane(bgCtx, domain, true)
				if policy != "dane-only" {
					t.Skipf("Expected DANE for %q, but not detected", domain)
				} else if !passedOnce {
					passedOnce = true
				}
			})
		}(domain)
	}
	if !passedOnce {
		t.Error("All tests failed.")
	}
}

func TestCheckDaneOnceReturnsErrorWhenMxAddressLookupTimesOut(t *testing.T) {
	originalTimeout := client.Timeout
	client.Timeout = 50 * time.Millisecond
	t.Cleanup(func() { client.Timeout = originalTimeout })

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			return
		}

		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeMX:
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.AuthenticatedData = true
			msg.Answer = []dns.RR{&dns.MX{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Mx:  "mx.example.test.",
			}}
			_ = w.WriteMsg(msg)
		case dns.TypeA, dns.TypeAAAA:
			// Simulate a temporary DNS transport failure for address records.
			return
		default:
			msg := new(dns.Msg)
			msg.SetRcode(r, dns.RcodeNameError)
			msg.AuthenticatedData = true
			_ = w.WriteMsg(msg)
		}
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	packetConn, err := net.ListenPacket("udp", server.Addr)
	if err != nil {
		t.Fatalf("failed to listen for test DNS server: %v", err)
	}
	server.PacketConn = packetConn
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policy, ttl, err := checkDaneOnce(ctx, "example.test", packetConn.LocalAddr().String())
	if err == nil {
		t.Fatalf("expected temporary MX address lookup failure to be returned as an error, got policy=%q ttl=%d", policy, ttl)
	}
}

func TestDaneMxAddressLookupFailureIsTemporary(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		switch {
		case q.Name == "victim.test." && q.Qtype == dns.TypeMX:
			msg.Answer = append(msg.Answer, &dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx.victim.test."})
		case q.Name == "mx.victim.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeServerFailure
		case strings.HasPrefix(q.Name, "_25._tcp.mx.victim.test.") && q.Qtype == dns.TypeTLSA:
			msg.Answer = append(msg.Answer, &dns.TLSA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300}, Usage: 3, Selector: 1, MatchingType: 1, Certificate: strings.Repeat("a", 64)})
		default:
			msg.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(msg)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	packetConn, err := net.ListenPacket("udp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	server.PacketConn = packetConn
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	policy, _, err := checkDaneOnce(context.Background(), "victim.test", packetConn.LocalAddr().String())
	if err == nil {
		t.Fatalf("expected MX address lookup failure to be treated as temporary error, got policy %q", policy)
	}
}

func TestDaneUnauthenticatedSuccessfulMxAddressLookupIsNotTemporary(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)

		q := r.Question[0]
		switch {
		case q.Name == "unsigned.test." && q.Qtype == dns.TypeMX:
			msg.AuthenticatedData = false
			msg.Answer = append(msg.Answer, &dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx.unsigned.test."})
		case q.Name == "mx.unsigned.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeSuccess
			if q.Qtype == dns.TypeA {
				msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.10")})
			}
		default:
			msg.AuthenticatedData = true
			msg.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(msg)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	packetConn, err := net.ListenPacket("udp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	server.PacketConn = packetConn
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	policy, ttl, err := checkDaneOnce(context.Background(), "unsigned.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected unsigned successful MX address lookup to be treated as no DANE, got error %v", err)
	}
	if policy != "" || ttl != 0 {
		t.Fatalf("expected no DANE policy for unsigned MX address lookup, got policy=%q ttl=%d", policy, ttl)
	}
}
