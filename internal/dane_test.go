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
	"sync"
	"sync/atomic"
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
	requireLiveNetworkTests(t)
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

func BenchmarkGetDanePolicy(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		results := make(chan ResultWithTTL, 1)
		results <- ResultWithTTL{Result: "dane-only", TTL: 120}
		if _, _, err := getDanePolicy(context.Background(), func() {}, 300, false, 1, results); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGetDanePolicyRejectsIncompleteResults(t *testing.T) {
	t.Parallel()

	results := make(chan ResultWithTTL)
	close(results)
	if _, _, err := getDanePolicy(context.Background(), func() {}, 300, false, 1, results); err == nil {
		t.Fatal("expected incomplete TLSA lookup results to fail")
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

func TestGetMxRecordsDeduplicatesAndLimitsAddressLookups(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var slowInFlight atomic.Int32
	var addressQueries atomic.Int32
	var unexpectedAAAA atomic.Int32
	var drainedBeforeBatch atomic.Bool
	var seenMu sync.Mutex
	seenQueries := map[string]int{}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			return
		}

		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		switch {
		case q.Name == "many.test." && q.Qtype == dns.TypeMX:
			msg.Answer = []dns.RR{
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx0.many.test."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 20, Mx: "mx1.many.test."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 30, Mx: "mx2.many.test."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 40, Mx: "mx3.many.test."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 123}, Preference: 50, Mx: "MX0.MANY.TEST."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 60, Mx: "mx4.many.test."},
				&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 70, Mx: "mx5.many.test."},
			}
		case strings.HasSuffix(q.Name, ".many.test.") && q.Qtype == dns.TypeA:
			addressQueries.Add(1)
			current := inFlight.Add(1)
			updateMaxInt32(&maxInFlight, current)

			name := strings.ToLower(q.Name)
			seenMu.Lock()
			seenQueries[name]++
			seenMu.Unlock()

			slow := false
			switch name {
			case "mx0.many.test.", "mx1.many.test.", "mx2.many.test.":
				slow = true
				slowInFlight.Add(1)
				time.Sleep(200 * time.Millisecond)
			case "mx4.many.test.":
				if slowInFlight.Load() != 0 {
					drainedBeforeBatch.Store(true)
				}
				time.Sleep(10 * time.Millisecond)
			default:
				time.Sleep(10 * time.Millisecond)
			}
			if slow {
				slowInFlight.Add(-1)
			}
			inFlight.Add(-1)

			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.10"),
			})
		case strings.HasSuffix(q.Name, ".many.test.") && q.Qtype == dns.TypeAAAA:
			unexpectedAAAA.Add(1)
			msg.Rcode = dns.RcodeNameError
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mxRecords, ttl, err, incompl := getMxRecords(ctx, "many.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected MX records to validate without error: %v", err)
	}
	if incompl {
		t.Fatal("expected authenticated MX and address lookups to be complete")
	}
	if len(mxRecords) != 6 {
		t.Fatalf("expected duplicate MX hosts to be collapsed to 6 records, got %d: %v", len(mxRecords), mxRecords)
	}
	if ttl != 123 {
		t.Fatalf("expected duplicate MX host to retain minimum TTL 123, got %d", ttl)
	}
	if addressQueries.Load() != 6 {
		t.Fatalf("expected one address query per unique MX host, got %d", addressQueries.Load())
	}
	if unexpectedAAAA.Load() != 0 {
		t.Fatalf("expected signed A responses to short-circuit AAAA lookups, got %d AAAA queries", unexpectedAAAA.Load())
	}
	if maxInFlight.Load() != DANE_MX_LOOKUP_CONCURRENCY {
		t.Fatalf("expected exactly %d concurrent address lookups, got %d", DANE_MX_LOOKUP_CONCURRENCY, maxInFlight.Load())
	}
	if !drainedBeforeBatch.Load() {
		t.Fatal("expected the next MX lookup to start as soon as a worker finished")
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if seenQueries["mx0.many.test."] != 1 {
		t.Fatalf("expected duplicate mx0 host to be queried once, got %d", seenQueries["mx0.many.test."])
	}
}

func TestCheckTlsaRecordsLimitsConcurrentLookups(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var slowInFlight atomic.Int32
	var drainedBeforeBatch atomic.Bool

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			return
		}

		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		if q.Qtype == dns.TypeTLSA && strings.HasSuffix(q.Name, ".tlsa.test.") {
			current := inFlight.Add(1)
			updateMaxInt32(&maxInFlight, current)

			slow := false
			switch q.Name {
			case "_25._tcp.mx0.tlsa.test.", "_25._tcp.mx1.tlsa.test.", "_25._tcp.mx2.tlsa.test.":
				slow = true
				slowInFlight.Add(1)
				time.Sleep(200 * time.Millisecond)
			case "_25._tcp.mx4.tlsa.test.":
				if slowInFlight.Load() != 0 {
					drainedBeforeBatch.Store(true)
				}
				time.Sleep(10 * time.Millisecond)
			default:
				time.Sleep(10 * time.Millisecond)
			}
			if slow {
				slowInFlight.Add(-1)
			}
			inFlight.Add(-1)
			msg.Rcode = dns.RcodeNameError
		} else {
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := checkTlsaRecords(ctx, []string{
		"mx0.tlsa.test.",
		"mx1.tlsa.test.",
		"mx2.tlsa.test.",
		"mx3.tlsa.test.",
		"mx4.tlsa.test.",
		"mx5.tlsa.test.",
	}, packetConn.LocalAddr().String())

	count := 0
	for result := range results {
		if result.Err != nil {
			t.Fatalf("expected TLSA lookup to complete without error: %v", result.Err)
		}
		count++
	}
	if count != 6 {
		t.Fatalf("expected 6 TLSA results, got %d", count)
	}
	if maxInFlight.Load() != DANE_MX_LOOKUP_CONCURRENCY {
		t.Fatalf("expected exactly %d concurrent TLSA lookups, got %d", DANE_MX_LOOKUP_CONCURRENCY, maxInFlight.Load())
	}
	if !drainedBeforeBatch.Load() {
		t.Fatal("expected the next TLSA lookup to start as soon as a worker finished")
	}
}

func updateMaxInt32(maxValue *atomic.Int32, value int32) {
	for {
		old := maxValue.Load()
		if value <= old || maxValue.CompareAndSwap(old, value) {
			return
		}
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

func TestDaneUnauthenticatedNxdomainForOneMxDoesNotBlockOthers(t *testing.T) {
	var validTlsaQueries atomic.Int32
	var unreachableTlsaQueries atomic.Int32

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)

		q := r.Question[0]
		switch {
		case q.Name == "mixed.test." && q.Qtype == dns.TypeMX:
			msg.AuthenticatedData = false
			msg.Answer = append(msg.Answer,
				&dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 10,
					Mx:         "missing.mixed.test.",
				},
				&dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 20,
					Mx:         "mx.reachable.test.",
				},
			)
		case q.Name == "missing.mixed.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeNameError
		case q.Name == "mx.reachable.test." && q.Qtype == dns.TypeA:
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.10"),
			})
		case q.Name == "_25._tcp.mx.reachable.test." && q.Qtype == dns.TypeTLSA:
			validTlsaQueries.Add(1)
			msg.AuthenticatedData = true
			msg.Rcode = dns.RcodeNameError
		case q.Name == "_25._tcp.missing.mixed.test." && q.Qtype == dns.TypeTLSA:
			unreachableTlsaQueries.Add(1)
			msg.AuthenticatedData = true
			msg.Rcode = dns.RcodeNameError
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

	policy, ttl, err := checkDaneOnce(context.Background(), "mixed.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected an unsigned NXDOMAIN MX target not to block reachable MX hosts, got %v", err)
	}
	if policy != "" || ttl != 0 {
		t.Fatalf("expected no DANE policy for the unsigned mixed MX set, got policy=%q ttl=%d", policy, ttl)
	}
	if got := validTlsaQueries.Load(); got != 1 {
		t.Fatalf("expected one TLSA lookup for the reachable MX, got %d", got)
	}
	if got := unreachableTlsaQueries.Load(); got != 0 {
		t.Fatalf("expected no TLSA lookup for the unreachable MX, got %d", got)
	}
}

func TestDaneUnauthenticatedNxdomainPreventsMandatoryDane(t *testing.T) {
	var validTlsaQueries atomic.Int32
	var unreachableTlsaQueries atomic.Int32

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		switch {
		case q.Name == "mixed-secure.test." && q.Qtype == dns.TypeMX:
			msg.Answer = append(msg.Answer,
				&dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 10,
					Mx:         "missing.unsigned.test.",
				},
				&dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 20,
					Mx:         "mx.secure.test.",
				},
			)
		case q.Name == "missing.unsigned.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeNameError
		case q.Name == "mx.secure.test." && q.Qtype == dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.20"),
			})
		case q.Name == "_25._tcp.mx.secure.test." && q.Qtype == dns.TypeTLSA:
			validTlsaQueries.Add(1)
			msg.Answer = append(msg.Answer, &dns.TLSA{
				Hdr:          dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  strings.Repeat("a", 64),
			})
		case q.Name == "_25._tcp.missing.unsigned.test." && q.Qtype == dns.TypeTLSA:
			unreachableTlsaQueries.Add(1)
			msg.Rcode = dns.RcodeNameError
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

	policy, ttl, err := checkDaneOnce(context.Background(), "mixed-secure.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected an unsigned NXDOMAIN MX target not to fail DANE discovery, got %v", err)
	}
	if policy != "dane" || ttl != 300 {
		t.Fatalf("expected opportunistic DANE with TTL 300, got policy=%q ttl=%d", policy, ttl)
	}
	if got := validTlsaQueries.Load(); got != 1 {
		t.Fatalf("expected one TLSA lookup for the reachable MX, got %d", got)
	}
	if got := unreachableTlsaQueries.Load(); got != 0 {
		t.Fatalf("expected no TLSA lookup for the unreachable MX, got %d", got)
	}
}

func TestCheckMxAddressClassifiesCompletedAndTemporaryResponses(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)

		q := r.Question[0]
		switch q.Name {
		case "secure.test.":
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.30"),
			})
		case "unsigned.test.":
			msg.AuthenticatedData = false
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.31"),
			})
		case "secure-nxdomain.test.":
			msg.AuthenticatedData = true
			msg.Rcode = dns.RcodeNameError
		case "unsigned-nxdomain.test.":
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeNameError
		case "servfail.test.":
			msg.AuthenticatedData = false
			msg.Rcode = dns.RcodeServerFailure
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

	tests := []struct {
		name   string
		host   string
		status uint8
	}{
		{name: "authenticated address", host: "secure.test", status: MxOk},
		{name: "unauthenticated address", host: "unsigned.test", status: MxNotSec},
		{name: "authenticated nxdomain", host: "secure-nxdomain.test", status: MxNotSec},
		{name: "unauthenticated nxdomain", host: "unsigned-nxdomain.test", status: MxNotSec},
		{name: "servfail", host: "servfail.test", status: MxFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkMxAddress(context.Background(), tt.host, packetConn.LocalAddr().String(), dns.TypeA); got != tt.status {
				t.Fatalf("checkMxAddress(%q) = %d, want %d", tt.host, got, tt.status)
			}
		})
	}
}

func TestDaneAuthenticatedAddressNodataSkipsTlsa(t *testing.T) {
	var tlsaQueries atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		switch {
		case q.Name == "nodata.test." && q.Qtype == dns.TypeMX:
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "mx.nodata.test.",
			})
		case q.Name == "mx.nodata.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			// Authenticated NODATA: the host has no address and is not reachable.
		case q.Name == "_25._tcp.mx.nodata.test." && q.Qtype == dns.TypeTLSA:
			tlsaQueries.Add(1)
			msg.Answer = append(msg.Answer, &dns.TLSA{
				Hdr:          dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  strings.Repeat("a", 64),
			})
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

	policy, ttl, err := checkDaneOnce(context.Background(), "nodata.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected authenticated NODATA to be treated as unreachable, got %v", err)
	}
	if policy != "" || ttl != 0 {
		t.Fatalf("expected no DANE policy for unreachable MX, got policy=%q ttl=%d", policy, ttl)
	}
	if got := tlsaQueries.Load(); got != 0 {
		t.Fatalf("expected TLSA lookup to be skipped, got %d queries", got)
	}
}

func TestDaneAuthenticatedMxNodataUsesImplicitMx(t *testing.T) {
	var addressQueries atomic.Int32
	var tlsaQueries atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true

		q := r.Question[0]
		switch {
		case q.Name == "implicit.test." && q.Qtype == dns.TypeMX:
			msg.Ns = append(msg.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 240},
				Ns:      "ns.test.",
				Mbox:    "hostmaster.test.",
				Minttl:  120,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
			})
		case q.Name == "implicit.test." && q.Qtype == dns.TypeA:
			addressQueries.Add(1)
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.20"),
			})
		case q.Name == "_25._tcp.implicit.test." && q.Qtype == dns.TypeTLSA:
			tlsaQueries.Add(1)
			msg.Answer = append(msg.Answer, &dns.TLSA{
				Hdr:          dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 600},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  strings.Repeat("a", 64),
			})
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

	policy, ttl, err := checkDaneOnce(context.Background(), "implicit.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("implicit MX lookup failed: %v", err)
	}
	if policy != "dane-only" || ttl != 120 {
		t.Fatalf("expected implicit MX DANE policy with negative MX TTL, got policy=%q ttl=%d", policy, ttl)
	}
	if addressQueries.Load() != 1 || tlsaQueries.Load() != 1 {
		t.Fatalf("expected address and TLSA lookup, got address=%d tlsa=%d", addressQueries.Load(), tlsaQueries.Load())
	}
}

func TestDaneDoesNotUseImplicitMxForNxdomainOrNullMx(t *testing.T) {
	tests := []struct {
		name   string
		rcode  int
		nullMx bool
	}{
		{name: "nxdomain", rcode: dns.RcodeNameError},
		{name: "null mx", rcode: dns.RcodeSuccess, nullMx: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var followupQueries atomic.Int32
			mux := dns.NewServeMux()
			mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.AuthenticatedData = true
				q := r.Question[0]
				if q.Name == "nomail.test." && q.Qtype == dns.TypeMX {
					msg.Rcode = tt.rcode
					if tt.nullMx {
						msg.Answer = append(msg.Answer, &dns.MX{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
							Mx:  ".",
						})
					}
				} else {
					followupQueries.Add(1)
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

			policy, ttl, err := checkDaneOnce(context.Background(), "nomail.test", packetConn.LocalAddr().String())
			if err != nil || policy != "" || ttl != 0 {
				t.Fatalf("expected no DANE policy, got policy=%q ttl=%d err=%v", policy, ttl, err)
			}
			if followupQueries.Load() != 0 {
				t.Fatalf("expected no address or TLSA lookup, got %d follow-up queries", followupQueries.Load())
			}
		})
	}
}

func TestNegativeResponseTTLUsesSoaMinimum(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = append(msg.Ns,
		&dns.SOA{Hdr: dns.RR_Header{Ttl: 600}, Minttl: 120},
		&dns.SOA{Hdr: dns.RR_Header{Ttl: 90}, Minttl: 300},
	)
	if got := negativeResponseTTL(msg); got != 90 {
		t.Fatalf("negative response TTL = %d, want 90", got)
	}
}

func TestDaneFollowsSecureCnameDuringMxLookup(t *testing.T) {
	var targetMxQueries atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.AuthenticatedData = true
		q := r.Question[0]
		switch {
		case q.Name == "alias.test." && q.Qtype == dns.TypeMX:
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 100},
				Target: "target.test.",
			})
		case q.Name == "target.test." && q.Qtype == dns.TypeMX:
			targetMxQueries.Add(1)
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "mx.target.test.",
			})
		case q.Name == "mx.target.test." && q.Qtype == dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.30"),
			})
		case q.Name == "_25._tcp.mx.target.test." && q.Qtype == dns.TypeTLSA:
			msg.Answer = append(msg.Answer, &dns.TLSA{
				Hdr:          dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 600},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  strings.Repeat("b", 64),
			})
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

	policy, ttl, err := checkDaneOnce(context.Background(), "alias.test", packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("CNAME MX lookup failed: %v", err)
	}
	if policy != "dane-only" || ttl != 100 {
		t.Fatalf("expected CNAME-limited DANE policy, got policy=%q ttl=%d", policy, ttl)
	}
	if targetMxQueries.Load() != 1 {
		t.Fatalf("expected one target MX query, got %d", targetMxQueries.Load())
	}
}
