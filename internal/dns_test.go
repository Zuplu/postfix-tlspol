/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

type observedDNSQuery struct {
	qtype   uint16
	udpSize uint16
	do      bool
}

func BenchmarkNewDNSQuery(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := newDNSQuery("_25._tcp.mx.example.test", dns.TypeTLSA, true)
		if m == nil {
			b.Fatal("newDNSQuery returned nil")
		}
	}
}

func TestPolicyDNSQueriesUseHardenedEDNS0Size(t *testing.T) {
	observed := make(chan observedDNSQuery, 8)
	handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			t.Errorf("unpack DNS request: %v", err)
			return
		}
		if len(r.Question) == 0 {
			return
		}
		q := dnsQuestion(r)
		opt := dnsEDNS0(r)
		if opt == nil {
			t.Errorf("expected EDNS0 on %s query for %s", dns.TypeToString[q.Qtype], q.Name)
		} else {
			observed <- observedDNSQuery{qtype: q.Qtype, udpSize: opt.UDPSize(), do: opt.Do()}
		}

		msg := new(dns.Msg)
		setDNSReply(msg, r)
		switch q.Qtype {
		case dns.TypeMX:
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, dnsMX(q.Name, 300, 0, "mx.edns.test."))
		case dns.TypeA:
			msg.AuthenticatedData = true
		case dns.TypeAAAA:
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, dnsAAAA(q.Name, 300, "2001:db8::10"))
		case dns.TypeTLSA:
			msg.AuthenticatedData = true
			setDNSRcode(msg, r, dns.RcodeNameError)
		case dns.TypeTXT:
			msg.Answer = append(msg.Answer, dnsTXT(q.Name, 300, "v=STSv1; id=edns1;"))
		default:
			setDNSRcode(msg, r, dns.RcodeNameError)
		}
		_ = writeDNSMsg(w, msg)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: handler}
	packetConn, err := net.ListenPacket("udp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	server.PacketConn = packetConn
	shutdown := startTestDNSServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err, _ := getMxRecords(ctx, "edns.test", packetConn.LocalAddr().String()); err != nil {
		t.Fatalf("expected DANE MX path to complete: %v", err)
	}
	if _, err := checkDaneOnce(ctx, "edns.test", packetConn.LocalAddr().String()); err != nil {
		t.Fatalf("expected DANE TLSA path to complete: %v", err)
	}
	if ok, err := checkMtaStsRecord(ctx, "edns.test", packetConn.LocalAddr().String()); err != nil || !ok {
		t.Fatalf("expected MTA-STS TXT path to complete, ok=%v err=%v", ok, err)
	}
	shutdown()
	close(observed)

	seen := map[uint16]int{}
	for query := range observed {
		if query.udpSize != DNS_UDP_PAYLOAD_SIZE {
			t.Fatalf("expected EDNS0 UDP size %d for %s, got %d", DNS_UDP_PAYLOAD_SIZE, dns.TypeToString[query.qtype], query.udpSize)
		}
		if query.qtype == dns.TypeTXT {
			if query.do {
				t.Fatal("expected MTA-STS TXT query not to set DNSSEC OK bit")
			}
		} else if !query.do {
			t.Fatalf("expected %s query to set DNSSEC OK bit", dns.TypeToString[query.qtype])
		}
		seen[query.qtype]++
	}
	for _, qtype := range []uint16{dns.TypeMX, dns.TypeA, dns.TypeAAAA, dns.TypeTLSA, dns.TypeTXT} {
		if seen[qtype] == 0 {
			t.Fatalf("expected to observe %s query", dns.TypeToString[qtype])
		}
	}
}

func TestPolicyDNSQueriesRetryTruncatedUDPOverTCP(t *testing.T) {
	for _, tt := range []struct {
		name          string
		qtype         uint16
		authenticated bool
		wantPolicy    string
	}{
		{name: "MTA-STS", qtype: dns.TypeTXT},
		{name: "authenticated DANE", qtype: dns.TypeTLSA, authenticated: true, wantPolicy: "dane-only"},
		{name: "unauthenticated DANE", qtype: dns.TypeTLSA},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testPolicyDNSQueryRetriesTruncatedUDPOverTCP(t, tt.qtype, tt.authenticated, tt.wantPolicy)
		})
	}
}

func testPolicyDNSQueryRetriesTruncatedUDPOverTCP(t *testing.T, qtype uint16, authenticated bool, wantPolicy string) {
	t.Helper()
	var udpQueries atomic.Int32
	var tcpQueries atomic.Int32
	wantName := "_mta-sts.truncated.test."
	if qtype == dns.TypeTLSA {
		wantName = "_25._tcp.truncated.test."
	}

	checkQuery := func(r *dns.Msg) bool {
		if err := r.Unpack(); err != nil {
			t.Errorf("unpack DNS request: %v", err)
			return false
		}
		if len(r.Question) != 1 {
			t.Errorf("expected one question, got %d", len(r.Question))
			return false
		}
		if q := dnsQuestion(r); q.Name != wantName || q.Qtype != qtype {
			t.Errorf("expected %s question for %s, got %+v", dns.TypeToString[qtype], wantName, q)
		}
		if opt := dnsEDNS0(r); opt == nil || opt.UDPSize() != DNS_UDP_PAYLOAD_SIZE {
			t.Errorf("expected query EDNS0 size %d, got %#v", DNS_UDP_PAYLOAD_SIZE, opt)
		}
		if r.Security != (qtype == dns.TypeTLSA) || !r.RecursionDesired || r.CheckingDisabled {
			t.Errorf("unexpected query flags: DO=%v RD=%v CD=%v", r.Security, r.RecursionDesired, r.CheckingDisabled)
		}
		return true
	}

	udpHandler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		if !checkQuery(r) {
			return
		}
		msg := new(dns.Msg)
		setDNSReply(msg, r)
		msg.Truncated = true
		_ = writeDNSMsg(w, msg)
	})

	tcpHandler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		tcpQueries.Add(1)
		if !checkQuery(r) {
			return
		}
		msg := new(dns.Msg)
		setDNSReply(msg, r)
		msg.AuthenticatedData = authenticated
		if qtype == dns.TypeTLSA {
			msg.Answer = append(msg.Answer, dnsTLSA(wantName, 120, 3, 1, 1, strings.Repeat("ab", 32)))
		} else {
			msg.Answer = append(msg.Answer, dnsTXT(wantName, 300, "v=STSv1; id=", "tcp1;"))
		}
		if err := writeDNSMsg(w, msg); err != nil {
			t.Errorf("write TCP reply: %v", err)
		}
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", packetConn.LocalAddr().String())
	if err != nil {
		_ = packetConn.Close()
		t.Fatal(err)
	}

	udpServer := &dns.Server{PacketConn: packetConn, Handler: udpHandler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: tcpHandler}
	startTestDNSServer(t, udpServer)
	startTestDNSServer(t, tcpServer)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if qtype == dns.TypeTLSA {
		result := checkTlsa(ctx, "truncated.test", packetConn.LocalAddr().String())
		var wantTTL uint32
		if authenticated {
			wantTTL = 120
		}
		if result.Err != nil || result.Result != wantPolicy || result.TTL != wantTTL {
			t.Fatalf("expected policy %q with TTL %d after TCP retry, got %+v", wantPolicy, wantTTL, result)
		}
	} else {
		ok, err := checkMtaStsRecord(ctx, "truncated.test", packetConn.LocalAddr().String())
		if err != nil || !ok {
			t.Fatalf("expected split MTA-STS TXT record after TCP retry, got ok=%v err=%v", ok, err)
		}
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("expected one UDP query and one TCP retry, got udp=%d tcp=%d", udpQueries.Load(), tcpQueries.Load())
	}
}
