/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"net"
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
			msg.AuthenticatedData = false
			msg.Answer = append(msg.Answer, dnsA(q.Name, 300, "192.0.2.10"))
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
	if _, _, err := checkDaneOnce(ctx, "edns.test", packetConn.LocalAddr().String()); err != nil {
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

func TestExchangeDNSRetriesTruncatedUDPOverTCP(t *testing.T) {
	var udpQueries atomic.Int32
	var tcpQueries atomic.Int32

	udpHandler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			t.Errorf("unpack DNS request: %v", err)
			return
		}
		udpQueries.Add(1)
		if opt := dnsEDNS0(r); opt == nil || opt.UDPSize() != DNS_UDP_PAYLOAD_SIZE {
			t.Errorf("expected UDP query EDNS0 size %d, got %#v", DNS_UDP_PAYLOAD_SIZE, opt)
		}
		msg := new(dns.Msg)
		setDNSReply(msg, r)
		msg.Truncated = true
		_ = writeDNSMsg(w, msg)
	})

	tcpHandler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		tcpQueries.Add(1)
		msg := new(dns.Msg)
		setDNSReply(msg, r)
		msg.Answer = append(msg.Answer, dnsTXT(dnsQuestion(r).Name, 300, "v=STSv1; id=tcp1;"))
		_ = writeDNSMsg(w, msg)
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
	r, err := exchangeDNS(ctx, newDNSQuery("truncated.test", dns.TypeTXT, false), packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("expected TCP retry after truncated UDP response: %v", err)
	}
	if r.Truncated {
		t.Fatal("expected TCP retry response not to be truncated")
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected answer from TCP retry, got %d answers", len(r.Answer))
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("expected one UDP query and one TCP retry, got udp=%d tcp=%d", udpQueries.Load(), tcpQueries.Load())
	}
}
