/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type observedDNSQuery struct {
	qtype   uint16
	udpSize uint16
	do      bool
}

func TestPolicyDNSQueriesUseHardenedEDNS0Size(t *testing.T) {
	if client.UDPSize != DNS_UDP_PAYLOAD_SIZE {
		t.Fatalf("expected DNS client UDPSize %d, got %d", DNS_UDP_PAYLOAD_SIZE, client.UDPSize)
	}

	observed := make(chan observedDNSQuery, 8)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			return
		}
		q := r.Question[0]
		opt := r.IsEdns0()
		if opt == nil {
			t.Errorf("expected EDNS0 on %s query for %s", dns.TypeToString[q.Qtype], q.Name)
		} else {
			observed <- observedDNSQuery{qtype: q.Qtype, udpSize: opt.UDPSize(), do: opt.Do()}
		}

		msg := new(dns.Msg)
		msg.SetReply(r)
		switch q.Qtype {
		case dns.TypeMX:
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Mx:  "mx.edns.test.",
			})
		case dns.TypeA:
			msg.AuthenticatedData = false
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.10"),
			})
		case dns.TypeAAAA:
			msg.AuthenticatedData = true
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::10"),
			})
		case dns.TypeTLSA:
			msg.AuthenticatedData = true
			msg.SetRcode(r, dns.RcodeNameError)
		case dns.TypeTXT:
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"v=STSv1; id=edns1;"},
			})
		default:
			msg.SetRcode(r, dns.RcodeNameError)
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
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() { _ = server.Shutdown() })
	}
	t.Cleanup(shutdown)

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

	udpMux := dns.NewServeMux()
	udpMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		if opt := r.IsEdns0(); opt == nil || opt.UDPSize() != DNS_UDP_PAYLOAD_SIZE {
			t.Errorf("expected UDP query EDNS0 size %d, got %#v", DNS_UDP_PAYLOAD_SIZE, opt)
		}
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Truncated = true
		_ = w.WriteMsg(msg)
	})

	tcpMux := dns.NewServeMux()
	tcpMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		tcpQueries.Add(1)
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=STSv1; id=tcp1;"},
		})
		_ = w.WriteMsg(msg)
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

	udpServer := &dns.Server{PacketConn: packetConn, Handler: udpMux}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: tcpMux}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})

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
