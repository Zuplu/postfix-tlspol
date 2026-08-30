/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func startTestDNSServer(t *testing.T, server *dns.Server) func() {
	t.Helper()

	started := make(chan struct{})
	serveErr := make(chan error, 1)
	server.NotifyStartedFunc = func(context.Context) {
		close(started)
	}
	go func() {
		serveErr <- server.ListenAndServe()
	}()

	select {
	case <-started:
	case err := <-serveErr:
		t.Fatalf("start test DNS server: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out starting test DNS server")
	}

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			server.Shutdown(context.Background())
			if err := <-serveErr; err != nil {
				t.Errorf("stop test DNS server: %v", err)
			}
		})
	}
	t.Cleanup(shutdown)
	return shutdown
}

type dnsTestQuestion struct {
	Name  string
	Qtype uint16
}

type dnsTestEDNS struct {
	udpSize uint16
	do      bool
}

func (e *dnsTestEDNS) UDPSize() uint16 { return e.udpSize }
func (e *dnsTestEDNS) Do() bool        { return e.do }

func dnsQuestion(m *dns.Msg) dnsTestQuestion {
	name, qtype := dnsutil.Question(m)
	return dnsTestQuestion{Name: name, Qtype: qtype}
}

func dnsEDNS0(m *dns.Msg) *dnsTestEDNS {
	if m.UDPSize == 0 && !m.Security && len(m.Pseudo) == 0 {
		return nil
	}
	return &dnsTestEDNS{udpSize: m.UDPSize, do: m.Security}
}

func setDNSReply(m, request *dns.Msg) {
	dnsutil.SetReply(m, request)
}

func setDNSRcode(m, request *dns.Msg, rcode uint16) {
	dnsutil.SetReply(m, request)
	m.Rcode = rcode
}

func writeDNSMsg(w dns.ResponseWriter, m *dns.Msg) error {
	if err := m.Pack(); err != nil {
		return err
	}
	_, err := io.Copy(w, m)
	return err
}

func dnsHeader(name string, ttl uint32) dns.Header {
	return dns.Header{Name: name, TTL: ttl, Class: dns.ClassINET}
}

func dnsMX(name string, ttl uint32, preference uint16, mx string) *dns.MX {
	return &dns.MX{
		Hdr: dnsHeader(name, ttl),
		MX:  rdata.MX{Preference: preference, Mx: mx},
	}
}

func dnsA(name string, ttl uint32, address string) *dns.A {
	return &dns.A{
		Hdr: dnsHeader(name, ttl),
		A:   rdata.A{Addr: netip.MustParseAddr(address)},
	}
}

func dnsAAAA(name string, ttl uint32, address string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dnsHeader(name, ttl),
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr(address)},
	}
}

func dnsTXT(name string, ttl uint32, text ...string) *dns.TXT {
	return &dns.TXT{
		Hdr: dnsHeader(name, ttl),
		TXT: rdata.TXT{Txt: text},
	}
}

func dnsTLSA(name string, ttl uint32, usage, selector, matchingType uint8, certificate string) *dns.TLSA {
	return &dns.TLSA{
		Hdr: dnsHeader(name, ttl),
		TLSA: rdata.TLSA{
			Usage:        usage,
			Selector:     selector,
			MatchingType: matchingType,
			Certificate:  certificate,
		},
	}
}

func dnsSOA(name string, ttl, negativeTTL uint32) *dns.SOA {
	return &dns.SOA{
		Hdr: dnsHeader(name, ttl),
		SOA: rdata.SOA{Minttl: negativeTTL},
	}
}

func dnsCNAME(name string, ttl uint32, target string) *dns.CNAME {
	return &dns.CNAME{
		Hdr:   dnsHeader(name, ttl),
		CNAME: rdata.CNAME{Target: target},
	}
}
