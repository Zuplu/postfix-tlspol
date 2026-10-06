package tlspol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

type mixedMxFixture struct {
	signed  bool
	healthy string
	broken  string
	tlsa    bool
}

func startMixedMxDNS(t *testing.T, fixture mixedMxFixture) (string, *atomic.Int32) {
	t.Helper()
	var healthyQueries atomic.Int32
	handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, request *dns.Msg) {
		msg := new(dns.Msg)
		setDNSReply(msg, request)
		msg.AuthenticatedData = fixture.signed
		q := dnsQuestion(request)
		switch {
		case q.Qtype == dns.TypeMX:
			if fixture.broken == "mx-servfail" {
				msg.AuthenticatedData = false
				msg.Rcode = dns.RcodeServerFailure
				break
			}
			// Fill all workers with failures before the healthy candidate is queued.
			for i := range DANE_MX_LOOKUP_CONCURRENCY {
				msg.Answer = append(msg.Answer, dnsMX(q.Name, 300, uint16(i), fmt.Sprintf("bad%d.example.test.", i)))
			}
			if fixture.healthy != "none" {
				msg.Answer = append(msg.Answer, dnsMX(q.Name, 300, 10, "healthy.example.test."))
			}
		case q.Name == "healthy.example.test." && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			healthyQueries.Add(1)
			msg.AuthenticatedData = fixture.healthy == "secure"
			switch fixture.healthy {
			case "secure", "insecure":
				if q.Qtype == dns.TypeA {
					msg.Answer = []dns.RR{dnsA(q.Name, 300, "192.0.2.1")}
				}
			case "nxdomain":
				msg.Rcode = dns.RcodeNameError
			}
		case strings.HasPrefix(q.Name, "bad") && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA):
			msg.AuthenticatedData = false
			switch fixture.broken {
			case "timeout":
				return
			case "tlsa":
				msg.AuthenticatedData = true
				if q.Qtype == dns.TypeA {
					msg.Answer = []dns.RR{dnsA(q.Name, 300, "192.0.2.2")}
				}
			case "refused":
				msg.Rcode = dns.RcodeRefused
			default:
				msg.Rcode = dns.RcodeServerFailure
			}
		case q.Qtype == dns.TypeTLSA:
			msg.AuthenticatedData = true
			if strings.HasPrefix(q.Name, "_25._tcp.bad") {
				msg.AuthenticatedData = false
				msg.Rcode = dns.RcodeServerFailure
			} else if fixture.tlsa {
				msg.Answer = []dns.RR{dnsTLSA(q.Name, 300, 3, 1, 1, strings.Repeat("a", 64))}
			}
		default:
			msg.Rcode = dns.RcodeNameError
		}
		_ = writeDNSMsg(w, msg)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Net: "udp", Addr: pc.LocalAddr().String(), PacketConn: pc, Handler: handler}
	startTestDNSServer(t, server)
	return pc.LocalAddr().String(), &healthyQueries
}

func TestDaneMixedMxFailures(t *testing.T) {
	originalTimeout := client.Transport.ReadTimeout
	client.Transport.ReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { client.Transport.ReadTimeout = originalTimeout })
	for _, tc := range []struct {
		name    string
		fixture mixedMxFixture
		want    string
		fail    bool
	}{
		{"unsigned MX with SERVFAIL", mixedMxFixture{false, "insecure", "servfail", false}, "", false},
		{"signed MX without TLSA", mixedMxFixture{true, "secure", "servfail", false}, "", false},
		{"signed MX with TLSA", mixedMxFixture{true, "secure", "servfail", true}, "dane", false},
		{"unsigned MX with signed TLSA", mixedMxFixture{false, "secure", "servfail", true}, "dane", false},
		{"address refusal", mixedMxFixture{true, "secure", "refused", true}, "dane", false},
		{"address timeout", mixedMxFixture{true, "secure", "timeout", true}, "dane", false},
		{"no surviving MX", mixedMxFixture{true, "none", "servfail", false}, "", true},
		{"unsigned NODATA is not a survivor", mixedMxFixture{false, "nodata", "servfail", false}, "", true},
		{"unsigned NXDOMAIN is not a survivor", mixedMxFixture{false, "nxdomain", "servfail", false}, "", true},
		{"TLSA failure without sibling DANE", mixedMxFixture{true, "secure", "tlsa", false}, "", true},
		{"TLSA failure with sibling DANE", mixedMxFixture{true, "secure", "tlsa", true}, "", true},
		{"MX RRset failure", mixedMxFixture{true, "secure", "mx-servfail", true}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, healthyQueries := startMixedMxDNS(t, tc.fixture)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := checkDaneOnce(ctx, "example.test", resolver)
			if (err != nil) != tc.fail {
				t.Fatalf("result=%+v err=%v, want failure=%v", result, err, tc.fail)
			}
			if !tc.fail && (result.Policy != tc.want || !result.Partial || result.TTL != 0) {
				t.Fatalf("expected uncached partial policy %q, got %+v", tc.want, result)
			}
			if !tc.fail && healthyQueries.Load() == 0 {
				t.Fatal("failed MX lookups cancelled the healthy candidate")
			}
		})
	}
}

func TestMixedMxLookupRespectsCancellation(t *testing.T) {
	resolver, _ := startMixedMxDNS(t, mixedMxFixture{true, "secure", "timeout", true})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if result, err := checkDaneOnce(ctx, "example.test", resolver); err == nil {
		t.Fatalf("cancelled lookup returned a usable result: %+v", result)
	}
}

func TestMixedMxFailurePolicySelection(t *testing.T) {
	origDns, origSts := config.Dns, checkMtaStsPolicy
	t.Cleanup(func() { config.Dns, checkMtaStsPolicy = origDns, origSts })
	for _, tc := range []struct {
		name    string
		fixture mixedMxFixture
		sts     string
		want    string
	}{
		{"no policy", mixedMxFixture{false, "insecure", "servfail", false}, "", ""},
		{"STS remains available", mixedMxFixture{false, "insecure", "servfail", false}, "secure match=healthy.example.test", "secure match=healthy.example.test"},
		{"DANE takes precedence", mixedMxFixture{true, "secure", "servfail", true}, "secure match=healthy.example.test", "dane"},
		{"TLSA error cannot become STS", mixedMxFixture{true, "secure", "tlsa", false}, "secure match=healthy.example.test", "TEMP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, _ := startMixedMxDNS(t, tc.fixture)
			config.Dns = DnsConfig{Address: &resolver}
			checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
				return tc.sts, "", 86400
			}
			result := queryDomainOnceImpl("example.test")
			if result.Policy != tc.want || result.TTL != 0 || result.Dane.HasData() {
				t.Fatalf("unexpected domain policy: %+v", result)
			}
			if result.DanePartial != (tc.want != "TEMP") {
				t.Fatalf("incorrect partial state: %+v", result)
			}
		})
	}
}
