package tlspol

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestMxAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signed   bool
		a        string
		aaaa     string
		want     uint8
		wantAAAA int32
	}{
		{"secure IPv4 survives IPv6 failure", true, "address", "servfail", MxOk, 0},
		{"insecure IPv4 survives IPv6 failure", false, "address", "servfail", MxNotSec, 0},
		{"secure IPv6 survives IPv4 failure", true, "servfail", "address", MxOk, 1},
		{"insecure IPv6 survives IPv4 failure", false, "servfail", "address", MxNotSec, 1},
		{"insecure IPv6 after empty IPv4", false, "nodata", "address", MxNotSec, 1},
		{"insecure empty IPv4 cannot hide IPv6 failure", false, "nodata", "servfail", MxFail, 1},
		{"secure empty IPv4 cannot hide IPv6 failure", true, "nodata", "servfail", MxFail, 1},
		{"insecure negative answers have no address", false, "nxdomain", "nxdomain", MxInsecureNoAddress, 1},
		{"secure negative answers have no address", true, "nodata", "nodata", MxNoAddress, 1},
		{"both families fail", true, "servfail", "servfail", MxFail, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var aaaaQueries atomic.Int32
			handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, request *dns.Msg) {
				msg := new(dns.Msg)
				setDNSReply(msg, request)
				msg.AuthenticatedData = tc.signed
				q := dnsQuestion(request)
				answer := tc.a
				if q.Qtype == dns.TypeAAAA {
					aaaaQueries.Add(1)
					answer = tc.aaaa
				}
				switch answer {
				case "address":
					if q.Qtype == dns.TypeA {
						msg.Answer = []dns.RR{dnsA(q.Name, 300, "192.0.2.1")}
					} else {
						msg.Answer = []dns.RR{dnsAAAA(q.Name, 300, "2001:db8::1")}
					}
				case "servfail":
					msg.AuthenticatedData = false
					msg.Rcode = dns.RcodeServerFailure
				case "nxdomain":
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
			if got := checkMx(context.Background(), "mx.example.test", pc.LocalAddr().String()); got != tc.want {
				t.Fatalf("checkMx = %d, want %d", got, tc.want)
			}
			if got := aaaaQueries.Load(); got != tc.wantAAAA {
				t.Fatalf("AAAA queries = %d, want %d", got, tc.wantAAAA)
			}
		})
	}
}
