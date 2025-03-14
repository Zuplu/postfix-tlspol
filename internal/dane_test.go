package tlspol

import (
	"fmt"
	"testing"
)

func init() {
	config = Config{
		Server: ServerConfig{},
		Dns: DnsConfig{
			Address: "8.8.8.8:53",
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
				policy, _ := checkDane(&bgCtx, &domain, true)
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
