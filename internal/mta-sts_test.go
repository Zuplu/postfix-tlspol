package tlspol

import (
	"fmt"
	"strings"
	"testing"
)

func init() {
	config = Config{
		Server: ServerConfig{},
		Dns: DnsConfig{
			Address: "dns.google:53",
		},
		Redis: RedisConfig{
			Disable: true,
		},
	}
}

func TestMtaSts(t *testing.T) {
	t.Parallel()
	domains := []string{"gmail.com", "outlook.com", "zuplu.com", "mailbox.org", "protonmail.com"}

	passedOnce := false
	for _, domain := range domains {
		func(domain string) {
			t.Run(fmt.Sprintf("Domain=%q", domain), func(t *testing.T) {
				if passedOnce && testing.Short() {
					t.SkipNow()
					return
				}
				policy, _, _ := checkMtaSts(&bgCtx, &domain)
				if !strings.HasPrefix(policy, "secure ") {
					t.Skipf("Expected MTA-STS for %q, but not detected", domain)
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
