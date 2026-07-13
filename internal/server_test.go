/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"fmt"
	"os"
	"testing"
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

func TestDaneOverMtaSts(t *testing.T) {
	requireLiveNetworkTests(t)
	t.Parallel()
	domains := []string{"zuplu.com", "mailbox.org", "protonmail.com"}
	passedOnce := false
	for _, domain := range domains {
		func(domain string) {
			t.Run(fmt.Sprintf("Domain=%q", domain), func(t *testing.T) {
				if passedOnce && testing.Short() {
					t.SkipNow()
					return
				}
				result := queryDomain(domain)
				if result.Policy != "dane-only" {
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

func requireLiveNetworkTests(t *testing.T) {
	t.Helper()
	if os.Getenv("TLSPOL_LIVE_TESTS") != "1" {
		t.Skip("set TLSPOL_LIVE_TESTS=1 to run tests against public DNS and HTTPS services")
	}
}
