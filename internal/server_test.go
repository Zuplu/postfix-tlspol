package main

import (
	"fmt"
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

func TestDaneOverMtaSts(t *testing.T) {
	domains := []string{"zuplu.com", "mailbox.org", "protonmail.com"}
	for _, domain := range domains {
		func(domain string) {
			if t.Run(fmt.Sprintf("Domain=%q", domain), func(t *testing.T) {
				policy, _, _ := queryDomain(&domain)
				if policy != "dane-only" {
					t.Errorf("Expected DANE for %q, but not detected", domain)
				}
			}) && testing.Short() {
				t.Skip("At least one test passed!")
			}
		}(domain)
	}
}
