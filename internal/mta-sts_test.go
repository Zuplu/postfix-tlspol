package main

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
	domains := []string{"gmail.com", "outlook.com", "zuplu.com", "mailbox.org", "protonmail.com"}
	for _, domain := range domains {
		func(domain string) {
			if t.Run(fmt.Sprintf("Domain=%q", domain), func(t *testing.T) {
				policy, _, _ := checkMtaSts(&bgCtx, &domain)
				if !strings.HasPrefix(policy, "secure ") {
					t.Errorf("Expected MTA-STS for %q, but not detected", domain)
				}
			}) && testing.Short() {
				t.Skip("At least one test passed!")
			}
		}(domain)
	}
}
