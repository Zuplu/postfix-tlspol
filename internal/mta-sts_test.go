/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"fmt"
	"strings"
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

func TestParseMtaStsPolicy(t *testing.T) {
	t.Parallel()

	t.Run("valid enforce policy", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 86400\n"))
		if policy != "secure match=mail.example.com:.backup.example.com servername=hostname" {
			t.Fatalf("unexpected policy: %q", policy)
		}
		if ttl != 86400 {
			t.Fatalf("unexpected ttl: %d", ttl)
		}
		for _, expected := range []string{
			"policy_type=sts",
			"policy_domain=example.com",
			"mx_host_pattern=mail.example.com",
			"mx_host_pattern=*.backup.example.com",
			"policy_string = version: STSv1",
			"policy_string = mx: *.backup.example.com",
		} {
			if !strings.Contains(report, expected) {
				t.Fatalf("expected report to contain %q; report=%q", expected, report)
			}
		}
	})

	t.Run("missing version is not enforceable", func(t *testing.T) {
		t.Parallel()

		policy, _, ttl := parseMtaStsPolicy("example.com", strings.NewReader("mode: enforce\nmx: mail.example.com\nmax_age: 86400\n"))
		if policy != "" {
			t.Fatalf("expected no enforceable policy, got %q", policy)
		}
		if ttl != 0 {
			t.Fatalf("expected ttl 0 without version, got %d", ttl)
		}
	})

	t.Run("missing max age is not enforceable", func(t *testing.T) {
		t.Parallel()

		policy, _, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\n"))
		if policy != "" {
			t.Fatalf("expected no enforceable policy, got %q", policy)
		}
		if ttl != 0 {
			t.Fatalf("expected ttl 0 without max_age, got %d", ttl)
		}
	})

	t.Run("testing mode retains max age without policy", func(t *testing.T) {
		t.Parallel()

		policy, _, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 3600\n"))
		if policy != "" {
			t.Fatalf("expected no enforceable policy, got %q", policy)
		}
		if ttl != 3600 {
			t.Fatalf("expected ttl 3600 for valid non-enforcing policy, got %d", ttl)
		}
	})

	t.Run("invalid mode invalidates policy", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: invalid\nmx: mail.example.com\nmax_age: 86400\n"))
		if policy != "" || report != "" || ttl != 0 {
			t.Fatalf("expected invalid policy to be rejected, got policy=%q report=%q ttl=%d", policy, report, ttl)
		}
	})

	t.Run("ip literal mx patterns are rejected", func(t *testing.T) {
		t.Parallel()

		for _, policyText := range []string{
			"version: STSv1\nmode: enforce\nmx: 127.0.0.1\nmax_age: 86400\n",
			"version: STSv1\nmode: enforce\nmx: 1.2.3.4\nmax_age: 86400\n",
			"version: STSv1\nmode: enforce\nmx: *.1.2.3.4\nmax_age: 86400\n",
		} {
			policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader(policyText))
			if policy != "" || report != "" || ttl != 0 {
				t.Fatalf("expected IP literal MX policy to be rejected, got policy=%q report=%q ttl=%d", policy, report, ttl)
			}
		}
	})

	t.Run("control bytes in extension lines are rejected", func(t *testing.T) {
		t.Parallel()

		for _, policyText := range []string{
			"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nx-report: ok\x00bad\n",
			"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nx-report: ok\tbad\n",
			"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nx-report: ok\rbad\n",
			"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nx-report: ok\x7fbad\n",
		} {
			policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader(policyText))
			if policy != "" || report != "" || ttl != 0 {
				t.Fatalf("expected control-bearing policy line to be rejected, got policy=%q report=%q ttl=%d", policy, report, ttl)
			}
		}
	})

	t.Run("invalid extension names are rejected", func(t *testing.T) {
		t.Parallel()

		for _, extLine := range []string{
			"_comment: ok",
			"-comment: ok",
			".comment: ok",
			"bad name: ok",
			"x+comment: ok",
			"café: ok",
			strings.Repeat("a", 33) + ": ok",
		} {
			policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"+extLine+"\n"))
			if policy != "" || report != "" || ttl != 0 {
				t.Fatalf("expected invalid extension name %q to be rejected, got policy=%q report=%q ttl=%d", extLine, policy, report, ttl)
			}
		}
	})

	t.Run("invalid extension values are rejected", func(t *testing.T) {
		t.Parallel()

		for _, extLine := range []string{
			"comment:",
			"comment: ok\x00bad",
			"comment: ok\tbad",
			"comment: ok\rbad",
			"comment: ok\x7fbad",
			"comment: ok" + string([]byte{0xff}) + "bad",
		} {
			policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"+extLine+"\n"))
			if policy != "" || report != "" || ttl != 0 {
				t.Fatalf("expected invalid extension value %q to be rejected, got policy=%q report=%q ttl=%d", extLine, policy, report, ttl)
			}
		}
	})

	t.Run("printable extension lines remain reportable", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nx-report: safe-value\n"))
		if policy == "" || ttl != 86400 {
			t.Fatalf("expected printable extension policy to remain valid, got policy=%q ttl=%d", policy, ttl)
		}
		if !strings.Contains(report, "policy_string = x-report: safe-value") {
			t.Fatalf("expected printable extension line in report, got %q", report)
		}
	})

	t.Run("utf8 extension lines without x prefix remain reportable", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\ncomment: café au lait\n"))
		if policy != "secure match=mail.example.com servername=hostname" {
			t.Fatalf("unexpected policy: %q", policy)
		}
		if ttl != 86400 {
			t.Fatalf("unexpected ttl: %d", ttl)
		}
		if !strings.Contains(report, "policy_string = comment: café au lait") {
			t.Fatalf("expected UTF-8 extension line in report, got %q", report)
		}
	})

	t.Run("extension braces are ignored after validation", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\ncomment: {café}\n"))
		if policy != "secure match=mail.example.com servername=hostname" || ttl != 86400 {
			t.Fatalf("expected brace extension policy to remain valid, got policy=%q ttl=%d", policy, ttl)
		}
		if strings.Contains(report, "comment: {café}") {
			t.Fatalf("expected brace extension to be omitted from report, got %q", report)
		}
	})
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
				policy, _, _ := checkMtaSts(bgCtx, domain, true)
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
