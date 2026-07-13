/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
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

func TestMtaStsRecordAvailable(t *testing.T) {
	txt := func(chunks ...string) dns.RR {
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: "_mta-sts.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: chunks,
		}
	}
	tests := []struct {
		name    string
		rcode   int
		answers []dns.RR
		want    bool
		wantErr bool
	}{
		{name: "valid split record", answers: []dns.RR{txt("v=STSv1; id=", "policy1;")}, want: true},
		{name: "valid whitespace delimiters", answers: []dns.RR{txt("v=STSv1 \t; \tid=policy1 \t;")}, want: true},
		{name: "unrelated record discarded", answers: []dns.RR{txt("verification=abc"), txt("v=STSv1; id=policy1;")}, want: true},
		{name: "missing id", answers: []dns.RR{txt("v=STSv1; x-note=ok;")}},
		{name: "wrong version", answers: []dns.RR{txt("v=STSv10; id=policy1;")}},
		{name: "multiple candidates", answers: []dns.RR{txt("v=STSv1; id=policy1;"), txt("v=STSv1; id=policy2;")}},
		{name: "invalid id", answers: []dns.RR{txt("v=STSv1; id=bad-value;")}},
		{name: "invalid extension value", answers: []dns.RR{txt("v=STSv1; id=policy1; note=has space;")}},
		{name: "trailing whitespace without delimiter", answers: []dns.RR{txt("v=STSv1; id=policy1 ")}},
		{name: "non ascii", answers: []dns.RR{txt("v=STSv1; id=policy1; note=café;")}},
		{name: "servfail is temporary", rcode: dns.RcodeServerFailure, wantErr: true},
		{name: "nxdomain means unavailable", rcode: dns.RcodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: tt.rcode}, Answer: tt.answers}
			got, err := mtaStsRecordAvailable(msg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("available = %v, want %v", got, tt.want)
			}
		})
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

	t.Run("missing mode is invalid", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmx: mail.example.com\nmax_age: 86400\n"))
		if policy != "" || report != "" || ttl != 0 {
			t.Fatalf("expected policy without mode to be rejected, got policy=%q report=%q ttl=%d", policy, report, ttl)
		}
	})

	t.Run("enforce and testing require mx", func(t *testing.T) {
		t.Parallel()

		for _, mode := range []string{"enforce", "testing"} {
			policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: "+mode+"\nmax_age: 86400\n"))
			if policy != "" || report != "" || ttl != 0 {
				t.Fatalf("expected %s policy without mx to be rejected, got policy=%q report=%q ttl=%d", mode, policy, report, ttl)
			}
		}
	})

	t.Run("none mode permits no mx", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\nmode: none\nmax_age: 86400\n"))
		if policy != "" || report != "" || ttl != 86400 {
			t.Fatalf("unexpected none policy result: policy=%q report=%q ttl=%d", policy, report, ttl)
		}
	})

	t.Run("blank policy line is invalid", func(t *testing.T) {
		t.Parallel()

		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader("version: STSv1\n\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"))
		if policy != "" || report != "" || ttl != 0 {
			t.Fatalf("expected blank line to invalidate policy, got policy=%q report=%q ttl=%d", policy, report, ttl)
		}
	})

	t.Run("oversized policy is invalid", func(t *testing.T) {
		t.Parallel()

		body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nnote: " + strings.Repeat("a", MTASTS_MAX_POLICY_SIZE)
		policy, report, ttl := parseMtaStsPolicy("example.com", strings.NewReader(body))
		if policy != "" || report != "" || ttl != 0 {
			t.Fatalf("expected oversized policy to be rejected, got policy=%q report=%q ttl=%d", policy, report, ttl)
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

func TestMtaStsPolicyMediaType(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{contentType: "text/plain", want: true},
		{contentType: "text/plain; charset=utf-8", want: true},
		{contentType: "TEXT/PLAIN; charset=US-ASCII; x-extra=ignored", want: true},
		{contentType: ""},
		{contentType: "text/html"},
		{contentType: "text/plain; charset=iso-8859-1", want: true},
		{contentType: "not a media type"},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			if got := isValidMtaStsPolicyMediaType(tt.contentType); got != tt.want {
				t.Fatalf("isValidMtaStsPolicyMediaType(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func FuzzParseMtaStsPolicy(f *testing.F) {
	for _, seed := range []string{
		"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n",
		"version: STSv1\nmode: none\nmax_age: 0\n",
		"version: STSv1\ncomment: caf\xc3\xa9\nmode: testing\nmx: *.example.com\nmax_age: 31557600\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, policyText string) {
		policy, _, ttl := parseMtaStsPolicy("example.com", strings.NewReader(policyText))
		if uint64(ttl) > MTASTS_MAX_AGE {
			t.Fatalf("parser returned out-of-range max_age %d", ttl)
		}
		if policy != "" && !strings.HasPrefix(policy, "secure match=") {
			t.Fatalf("parser returned unexpected policy %q", policy)
		}
	})
}

func TestMtaSts(t *testing.T) {
	requireLiveNetworkTests(t)
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
