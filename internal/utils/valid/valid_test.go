/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package valid

import (
	"strings"
	"testing"
)

func TestIsHex(t *testing.T) {
	cases := []struct {
		in  string
		out bool
	}{
		{"abcdef", true},
		{"ABCDEF123", true},
		{"123xyz", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsHex(c.in); got != c.out {
			t.Errorf("IsHex(%q) = %v, want %v", c.in, got, c.out)
		}
	}
}

func TestSHA(t *testing.T) {
	if !IsSHA224(strings.Repeat("a", 56)) {
		t.Error("SHA224 check failed")
	}
	if IsSHA224("deadbeef") {
		t.Error("invalid SHA224 accepted")
	}
	if !IsSHA256(strings.Repeat("b", 64)) {
		t.Error("SHA256 check failed")
	}
	if !IsSHA384(strings.Repeat("c", 96)) {
		t.Error("SHA384 check failed")
	}
	if !IsSHA512(strings.Repeat("d", 128)) {
		t.Error("SHA512 check failed")
	}
}

func TestIsDNSName(t *testing.T) {
	valid := []string{
		"example.com",
		"foo-bar.example.com",
		"xn--d1acufc.xn--p1ai",
		"test.",
	}
	invalid := []string{
		"", ".", "-bad.com", "bad-.com", "ba..d.com",
		strings.Repeat("a", 64) + ".com",
	}
	for _, s := range valid {
		if !IsDNSName(s) {
			t.Errorf("expected valid DNS name: %q", s)
		}
	}
	for _, s := range invalid {
		if IsDNSName(s) {
			t.Errorf("expected invalid DNS name: %q", s)
		}
	}
}

func TestASCIIAndUTF8(t *testing.T) {
	if !IsPrintableASCII("HelloWorld!") {
		t.Error("expected printable ASCII")
	}
	if IsPrintableASCII("Hello\x01") {
		t.Error("unexpected control char accepted")
	}
	if !IsUTF8("Hällo") {
		t.Error("expected valid UTF-8")
	}
	if IsUTF8(string([]byte{0xff, 0xfe})) {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestIPs(t *testing.T) {
	if !IsIP4("192.168.1.1") {
		t.Error("IPv4 failed")
	}
	if IsIP4("::1") {
		t.Error("IPv6 accepted as IPv4")
	}
	if !IsIP6("::1") {
		t.Error("IPv6 failed")
	}
	if !IsIP("10.0.0.1") || !IsIP("2001:db8::1") {
		t.Error("generic IP check failed")
	}
	if IsIP("not.an.ip") {
		t.Error("invalid IP accepted")
	}
}
