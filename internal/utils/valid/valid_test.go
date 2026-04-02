/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package valid

import (
	"strings"
	"testing"
)

func TestIsHex(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"lower", "abcdef", true},
		{"upper_and_digits", "ABCDEF123", true},
		{"mixed_case", "aBcDeF", true},
		{"single_zero", "0", true},
		{"non_hex_letters", "123xyz", false},
		{"prefix_not_allowed", "0xdeadbeef", false},
		{"whitespace_not_allowed", "dead beef", false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsHex(tc.in); got != tc.want {
				t.Fatalf("IsHex(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSHA(t *testing.T) {
	t.Parallel()

	type shaCase struct {
		name string
		in   string
		want bool
		fn   func(string) bool
	}

	cases := []shaCase{
		{"sha224_valid", strings.Repeat("a", 56), true, IsSHA224},
		{"sha224_invalid_len", strings.Repeat("a", 55), false, IsSHA224},
		{"sha224_invalid_char", strings.Repeat("a", 55) + "g", false, IsSHA224},

		{"sha256_valid", strings.Repeat("b", 64), true, IsSHA256},
		{"sha256_invalid_len", strings.Repeat("b", 63), false, IsSHA256},
		{"sha256_invalid_char", strings.Repeat("b", 63) + "z", false, IsSHA256},

		{"sha384_valid", strings.Repeat("c", 96), true, IsSHA384},
		{"sha384_invalid_len", strings.Repeat("c", 95), false, IsSHA384},
		{"sha384_invalid_char", strings.Repeat("c", 95) + "x", false, IsSHA384},

		{"sha512_valid", strings.Repeat("d", 128), true, IsSHA512},
		{"sha512_invalid_len", strings.Repeat("d", 127), false, IsSHA512},
		{"sha512_invalid_char", strings.Repeat("d", 127) + "q", false, IsSHA512},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.fn(tc.in); got != tc.want {
				t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestIsDNSName(t *testing.T) {
	t.Parallel()

	max63 := strings.Repeat("a", 63)
	tooLong64 := strings.Repeat("a", 64)
	max253 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	tooLong254 := max253 + "e"

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"basic_domain", "example.com", true},
		{"hyphen_inside_label", "foo-bar.example.com", true},
		{"punycode_like", "xn--d1acufc.xn--p1ai", true},
		{"trailing_dot_fqdn", "test.", true},
		{"single_label", "localhost", true},
		{"max_label_length_63", max63 + ".com", true},
		{"max_total_length_253", max253, true},

		{"empty", "", false},
		{"dot_only", ".", false},
		{"starts_with_hyphen", "-bad.com", false},
		{"ends_with_hyphen", "bad-.com", false},
		{"double_dot", "ba..d.com", false},
		{"label_too_long_64", tooLong64 + ".com", false},
		{"total_too_long_254", tooLong254, false},
		{"ipv4_literal_not_dns", "192.168.1.1", false},
		{"ipv6_literal_not_dns", "2001:db8::1", false},
		{"underscore_not_allowed", "bad_name.example", false},
		{"space_not_allowed", "bad name.example", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsDNSName(tc.in); got != tc.want {
				t.Fatalf("IsDNSName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestASCIIAndUTF8(t *testing.T) {
	t.Parallel()

	t.Run("printable_ascii", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			in   string
			want bool
		}{
			{"HelloWorld!", true},
			{"~", true},
			{" ", true},
			{"", true},
			{"Hello\x01", false},
			{"\n", false},
			{"\x7f", false},
			{"Hällo", false},
		}

		for _, tc := range cases {
			if got := IsPrintableASCII(tc.in); got != tc.want {
				t.Fatalf("IsPrintableASCII(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	})

	t.Run("utf8", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			in   string
			want bool
		}{
			{"Hällo", true},
			{"", true},
			{string([]byte{0xff, 0xfe}), false},
			{string([]byte{0xe2, 0x82}), false}, // truncated sequence
		}

		for _, tc := range cases {
			if got := IsUTF8(tc.in); got != tc.want {
				t.Fatalf("IsUTF8(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	})
}

func TestIPs(t *testing.T) {
	t.Parallel()

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			in   string
			want bool
		}{
			{"192.168.1.1", true},
			{"0.0.0.0", true},
			{"255.255.255.255", true},
			{"256.1.1.1", false},
			{"::1", false},
			{"not.an.ip", false},
		}

		for _, tc := range cases {
			if got := IsIP4(tc.in); got != tc.want {
				t.Fatalf("IsIP4(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			in   string
			want bool
		}{
			{"::1", true},
			{"2001:db8::1", true},
			{"192.168.1.1", false},
			{"2001:::1", false},
			{"not.an.ip", false},
		}

		for _, tc := range cases {
			if got := IsIP6(tc.in); got != tc.want {
				t.Fatalf("IsIP6(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	})

	t.Run("generic_ip", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			in   string
			want bool
		}{
			{"10.0.0.1", true},
			{"2001:db8::1", true},
			{"not.an.ip", false},
			{"", false},
		}

		for _, tc := range cases {
			if got := IsIP(tc.in); got != tc.want {
				t.Fatalf("IsIP(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	})
}
