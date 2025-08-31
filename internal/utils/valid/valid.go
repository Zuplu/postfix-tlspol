/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package valid

import (
	"net"
	"unicode/utf8"
)

func isHexByte(b byte) bool {
	return b >= '0' && b <= '9' ||
		b|0x20 >= 'a' && b|0x20 <= 'f'
}

func IsHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func IsSHA224(s string) bool { return len(s) == 56 && IsHex(s) }

func IsSHA256(s string) bool { return len(s) == 64 && IsHex(s) }

func IsSHA384(s string) bool { return len(s) == 96 && IsHex(s) }

func IsSHA512(s string) bool { return len(s) == 128 && IsHex(s) }

//gocyclo:ignore
func IsDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
		if s == "" {
			return false
		}
	}
	if net.ParseIP(s) != nil {
		return false
	}
	labelLen := 0
	startOfLabel := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if labelLen == 0 || labelLen > 63 || s[i-1] == '-' {
				return false
			}
			labelLen = 0
			startOfLabel = true
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') ||
			startOfLabel && c == '-' {
			return false
		}
		labelLen++
		startOfLabel = false
	}
	if labelLen == 0 || labelLen > 63 || s[len(s)-1] == '-' {
		return false
	}
	return true
}

func IsPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func IsUTF8(s string) bool { return utf8.ValidString(s) }

func IsIP4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func IsIP6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

func IsIP(s string) bool { return net.ParseIP(s) != nil }
