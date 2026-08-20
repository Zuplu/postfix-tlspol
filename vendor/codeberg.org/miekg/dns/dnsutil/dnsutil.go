// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

import "crypto/rand"

// Trim removes the zone component from s. It returns the trimmed name or the original string if z is longer
// than s. The trimmed name will be returned without a trailing dot. s and z must be syntactically valid
// domain names, see [IsName] and [IsFqdn]. And also see [Prev] and [Next] to iterate over a domain name.
func Trim(s, z string) string {
	offset, start := len(s), false
	for range Labels(z) {
		offset, start = Prev(s, offset)
		if start {
			return s
		}
	}
	return s[:offset-1]
}

// IsBelow checks if child sits below parent in the DNS tree, i.e. check if the child is a sub-domain of
// parent. If child and parent are at the same level, true is returned as well.
func IsBelow(parent, child string) bool { return Common(parent, child) == Labels(parent) }

// Randomize randomizes the string s, it randomly upper or lower cases each letter. If a letter is already
// uppercase it is downcased.
func Randomize(s string) string {
	b := []byte(s)
	r := [1]byte{}
	for i := range b {
		rand.Read(r[:])
		if r[0]%2 == 0 {
			if b[i] >= 'A' && b[i] <= 'Z' {
				b[i] += 0x20
				continue
			}
			if b[i] >= 'a' && b[i] <= 'z' {
				b[i] -= 0x20
			}
		}
	}
	return string(b)
}
