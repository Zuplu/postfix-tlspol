// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

import (
	"crypto/rand"

	"codeberg.org/miekg/dns"
)

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

// SetReply turns the request r into its own reply, and returns r. The ID, opcode, question and the EDNS0
// settings (UDP size, DO bit) are kept. The RecursionDesired, CheckingDisabled and Security bits are only
// kept for a query, and the rcode is set to success. All other header bits are cleared and the other sections
// are resliced to length zero as is the Data.
func SetReply(m *dns.Msg) *dns.Msg {
	m.Flags = 0 // RFC 6891, section 6.1.4: a sender zeroes these.
	m.Response = true
	m.Authoritative, m.Truncated, m.RecursionAvailable, m.AuthenticatedData, m.Zero = false, false, false, false, false
	if m.Opcode != dns.OpcodeQuery {
		m.RecursionDesired, m.CheckingDisabled, m.Security, m.Delegation = false, false, false, false
	}
	m.Rcode = dns.RcodeSuccess
	m.Reset()
	m.Data = m.Data[:0]
	return m
}
