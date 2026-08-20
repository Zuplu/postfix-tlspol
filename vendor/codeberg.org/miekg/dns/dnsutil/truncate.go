package dnsutil

import "codeberg.org/miekg/dns"

// Truncate helps ensure the reply message will fit into the requested buffer
// size by removing all records and only leaving the question section and the pseudo section.
// After which the TC bit is set.
//
// Comparing the length of the message with the message's UDPSize is a good indication if the truncation
// was sufficient, i.e. m.Len() < m.UDPSize.
func Truncate(m *dns.Msg) {
	m.Truncated = true
	m.Answer = m.Answer[:0]
	m.Ns = m.Ns[:0]
	m.Extra = m.Extra[:0]
}
