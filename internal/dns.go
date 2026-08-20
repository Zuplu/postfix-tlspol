/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"

	"codeberg.org/miekg/dns"
)

func newDNSQuery(name string, qtype uint16, dnssecOK bool) *dns.Msg {
	m := dns.NewMsg(name, qtype)
	m.UDPSize = DNS_UDP_PAYLOAD_SIZE
	m.Security = dnssecOK
	return m
}

func exchangeDNS(ctx context.Context, m *dns.Msg, resolverAddress string) (*dns.Msg, error) {
	r, _, err := client.Exchange(ctx, m, "udp", resolverAddress)
	if err != nil {
		return nil, err
	}
	if r == nil || !r.Truncated {
		return r, nil
	}

	r, _, err = client.Exchange(ctx, m, "tcp", resolverAddress)
	if err != nil {
		return nil, err
	}
	return r, nil
}
