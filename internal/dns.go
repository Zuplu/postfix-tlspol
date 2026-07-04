/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"

	"github.com/miekg/dns"
)

func newDNSQuery(name string, qtype uint16, dnssecOK bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(DNS_UDP_PAYLOAD_SIZE, dnssecOK)
	return m
}

func exchangeDNS(ctx context.Context, m *dns.Msg, resolverAddress string) (*dns.Msg, error) {
	udpClient := client
	udpClient.Net = "udp"
	r, _, err := udpClient.ExchangeContext(ctx, m, resolverAddress)
	if err != nil {
		return nil, err
	}
	if r == nil || !r.Truncated {
		return r, nil
	}

	tcpClient := client
	tcpClient.Net = "tcp"
	r, _, err = tcpClient.ExchangeContext(ctx, m, resolverAddress)
	if err != nil {
		return nil, err
	}
	return r, nil
}
