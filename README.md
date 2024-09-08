# postfix-tlspol

[![CodeQL Badge](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/8fc8fa03ee7b49e4ad9375be46ccee47)](https://app.codacy.com/gh/Zuplu/postfix-tlspol/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

A lightweight and highly performant MTA-STS + DANE/TLSA resolver and TLS policy socketmap server for Postfix that complies to the standards and prioritizes DANE where possible.

# Logic

- Simultaneously checks for MTA-STS and DANE for a queried domain.
  
- **For DANE:**
  - Check each MX record (all servers in parallel), if one supports DANE. The DNS responses must be authorized (`ad` flag set).
  - Verify TLSA records for correctness and supported parameters, only then the `dane-only` policy (Mandatory DANE) will be returned.
  - In case of unsupported parameters or malformed TLSA records, `dane` (Opportunistic DANE) is returned.
  - In those edge cases, Postfix will try to enforce DANE if the TLSA records are usable. If they are not (despite valid DNSSEC signatures, e. g. malformed record set by the legitimate domain administrator or unsupported parameters), it will fall back to *mandatory* but unauthenticated TLS (thus `encrypt` at worst).
  - If the TLSA records are usable but invalid (e. g. key fingerprint mismatch), the mail will be deferred (for both `dane` and `dane-only`), even if there is a valid MTA-STS policy (in conformance with [RFC 8461, 2](https://www.rfc-editor.org/rfc/rfc8461#section-2)).
    
- **For MTA-STS:**
  - Check for an existing MTA-STS record over DNS, and if found, fetch the policy via HTTPS.
  - If a response from the DANE query is available and not empty, the MTA-STS result is ignored.
  - If the DANE check is not ready yet, the result will be hold back, until it is completed.
  - DNS errors won't downgrade to MTA-STS, TLSA records must be explicitly and verifiably not available for MTA-STS to overrule DANE.
  - If there is no TLSA record available for at least one MX record, so that the DANE query returns an empty policy, then the MTA-STS policy will take effect and result in a `secure` policy and explicitly enforce a `match=` with the policy-provided MX hostnames.
    
- The result is cached by `minimum TTL of all queries` or `max_age` seconds, for DANE and MTA-STS respectively.

It is recommended to still set the default TLS policy to `dane` (Opportunistic DANE) in Postfix.

# Requirements

- A Redis-compatible database
- Postfix
- Go 1.23+
- DNSSEC-validating DNS server (preferably on localhost)

# Install

```
git clone https://github.com/Zuplu/postfix-tlspol
cd postfix-tlspol
./build.sh
systemctl enable --now ./postfix-tlspol.service
```

Edit `config.yaml` as needed.

In `/etc/postfix/main.cf`:

```
smtp_tls_security_level = dane
smtp_dns_support_level = dnssec
smtp_tls_policy_maps = socketmap:inet:127.0.0.1:8642:query
```

Restart or reload as needed.
```
# after editting Postfix configuration main.cf
service postfix restart

# after changing config.yaml
service postfix-tlspol restart
```

# Update

```
git pull
./build.sh
service postfix-tlspol restart
```

# Configuration

Configuration example for `config.yaml`:
```
server:
  address: 127.0.0.1:8642  # server:port to listen as a socketmap server
  tlsrpt: no               # set yes to enable Postfix 3.10+ TLSRPT support
                           # this is experimental, not backwards compatible
                           # and may result in delivery failures (default no)
  prefetch: no             # prefetch when TTL is about to expire (default no)

dns:
  address: 127.0.0.53:53   # must support dnssec

redis:
  disable: no              # disables caching (default no)
  address: 127.0.0.1:6379  # redis compatible server:port to act as a cache
  db: 2                    # select redis db number

```

# Prefetching

If you enable prefetching via `config.yaml`, it is recommended to adjust your local DNS caching resolver to serve the original TTL response.

For example, in Unbound, configure the following:
```
cache-min-ttl: 10
cache-max-ttl: 300
serve-original-ttl: yes
```
This will serve the original TTL, but still reload the cache after `300` seconds, when a new query is made.

It ensures that when postfix-tlspol prefetches policies before the TTL actually expires, the DNS cache won't be used (otherwise it would only prefetch for the residual TTL time).

Prefetching will work without these settings, but a little less efficiently.
