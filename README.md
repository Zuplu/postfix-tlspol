# postfix-tlspol

[![GitHub Release](https://img.shields.io/github/v/release/Zuplu/postfix-tlspol)](https://github.com/Zuplu/postfix-tlspol/releases/latest) [![GitHub License](https://img.shields.io/github/license/Zuplu/postfix-tlspol)](https://github.com/Zuplu/postfix-tlspol/blob/main/LICENSE) [![CodeQL Badge](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/) [![Go Report Card](https://goreportcard.com/badge/github.com/Zuplu/postfix-tlspol)](https://goreportcard.com/report/github.com/Zuplu/postfix-tlspol) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/98f114fa07ac4daa89495e5248d4c76b)](https://app.codacy.com/gh/Zuplu/postfix-tlspol/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) [![build-docker](https://img.shields.io/github/actions/workflow/status/Zuplu/postfix-tlspol/build-docker.yaml?branch=main&event=push&logo=docker&logoColor=white&label=Docker&color=%232496ED)](https://hub.docker.com/r/zuplu/postfix-tlspol/tags) [![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/Zuplu/postfix-tlspol)](https://github.com/Zuplu/postfix-tlspol/blob/main/go.mod)

[<img src="https://zuplu.com/mascot.svg" width="140em" align="right" alt="Gopher mascot" />](#)

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

It is recommended to still set the default TLS policy to `dane` (Opportunistic DANE) in Postfix (see below).

# Install packaged version

List of repositories serving prebuilt and packaged versions of postfix-tlspol:

[![Packaging status](https://repology.org/badge/vertical-allrepos/postfix-tlspol.svg?exclude_sources=modules,site)](#)

# Install via Docker

Installation with Docker simplifies setup, as it contains its own `Redis` database and a properly configured DNS resolver, `Unbound`. The image itself is only about 25 MB.

```
docker volume create postfix-tlspol-data
docker run -d \
    -v postfix-tlspol-data:/data \
    -p 127.0.0.1:8642:8642 \
    --restart unless-stopped \
    --name postfix-tlspol \
    zuplu/postfix-tlspol:latest
```

Jump to *Postfix configuration* to integrate the socketmap server.

To update the image, stop and remove the container, and run the above command again.

To disable prefetching, pass `-e TLSPOL_PREFETCH=0` to the above command.

# Install from source

## Build a Docker container from source

```
git clone https://github.com/Zuplu/postfix-tlspol
cd postfix-tlspol
scripts/build.sh # press 'd' for Docker when prompted
```

## Standalone

### Requirements

These requirements only apply if you use the non-Docker variant for installation, i. e. as a systemd service unit.

- A Redis-compatible database (e. g. Valkey, KeyDB, Redis, ...; optional if caching is disabled)
- Postfix
- Go (latest)
- DNSSEC-validating DNS server (preferably on localhost)

### Build and install

```
git clone https://github.com/Zuplu/postfix-tlspol
cd postfix-tlspol
scripts/build.sh # press 's' for systemd when prompted
```

Edit `configs/config.yaml` as needed. After any change, a restart is required:
```
service postfix-tlspol restart
```

# Postfix configuration

In `/etc/postfix/main.cf`:

```
smtp_dns_support_level = dnssec
smtp_tls_security_level = dane
smtp_tls_dane_insecure_mx_policy = dane
smtp_tls_policy_maps = socketmap:inet:127.0.0.1:8642:QUERY
```

Note: Explicitly setting `smtp_tls_dane_insecure_mx_policy` to `dane` is a workaround to keep falling back to `dane` in case you changed the recommended default `smtp_tls_security_level` to something different than `dane`. postfix-tlspol returns `dane` only for domains where `dane-only` is not possible (because the MX lookup is unsigned, but the MX server itself supports DANE). Not setting this would make `dane` ineffective and only honor `dane-only`, if your `smtp_tls_security_level` is not `dane`.

### For Postfix 3.10 and later

```
smtp_dns_support_level = dnssec
smtp_tls_security_level = dane
# already default:
# smtp_tls_dane_insecure_mx_policy = dane
smtp_tls_policy_maps = socketmap:inet:127.0.0.1:8642:QUERYwithTLSRPT
```

Note the `QUERYwithTLSRPT` that enables TLSRPT support for Postfix 3.10+.

### Reload

After changing the Postfix configuration, do:
```
postfix reload
```

# Update (from source)

You can update postfix-tlspol (both the Docker container and the systemd service variant), by simply doing:
```
git pull
scripts/build.sh
```

# Configuration

_*Warning:* Configuring is only available for the standalone/systemd installation. The Docker version is configured properly with prefetching enabled._

Configuration example for `configs/config.yaml`:
```
server:
  # server:port to listen as a socketmap server
  # or unix:/run/postfix-tlspol/tlspol.sock for Unix Domain Socket
  address: 127.0.0.1:8642

  # prefetch when TTL is about to expire (default true)
  prefetch: true

dns:
  # must support DNSSEC
  address: 127.0.0.53:53

redis:
  # disable caching (default false)
  disable: false

  # Redis compatible server:port to act as a cache
  address: 127.0.0.1:6379

  # select Redis DB number
  db: 2
```

# Prefetching

If you enable prefetching via `configs/config.yaml`, it is recommended to adjust your local DNS caching resolver to serve the original TTL response.

For example, in `Unbound`, configure the following:
```
cache-min-ttl: 10
cache-max-ttl: 240
serve-original-ttl: yes
```
This will serve the original TTL, but still skip the cache after `240` seconds, when a new query is made. (Note: Policies with TTL lower than 300 seconds are not elligible for prefetching.)

It ensures that when postfix-tlspol prefetches policies before the TTL actually expires, the DNS cache won't be used (otherwise it would only prefetch for the residual TTL time).

Prefetching will work without these settings, but a little less efficiently.
