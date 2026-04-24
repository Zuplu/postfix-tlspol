# postfix-tlspol

[![GitHub Release](https://img.shields.io/github/v/release/Zuplu/postfix-tlspol)](https://github.com/Zuplu/postfix-tlspol/releases/latest) [![GitHub License](https://img.shields.io/github/license/Zuplu/postfix-tlspol)](https://github.com/Zuplu/postfix-tlspol/blob/main/LICENSE) [![CodeQL Badge](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Zuplu/postfix-tlspol/actions/workflows/github-code-scanning/codeql/) [![Go Report Card](https://goreportcard.com/badge/github.com/Zuplu/postfix-tlspol)](https://goreportcard.com/report/github.com/Zuplu/postfix-tlspol) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/98f114fa07ac4daa89495e5248d4c76b)](https://app.codacy.com/gh/Zuplu/postfix-tlspol/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) [![Automated Docker Build](https://img.shields.io/github/actions/workflow/status/Zuplu/postfix-tlspol/build-docker.yaml?branch=main&logo=docker&logoColor=white&label=Docker&color=%232496ED)](https://hub.docker.com/r/zuplu/postfix-tlspol/tags) [![Dependabot Badge](https://img.shields.io/badge/dependabot-enabled-0366D6?logo=dependabot&logoColor=white)](https://github.com/Zuplu/postfix-tlspol/actions/workflows/dependabot/dependabot-updates)

[<img src="https://zuplu.com/mascot.svg" width="140em" align="right" alt="Gopher Mascot" />](#)

A lightweight and highly performant MTA-STS + DANE/TLSA resolver and TLS policy socketmap server for Postfix that complies to the standards and prioritizes DANE where possible.

## New: Prometheus Metrics & Grafana Dashboard

[<img src="https://zuplu.com/dashboard.png" width="140em" align="right" alt="Grafana Dashboard" />](#)

The socketmap listener auto-detects HTTP and exposes `/metrics` on the same Unix/TCP socket, including Go runtime metrics and counters for `dane`, `dane-only`, and `secure` (MTA-STS) results.

<br/><br/><br/><br/>

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
  - DANE is authoritative when fresh and usable. MTA-STS is only used when fresh DANE state explicitly proves that no DANE policy is available.
  - Temporary DANE failures do not downgrade to MTA-STS. TLSA records must be explicitly and verifiably not available for MTA-STS to overrule DANE.
  - MTA-STS and DANE state are cached independently, so a later refreshed DANE result immediately overrides a still-fresh MTA-STS policy.
  - If there is no TLSA record available for at least one MX record, so that the DANE query returns an empty policy, then the MTA-STS policy will take effect and result in a `secure` policy and explicitly enforce a `match=` with the policy-provided MX hostnames.

- DANE and MTA-STS branches are cached by `minimum TTL of all DNSSEC/DANE queries` and MTA-STS `max_age` seconds respectively. The served result is derived from the fresh branch state on every cache hit, with mandatory DANE (`dane-only`) taking precedence.

It is recommended to still set the default TLS policy to `dane` (Opportunistic DANE) in Postfix (see below).

# Install packaged version

List of repositories serving prebuilt and packaged versions of postfix-tlspol:

[![Packaging status](https://repology.org/badge/vertical-allrepos/postfix-tlspol.svg?exclude_sources=modules,site)](#)

# Install via Docker

Installation with Docker simplifies setup, as it contains its own properly configured DNS resolver, `Unbound`. The image itself is only about 8 MB (compressed).

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

To update the image, stop and remove the container, and run the `docker run ...` command again.

To disable prefetching, pass `-e TLSPOL_PREFETCH=0` to the above command.

# Install from source

## Build a Docker container from source

```
git clone https://github.com/Zuplu/postfix-tlspol
cd postfix-tlspol
scripts/build.sh
```
Press _d_ for Docker when prompted or select it if a terminal UI appears.

## Standalone

### Requirements

These requirements only apply if you use the non-Docker variant for installation, i. e. as a systemd service unit.

- Postfix
- Go (latest)
- DNSSEC-validating DNS server (preferably on localhost)

### Build and install

```
git clone https://github.com/Zuplu/postfix-tlspol
cd postfix-tlspol
scripts/build.sh
```
Press _s_ for systemd when prompted or select it if a terminal UI appears.

Edit `/etc/postfix-tlspol/config.yaml` as needed. After any change, a restart is required:
```
service postfix-tlspol restart
```

# Postfix configuration

In `/etc/postfix/main.cf`:

### Before Postfix 3.10

```
smtp_dns_support_level = dnssec
smtp_tls_security_level = dane
smtp_tls_dane_insecure_mx_policy = dane
smtp_tls_policy_maps = socketmap:inet:127.0.0.1:8642:QUERY
```

<details>
  <summary><b>Explanation for <code>smtp_tls_dane_insecure_mx_policy</code></b></summary>

  This bug has been fixed in [Postfix stable release 3.10.0](https://www.postfix.org/announcements/postfix-3.10.0.html), as well as in [Postfix legacy releases 3.9.2, 3.8.8, 3.7.13, and 3.6.17](https://www.postfix.org/announcements/postfix-3.9.2.html) and all subsequent newer releases. *You do not need to manually set this, if you use one of these or more recent versions.*

  Explicitly setting <code>smtp_tls_dane_insecure_mx_policy</code> to <code>dane</code> is a workaround for a bug that only matters in case you change the recommended default <code>smtp_tls_security_level</code> to something different than <code>dane</code>.

  postfix-tlspol returns <code>dane</code> (opportunistic DANE) only for domains where <code>dane-only</code> (mandatory DANE) is not possible (because the MX lookup is unsigned, but the MX server itself supports DANE). Not setting this would render <code>dane</code> ineffective and only honor <code>dane-only</code>, if your <code>smtp_tls_security_level</code> is not <code>dane</code>. So even when postfix-tlspol explicitly requests opportunistic DANE for a domain, Postfix would ignore it before the fix.
</details>

### For Postfix 3.10 and later

```
smtp_dns_support_level = dnssec
smtp_tls_security_level = dane
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

_*Warning:* Configuring is only available for the standalone/systemd installation. The Docker version is autoconfigured._

Configuration example for `/etc/postfix-tlspol/config.yaml`:
```
server:
  # server:port to listen as a socketmap server
  # or unix:/run/postfix-tlspol/tlspol.sock for Unix Domain Socket
  address: 127.0.0.1:8642

  # socket file permissions if Unix Domain Sockets are used
  socket-permissions: 0666

  # prefetch when TTL is about to expire (default true)
  prefetch: true

  # cache file (default /var/lib/postfix-tlspol/cache.db)
  cache-file: /var/lib/postfix-tlspol/cache.db

dns:
  # must support DNSSEC, uses /etc/resolv.conf if unset
  #address: 127.0.0.53:53
```

# Prefetching

Prefetching is enabled by default, and postfix-tlspol tries to keep its cache fresh.
