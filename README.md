# postfix-tlspol

A lightweight MTA-STS and DANE/TLSA resolver and TLS policy socketmap server for Postfix that complies to the standards and prioritizes DANE where possible.

# Requirements

- A redis compatible database
- Postfix
- Go 1.19+

# Install

```
cd /opt
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
