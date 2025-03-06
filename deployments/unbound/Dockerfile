FROM mvance/unbound

RUN cat <<EOF >/opt/unbound/etc/unbound/unbound.conf
server:
  username: _unbound
  chroot: ""
  do-daemonize: no
  use-syslog: no
  verbosity: 1
  access-control: 0.0.0.0/0 allow
  log-servfail: yes
  log-queries: yes
  ede: yes
  interface: 0.0.0.0
  port: 53
  do-ip4: yes
  prefer-ip4: yes
  do-ip6: yes
  prefer-ip6: no
  do-udp: yes
  do-tcp: yes
  max-udp-size: 1232
  edns-buffer-size: 1232
  auto-trust-anchor-file: "var/root.key"
  cache-min-ttl: 10
  cache-max-ttl: 240
  serve-original-ttl: yes
  serve-expired: no
  prefetch-key: yes
  prefetch: yes
  hide-identity: yes
  hide-version: yes
  target-fetch-policy: "4 3 2 2 1"
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-algo-downgrade: yes
  harden-below-nxdomain: no
  harden-referral-path: no
  harden-large-queries: no
  harden-short-bufsize: yes
  harden-unknown-additional: no
  aggressive-nsec: no
  val-permissive-mode: no
  unknown-server-time-limit: 1500
  jostle-timeout: 1000
  discard-timeout: 4000
  so-reuseport: yes
  num-threads: 2
  qname-minimisation: no
  minimal-responses: yes
  infra-cache-min-rtt: 4500
  infra-keep-probing: yes
  module-config: "validator iterator"
remote-control:
  control-enable: no
EOF

RUN chown _unbound:_unbound /opt/unbound/etc/unbound/unbound.conf \
 && chmod 0400 /opt/unbound/etc/unbound/unbound.conf


