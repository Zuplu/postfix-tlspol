## What's Changed in v1.8.17 (2025-09-05)

* fix: do not re-read `/etc/resolv.conf` on every single DNS request by @DragonWork
* build(deps): update toolchain to go1.25.1 by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.16...v1.8.17

## What's Changed in v1.8.16 (2025-08-31)

* fix: correctly cap 10-digit values (which are valid since 9ad53de) to upper limit in MTA-STS `max_age` per RFC 8461, 3.2 by @DragonWork
* feat: fallback to system resolver without dns.address by @mweinelt in [#73](https://github.com/Zuplu/postfix-tlspol/pull/73)
* refactor: rearrange imports by @DragonWork
* fix: fix MTA-STS policy parsing by @DragonWork
* chore(deps): bump actions/attest-build-provenance from 2.4.0 to 3.0.0 by @dependabot[bot] in [#75](https://github.com/Zuplu/postfix-tlspol/pull/75)
* build(deps): bump go.yaml.in/yaml/v4 from 4.0.0-rc.1 to 4.0.0-rc.2 by @dependabot[bot] in [#74](https://github.com/Zuplu/postfix-tlspol/pull/74)
* chore(release): update CHANGELOG.md by @DragonWork

## New Contributors
* @mweinelt made their first contribution in [#73](https://github.com/Zuplu/postfix-tlspol/pull/73)

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.15...v1.8.16

## What's Changed in v1.8.15 (2025-08-26)

* feat: allow `-export`ing in-memory database in postfix hash format
* refactor: lowercase domain names to standardize data as they are case-insensitive per RFC 4343
* fix: fine-tune prefetch algorithm
* fix: cap `max_age` to `math.MaxUint32` to prevent overflow
* chore: update dependabot.yaml
* fix: reject literal IP addresses in MTA-STS policy validation

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/7f83569...v1.8.15

## What's Changed in v1.8.14 (2025-08-23)

* Add CHANGELOG.md by @DragonWork
* Add release dates to CHANGELOG.md by @DragonWork
* Update toolchain to go1.25.0 by @DragonWork
* Remove external govalidator lib and use faster vanilla code by @DragonWork
* Fix DANE domains escaping prefetch algorithm because of low TTL returned from DNS resolver by @DragonWork
* Bump golang from 1.24.6-alpine3.22 to 1.25.0-alpine3.22 in /deployments in the docker group by @dependabot[bot] in [#68](https://github.com/Zuplu/postfix-tlspol/pull/68)
* Bump actions/checkout from 4.2.2 to 5.0.0 in the github-actions group by @dependabot[bot] in [#69](https://github.com/Zuplu/postfix-tlspol/pull/69)

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.13...v1.8.14

## What's Changed in v1.8.13 (2025-08-08)
* Bump docker/metadata-action from 5.7.0 to 5.8.0 in the github-actions group by @dependabot[bot] in [#61](https://github.com/Zuplu/postfix-tlspol/pull/61)
* Bump golang from `ddf5200` to `daae04e` in /deployments in the docker group by @dependabot[bot] in [#62](https://github.com/Zuplu/postfix-tlspol/pull/62)
* Bump the go-modules group with 2 updates by @dependabot[bot] in [#63](https://github.com/Zuplu/postfix-tlspol/pull/63)
* Update dependencies by @DragonWork
* Make systemd service file more compatible by @DragonWork
* Optimize prefetching and add counter for queries (use `-dump` to view) by @DragonWork
* Bump golang from 1.24.5-alpine3.22 to 1.24.6-alpine3.22 in /deployments in the docker group by @dependabot[bot] in [#65](https://github.com/Zuplu/postfix-tlspol/pull/65)
* Bump the github-actions group with 2 updates by @dependabot[bot] in [#66](https://github.com/Zuplu/postfix-tlspol/pull/66)

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.12...v1.8.13

## What's Changed in v1.8.12 (2025-07-09)
* Bump the github-actions group with 2 updates by @dependabot[bot] in [#58](https://github.com/Zuplu/postfix-tlspol/pull/58)
* Bump golang from 1.24.3-alpine3.21 to 1.24.4-alpine3.21 in /deployments in the docker group by @dependabot[bot] in [#57](https://github.com/Zuplu/postfix-tlspol/pull/57)
* Update and reduce dependencies by @DragonWork
* Make version tagging less strict for easier packaging on Debian by @DragonWork
* Update toolchain to go1.24.5 by @DragonWork
* Update Docker container base by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.11...v1.8.12

## What's Changed in v1.8.11 (2025-06-04)
* Bump docker/build-push-action from 6.16.0 to 6.18.0 in the github-actions group by @dependabot[bot] in [#53](https://github.com/Zuplu/postfix-tlspol/pull/53)
* Fix version tag regression by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.10...v1.8.11

## What's Changed in v1.8.10 (2025-05-12)
* Fix automated Docker build for x86-64-v1 by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.9...v1.8.10

## What's Changed in v1.8.9 (2025-05-08)
* Make log level (verbosity) configurable by @DragonWork
* Code cleanup by @DragonWork
* Finetune x86_64 feature level detection in build.sh by @DragonWork
* Fix minor typo in interactive build.sh when whiptail is not available by @DragonWork
* Bump the github-actions group with 3 updates by @dependabot[bot] in [#47](https://github.com/Zuplu/postfix-tlspol/pull/47)
* Update dependencies by @DragonWork
* Improve version tag derivation by @DragonWork
* Bump golang from 1.24.2-alpine3.21 to 1.24.3-alpine3.21 in /deployments in the docker group by @dependabot[bot] in [#48](https://github.com/Zuplu/postfix-tlspol/pull/48)
* Bump actions/setup-go from 5.4.0 to 5.5.0 in the github-actions group by @dependabot[bot] in [#49](https://github.com/Zuplu/postfix-tlspol/pull/49)
* Update toolchain to go1.24.3 by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.8...v1.8.9

## What's Changed in v1.8.8 (2025-04-09)
* Bump the github-actions group with 3 updates by @dependabot[bot] in [#41](https://github.com/Zuplu/postfix-tlspol/pull/41)
* Bump github.com/miekg/dns from 1.1.63 to 1.1.64 in the go-modules group by @dependabot[bot] in [#42](https://github.com/Zuplu/postfix-tlspol/pull/42)
* Bump golang from 1.24.1-alpine3.21 to 1.24.2-alpine3.21 in /deployments in the docker group by @dependabot[bot] in [#43](https://github.com/Zuplu/postfix-tlspol/pull/43)
* Update dependencies by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.7...v1.8.8

## What's Changed in v1.8.7 (2025-03-17)
* Bump docker/login-action from 3.3.0 to 3.4.0 in the github-actions group by @dependabot[bot] in [#40](https://github.com/Zuplu/postfix-tlspol/pull/40)
* Further optimizations, eliminate dangling goroutines and remove GC hacks by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.6...v1.8.7

## What's Changed in v1.8.6 (2025-03-17)
* Fix for wrong age calculation of cached entries by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.5...v1.8.6

## What's Changed in v1.8.5 (2025-03-17)
* Fix ever-increasing memory utilization by spawning ephemeral goroutines by @DragonWork
* Minor fix by @DragonWork
* Fix memory leak and further decrease memory usage down to ~10-15 MB by @DragonWork
* Fine tune GC by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.4...v1.8.5

## What's Changed in v1.8.4 (2025-03-15)
* Dump cache into pager when in terminal by @DragonWork
* Set maximum cache TTL to 30d and reject invalid format (overflowing uint32 considered invalid) in `max_age` attribute in MTA-STS policy by @DragonWork
* Minor bug fix and optimizations by @DragonWork
* Fix dysfunctional `-purge` command by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.3...v1.8.4

## What's Changed in v1.8.3 (2025-03-14)
* Fix missing version tag in automated Docker build by @DragonWork
* (Micro-)Optimize field alignment for better memory utilization by @DragonWork
* Disable caching of temporary errors and let Postfix decide when to retry by @DragonWork
* Fix undeleted socket file after termination by properly closing the socketmap server by @DragonWork
* Improve mutex in cache manager by @DragonWork
* Add `-dump` flag to view the cache and further optimizations by @DragonWork
* Even out prefetching attempts by @DragonWork
* Autoremove stale cached entries by @DragonWork
* Fix workflow by @DragonWork
* Fix prematurely deleted cache entries during dumping/viewing the cache contents. by @DragonWork
* Make queries retry once before responding with a temporary error by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.2...v1.8.3

## What's Changed in v1.8.2 (2025-03-10)
* Minor fix by @DragonWork
* Fix restarting systemd after build by @DragonWork
* Allow `NO_COLOR` and `NO_TIMESTAMP` environment variables for logging by @DragonWork
* Small improvements in Docker image building by @DragonWork
* Allow setting socket file permissions in config.yaml by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.1...v1.8.2

## What's Changed in v1.8.1 (2025-03-09)
* Hotfix for duplicated TLSRPT extensions by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.8.0...v1.8.1

## What's Changed in v1.8.0 (2025-03-08)
* Bump the github-actions group with 5 updates by @dependabot[bot] in [#21](https://github.com/Zuplu/postfix-tlspol/pull/21)
* Update README.md by @DragonWork
* Replace stuck dependency status badge by @DragonWork
* Bump actions/attest-build-provenance from 2.2.2 to 2.2.3 in the github-actions group by @dependabot[bot] in [#30](https://github.com/Zuplu/postfix-tlspol/pull/30)
* Bump golang from 1.24.0-alpine3.21 to 1.24.1-alpine3.21 in /deployments in the docker group by @dependabot[bot] in [#29](https://github.com/Zuplu/postfix-tlspol/pull/29)
* Update indirect dependencies by @DragonWork
* Remove Valkey/Redis database in favor of a new in-memory cache by @DragonWork
* Prefetch after expiration (and not before) to circumvent need for serve-original-ttl by @DragonWork
* Color output in logs only if bound to journald by @DragonWork
* Support selecting systemd/docker variant through first argument in scripts/build.sh by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.7.3...v1.8.0

## What's Changed in v1.7.3 (2025-03-01)
* Don‘t serve stale DNS answers in Docker image by @DragonWork
* Expired records break DNSSEC, thus DANE detection by @DragonWork
* Add packaging repositories to README.md by @DragonWork
* Bump the minor group with 2 updates by @dependabot[bot] in [#19](https://github.com/Zuplu/postfix-tlspol/pull/19)
* Bump the minor group with 2 updates by @dependabot[bot] in [#18](https://github.com/Zuplu/postfix-tlspol/pull/18)
* Configure Dependabot for less frequent updates by @DragonWork
* Relax Go version requirement and use more standardized install paths by @DragonWork
* The file `configs/config.yaml` gets moved to `/etc/postfix-tlspol/config.yaml` by @DragonWork
* The built executable is now installed to `/usr/bin` by @DragonWork
* Update Dockerfile for changed install paths by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.7.2...v1.7.3

## What's Changed in v1.7.2 (2025-02-22)
* Drop root permissions for Unbound in Docker build by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.7.1...v1.7.2

## What's Changed in v1.7.1 (2025-02-21)
* Bump golang from `3d74d23` to `2d40d4f` in /deployments by @dependabot[bot]
* Update README.md by @DragonWork
* Reduced cache latency by utilizing client-side caching of subsequent queries by @DragonWork
* Parallelized manual querying and testing by @DragonWork
* Added QUERYwithTLSRPT command to configure TLSRPT function via Postfix main.cf by @DragonWork
* Optimized compilation for amd64 processors by @DragonWork
* Bump docker/build-push-action from 6.13.0 to 6.14.0 in the minor group by @dependabot[bot]
* Format shell scripts and fix wrong CPU arch display (no functional effect) by @DragonWork
* Fix failing Docker container launch by @DragonWork

## New Contributors
* @dependabot[bot] made their first contribution

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.6.4...v1.7.1

## What's Changed in v1.6.4 (2025-02-17)
* Update README.md by @DragonWork
* Switch to Redis-compatible and open-source Valkey (Redis and KeyDB backends still work) by @DragonWork
* Update go-test.yaml by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.6.3...v1.6.4

## What's Changed in v1.6.3 (2025-02-15)
* Update GitHub Actions workflows by @DragonWork
* Add provenance attestation for built Docker images to harden supply chain by @DragonWork
* Update dependencies, including several security bug fixes within Docker base image by @DragonWork
* Create SECURITY.md by @DragonWork
* Add instructions for verifying automated Docker builds by @DragonWork
* Update dependabot.yaml by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.6.2...v1.6.3

## What's Changed in v1.6.2 (2025-02-12)
* Update build-docker.yaml by @DragonWork
* Parallelize multi-arch building for automated Docker releases by @DragonWork
* Update build-docker.yaml by @DragonWork
* Update toolchain to go1.24 by @DragonWork
* Code cleanup and Docker improvements by @DragonWork
* Fix hanging Docker build by @DragonWork
* Fix for failing Docker for good by @DragonWork
* Rollback to redis as keydb isn't available for all architectures yet by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.6.1...v1.6.2

## What's Changed in v1.6.1 (2025-02-10)
* Support listening on Unix Domain Sockets by @DragonWork
* Remove deprecated `policy_ttl` from TLSRPT extension by @DragonWork
* Code simplification by @DragonWork
* Add recommendation about explicitly setting `smtp_tls_dane_insecure_mx_policy` to `dane` by @DragonWork
* Update default config in README by @DragonWork
* Add flag for manual cache purging by @DragonWork
* Add instructions on how to persist Docker state/cache between updates by @DragonWork
* Update build-docker.yaml by @DragonWork
* Revert 1011736 by @DragonWork
* Minor changes by @DragonWork
* Update dependencies by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.6.0...v1.6.1

## What's Changed in v1.6.0 (2025-02-06)
* Fixed an issue of premature closing of the connection to Postfix after each request by @DragonWork
* Improved query parsing by @DragonWork
* Updated toolchain to go1.23.6 (includes security fixes) by @DragonWork
* Minor bug fix by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.5.5...v1.6.0

## What's Changed in v1.5.5 (2025-02-05)
* GitHub repository maintenance by @DragonWork
* Further cleanup by @DragonWork
* Fixes a MTA-STS policy parsing bug by @DragonWork
* Updated a dependency by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.5.4...v1.5.5

## What's Changed in v1.5.4 (2025-02-04)
* Return `dane` instead of `dane-only` when only some MX servers support DANE by @DragonWork
* Minor bug fix by @DragonWork
* Consider DANE-supporting MX records of a non-DNSSEC domain, and return `dane` (according to RFC 7672 Section 2.2.1 Paragraph 4) -> More DANE 🎉 by @DragonWork
* Minor bug fix and better code readability by using enums by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.5.2...v1.5.4

## What's Changed in v1.5.2 (2025-02-03)
* Add automated testing workflow for GitHub by @DragonWork
* Update go-test.yaml by @DragonWork
* Better testing by @DragonWork
* Updated build script by @DragonWork
* More detailed query script for manual debugging by @DragonWork
* Relaxed DNS error handling (strict option configurable) by @DragonWork
* Improved debugging with new query shell script by @DragonWork
* Updated dependencies by @DragonWork
* Minor bug fixes by @DragonWork
* Fix strict mode by @DragonWork
* Improved detection of domains that point to third-party MX servers with no proper DNSSEC support. This pre-detection prevents DNS errors and makes the new `strict` option obsolete, which is thus removed by @DragonWork
* Fixes false-positive DANE detection on non-DNSSEC domains (bug introduced in v1.5.0) by @DragonWork
* Minor bug fixes by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.4.4...v1.5.2

## What's Changed in v1.4.4 (2025-01-25)
* Added unit testing to ensure the core functions work before building (to prevent malfunction through a buggy version) by @DragonWork
* Reduced cyclomatic complexity for readability by @DragonWork
* Optimized prefetching by distributing the requests over time by @DragonWork
* Evaluation won't fail on first malformed MX record by @DragonWork
* Small bug fixes by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.4.3...v1.4.4

## What's Changed in v1.4.3 (2025-01-23)
* Build static binary by @DragonWork
* Replace mutex locking with channels by @DragonWork
* Fix wrong remaining TTL in logs for failing queries by @DragonWork
* Increase negative cache TTL by @DragonWork
* Introduce vendor folder for unifying dependencies inside the project by @DragonWork
* Optimized algorithm with cancelation of ongoing checks as soon as the policy is evaluated (DANE cancels ongoing TLSA checks and MTA-STS) by @DragonWork
* Reduced resource usage through recycling of objects by @DragonWork
* Better error handling by @DragonWork
* Fix version detection at build time for Docker by @DragonWork
* Small bug fixes by @DragonWork
* Hotfix for deadlocks and failing MTA-STS queries by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.4.0...v1.4.3

## What's Changed in v1.4.0 (2025-01-21)
* Restructured project to follow Go best practices by @DragonWork
* Added colored logging to stderr by @DragonWork
* More verbose error messages (e. g. details of DNS errors) by @DragonWork
* Small bug fixes by @DragonWork
* Fix automated Docker builds by @DragonWork
* Minor bug fixes by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.3.1...v1.4.0

## What's Changed in v1.3.1 (2025-01-20)
* Optimize prefetching algorithm by @DragonWork
* Enable prefetching by default by @DragonWork
* Update dependencies by @DragonWork
* Harden systemd service exposure by @DragonWork

**Full Changelog**: https://github.com/Zuplu/postfix-tlspol/compare/v1.3.0...v1.3.1

## All Other Changes from the initial upload until v1.3.0 (2025-01-17)
* Initial commit by @DragonWork
* Fix shell script permissions by @DragonWork
* Create FUNDING.yml by @DragonWork
* Update README.md by @DragonWork
* Disallow HTTP 3xx forwarding for MTA-STS and other code simplifications by @DragonWork
* Add preliminary support for Postfix 3.10+ TLSRPT feature for MTA-STS policies (must be explicitly enabled) and prohibit non-whitelisted chars in MTA-STS by @DragonWork
* Reformat config.yaml by @DragonWork
* Improved validation by @DragonWork
* Add option to disable caching; add further checks by @DragonWork
* Restructured codebase for readability by @DragonWork
* Fix typos in README.md by @DragonWork
* Increase minimum requirements by @DragonWork
* Bump minimum Go version to 1.23.0 to include security fixes by @DragonWork
* Require TLSv1.2 or higher when fetching the MTA-STS policy by @DragonWork
* Add code quality badge to README.md by @DragonWork
* Support prefetching (must be enabled, see README) by @DragonWork
* Search multiple TLSA records per MX server for `dane-only` support before returning `dane` in case of unsupported parameters by @DragonWork
* Log remaining cache TTL for queries by @DragonWork
* Optimizations for prefetching by @DragonWork
* Add CodeQL badge in README.md by @DragonWork
* Override config.yaml only if it does not exist and add support for Go 1.22.7+ by @DragonWork
* Fixed cached tempfail response by @DragonWork
* Add badges to README.md by @DragonWork
* Merge branch 'main' of github.com:Zuplu/postfix-tlspol by @DragonWork
* Adding Docker support by @DragonWork
* Fixed a bug in the Dockerfile by @DragonWork
* Fix failing automated CodeQL build by @DragonWork
* Minor fix in Docker image creation by @DragonWork
* Add instructions to pull and use prebuilt Docker images by @DragonWork
* Fix default port in `docker run` command in the instructions by @DragonWork
* Add workflow to automate Docker image deployment by @DragonWork
* Fix workflow context by @DragonWork
* Resetting workflow by @DragonWork
* Make workflow manually dispatchable by @DragonWork
* Fix typo in workflow file by @DragonWork
* Add missing checkout to workflow by @DragonWork
* Pin workflow actions to harden security by @DragonWork
* Update build-docker.yaml by @DragonWork
* Support more architectures in multi-platform Docker image by @DragonWork
* Enable workflow only for tagged releases by @DragonWork
* Harden Docker container by running everything as non-root by @DragonWork
* Make TLSRPT option changeable without disrupting cache by @DragonWork
* Allow configuring Prefetch and TLSRPT option via environment variables (useful for Docker) by @DragonWork
* Update dependencies (includes security fixes) by @DragonWork

---

<p align="center">
  <sub><em>🐉 Proudly developed by <strong>Ömer Güven</strong> (aka <strong>DragonWork</strong>) for 
  <a href="https://www.zuplu.com">Zuplu</a> and the Open Source Community.<br>
  ☕ Support my work: <a href="https://paypal.me/drgnwrk">paypal.me/drgnwrk</a></em></sub>
</p>
