# ReadyStack security maintenance of Consul v1.16.4

This repository is HashiCorp Consul at tag `v1.16.4` (commit `2b5841d3f6243fc9b24a5f223daeef69761e0317`,
2023-12-12), the last Consul release under the Mozilla Public License 2.0 (`LICENSE`). Every later release
(1.16.5 onward, 1.17 onward) is under the Business Source License 1.1 and is not open source. ReadyStack
packages this version as `readystack/consul` and fixes the vulnerabilities found in it on the branch
`readystack/v1.16.4`. It contains only the MPL-2.0 history up to `v1.16.4` and ReadyStack's commits on top.

All changes are MPL-2.0, like the files they modify. No code from HashiCorp's BUSL-licensed releases was read
or copied: each fix was written from the public advisory and the documented behaviour of the libraries
involved (Envoy for the two L7-intention fixes).

| Commit on `readystack/v1.16.4` | Fixes | What it changes |
|---|---|---|
| agent/dnsutil: internalize CoreDNS ExtractAddressFromReverse | CoreDNS advisories matched by version only | Consul used one stdlib-only CoreDNS function; it is copied (Apache-2.0, `agent/dnsutil/LICENSE.coredns`) and the CoreDNS module is no longer linked. No behaviour change. |
| agent/xds: normalize request paths (CVE-2024-10005) | [GHSA-chgm-7r52-whjj](https://github.com/advisories/GHSA-chgm-7r52-whjj), HCSEC-2024-22 | Envoy `normalize_path` and `merge_slashes` on every HTTP connection manager Consul generates. |
| agent/xds: header rules fail closed (CVE-2024-10006) | [GHSA-5c4w-8hhh-3c3h](https://github.com/advisories/GHSA-5c4w-8hhh-3c3h), HCSEC-2024-23 | Header rules in L7 intentions: deny-direction rules also match any one of several values and other letter case; allow-direction rules require every value to match. See `agent/xds/rbac_header_hardening.go`. |

Behaviour changes an operator may notice: the path the application receives is the normalized one (dot
segments resolved, duplicate slashes merged); a deny header rule now also matches values that differ only in
letter case, and requests that repeat a header (or list several values) where any value hits a deny rule or
one value misses an allow prefix, suffix or regex rule.

Tests: `go test ./agent/xds/... ./agent/structs/...` passes on this branch and on pristine `v1.16.4` (Go 1.26).
`agent/xds/rbac_header_hardening_test.go` shows each header bypass matching the v1.16.4 matcher and not the
fixed one.

Release tags `v1.16.4-cve-rN` are signed with the SSH key below and are immutable (repository ruleset).
Verify one with:

    echo 'johntdavenport@exceed.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKFITIEiczSFeJFzF2oaR1zXqP1m1ariW4aQzxyirfvN' > allowed_signers
    git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag v1.16.4-cve-r1

The `readystack/consul` image's release notes list the tag and commit each release is built from. Report a
problem to security@readystack.dev.
