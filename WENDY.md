# Wendy QUIC configuration patches

This branch tracks upstream quic-go v0.62.0, commit
`793f74d8e03368c5aded128af6f48d21dbb47f73`. The upstream module path and MIT
license are unchanged. WendyOS consumes an immutable revision of this fork.

## Configurable CRYPTO stream size

`Config.MaxCryptoStreamSize` bounds the total received CRYPTO data at each
encryption level, including data already consumed by TLS. Zero retains
upstream's 16 KiB default. Nonzero values below RFC 9000's 4096-byte minimum or
beyond the QUIC offset range are rejected;
the configured size is not preallocated. Both clients and servers apply it to
Initial, Handshake and 1-RTT CRYPTO streams.

WendyOS explicitly opts into 64 KiB for its device and app sessions because
Cloud v2 enrollment presents a legitimate 23,740-byte DER certificate chain.
Authentication, principal pinning, trust anchors and the transmitted TLS chain
are unchanged. The generic option is independent of Wendy's certificate format.

Config and connection regressions cover the unchanged default, configuration
copying, invalid offsets, every encryption level on both endpoint roles, large
flight acceptance and rejection after consuming the configured limit. WendyOS
also exercises real signed large chains and mutual authentication.

Keep the two Wendy patches as separate commits on the selected upstream
release. Rebase them onto a newer release, review the upstream delta and rerun
dependency and WendyOS integration tests before changing the pinned revision.
Retire this patch when upstream supports a sufficient configurable bound.

## Application-supplied initial RTT

The second patch adds optional `Config.InitialRTT` and uses that estimate for
initial loss recovery. Zero preserves the upstream 100 ms default. A real RTT
measurement replaces the estimate; this is not a minimum RTT, handshake
deadline or application timeout. Missing token estimates cannot erase a
configured seed. Negative configuration values are rejected.

WendyOS opts app sessions into a one-second estimate while investigating
premature probes and repeated setup traffic on multi-hop BLE paths. Other
callers retain their existing defaults. Authentication and zero-RTT policy
are unchanged.

Focused regressions cover config population/cloning, default and seeded probe
timeouts, absent token estimates, and replacement by a measured RTT:

```sh
go test -race -count=50 -run 'TestInitialRTT|TestNonpositiveInitialRTT|TestConfigClone|TestConfigDefaultValues' . ./internal/utils
```

Upstream tracks the initial-estimate option in
[#3754](https://github.com/quic-go/quic-go/issues/3754), with API lifecycle
questions in [#3862](https://github.com/quic-go/quic-go/issues/3862). Retire the
RTT patch when upstream exposes a suitable option and uses the estimate for
initial recovery. Both this and the configurable certificate-flight requirement must be
satisfied before WendyOS can return to an unmodified upstream release.
