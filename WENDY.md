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
