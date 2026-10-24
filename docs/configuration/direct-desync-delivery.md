# Direct desync delivery and verification status

This page records the delivery boundary, the accepted compatibility limits, the
build prerequisites and the actual verification status of the direct outbound
desync implementation. It describes the standalone console core for Ubuntu and
Windows, started from an externally generated ordinary sing-box configuration.
Desktop integration, desktop RPC/protocol/schema, services, installers and the
mVPN UI/generator are out of scope and are not part of this delivery.

## Supported boundary

- Console core on Ubuntu (linux/amd64) and Windows (windows/amd64), configured
  through the ordinary `direct` outbound `desync` object documented in
  [`direct-desync.md`](direct-desync.md),
  [`direct-desync-stream.md`](direct-desync-stream.md) and
  [`direct-desync-transport.md`](direct-desync-transport.md).
- Packet rules need the native packet backend and its capture privileges.
  Stream-only objects need neither a packet backend nor capture privileges.
- Deferred `tcp_fast_open` is available on Linux and Windows only; other
  platforms fail the deferred attempt with an actionable error instead of
  silently disabling TFO.

## Accepted compatibility limits

The following two combinations are accepted sing-box integration limitations
(user decision, 2026-10-24). Both keep an explicit refusal on the configuration
or attempt path; neither is silently disabled, emulated with a fallback, or
reimplemented as subflow ownership:

| Combination | Behaviour |
|---|---|
| Linux packet desync + `tcp_multipath` | Refused before network I/O with an actionable error. Ordinary MPTCP use and the allowed stream-only configurations remain supported. |
| `tcp_fast_open` + a first send that needs `MSG_OOB` or low-TTL disorder | Refused before the exchange with an actionable error. Ordinary deferred TFO and the other supported combinations remain supported. |

These are limits of the sing-box integration. They are not a claim that
bol-van/zapret universally forbids those combinations, and not a claim of
parity for every combination. See the compatibility and limits section of
[`direct-desync.md`](direct-desync.md), the deferred-TFO guard in
[`direct-desync-stream.md`](direct-desync-stream.md) and the transport controls
in [`direct-desync-transport.md`](direct-desync-transport.md).

## Build prerequisites

The console build path is documented in
[`direct-desync-socks-build.md`](direct-desync-socks-build.md). It is not a
plain `go build`:

- The accepted SOCKS wire-provenance repair is a hash-locked downstream patch to
  the pinned `github.com/sagernet/sing` module. A build must prepare an isolated
  verified dependency copy with the shipped
  `release/patches/prepare-sing-socks-wire.py` helper and build with the
  generated alternate modfile. An ordinary build uses the unmodified cached
  module and does not contain the contract.
- Every Windows console build requires unmodified **Go 1.26.9**, qualified with
  `release/check-windows-adoption-go.py`, plus the `release/LDFLAGS` linker
  settings. The requirement applies even when desync is disabled at runtime,
  because the adoption constructor is compiled into the binary.

## Verification performed

The reviewed implementation is Git tree
`0f668c8ee7133abae5d83bcbd25edb4026b8e178` on base
`d7a2091c66ea732cb5fdc040cb9cbafcfac9909d` (published as checkpoint commit
`e6aafface7ef1753f2fc288015e92e5a147f81c8`). The canonical base-to-tree delta is
3,310,010 bytes, SHA256
`52d11d9c15ecd93bfb1b52f2bd37d308cd4109333fa5f5bd8db887d36c839b0a`. This
documentation update does not change any implementation, test, build or
dependency blob of that tree.

| Stage | Identity | Result on the exact tree |
|---|---|---|
| Focused QA | tester-max, card `t_fd038a7f`, run 385 | PASS: unit and race suites, vet, Windows test compilation, JSON-to-constructor network matrix, the shipped SOCKS helper and console build chain, both console binaries compiled only (never executed), and native Windows socket/ownership controls on a Windows Server 2022 guest (35/35 probe tests and 26/26 delivered/control tests, loopback sockets only, no WinDivert driver or network change). |
| Security recheck | security reviewer, card `t_b31640e2`, run 387 | Scoped PASS: the multicast admission finding is closed and the cumulative UDP ownership, retained-state and reporting paths were rechecked. |
| Combined technical review | reviewer-max, card `t_a689feb9`, run 389 | Combined technical PASS with no blocking defect. No new security boundary was authorized. |

Native evidence is attributed rather than rerun for this documentation update:
earlier isolated Linux lab QA runs exercised the real NFQUEUE and socket
ownership paths on their own earlier trees (for example tester-max
`t_4b46e50f`, native Ubuntu NFQUEUE N1, 9/9), and the focused QA above ran the
native Windows controls on the test guest. Those results are not a fresh
execution on this documentation revision. Command and log records stay with the
corresponding task reports.

## Not executed

The following remain unverified execution gaps, not missing implementation.
They are reported as SKIP/NOT_EXECUTED and are not claimed as PASS:

- WinDivert driver and wire behaviour of the Windows packet capture path.
- Present WLAN and SSID/NLM activation behaviour.
- Real application traffic: YouTube playback, Discord voice, Telegram
  messaging/uploads and WarDogs connection/gameplay.
- O3 conditional suffix native reachability.
- Post-grace retained ConnectEx behaviour.
- Native ambiguous-close and socket-reuse outcomes.

No full wire-level or application-level equivalence with the reference
implementation is claimed.
