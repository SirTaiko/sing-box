# Direct outbound packet desync

`desync` is an optional object on an ordinary `direct` outbound. It is not an
outbound type, it has no `profile` selector and it never interprets tags. An
absent or disabled object keeps the exact existing direct path: no engine,
capture registration, reassembly buffers or extra goroutines are created.

```json
{
  "type": "direct",
  "tag": "zapret",
  "desync": {
    "rules": [
      {
        "network": ["tcp"],
        "port": [443],
        "protocol": ["tls"],
        "methods": ["fake", "multisplit"],
        "fake": {
          "repeats": 8,
          "fooling": ["ts"],
          "payloads": [{ "protocol": "tls", "file": "bin/stun2.bin" }]
        },
        "multisplit": {
          "split_pos": ["1"],
          "seqovl": 664,
          "seqovl_pattern": "bin/tls_clienthello_www_sferum_ru.bin"
        }
      }
    ]
  }
}
```

The engine is byte-oriented and owns native packets only for sockets owned by
that direct outbound. Every native dial attempt, including losing parallel
attempts, receives its own lease: local port, capture registration, counters,
reassembly and cancellation. UDP listener leases keep independent state per
peer; a cutoff on one peer never affects another.

## Rule fields

| Field | Meaning |
|---|---|
| `name`, `disabled` | diagnostics and explicit rule skip |
| `network` | `tcp`, `udp` or both (listable) |
| `ip_version` | `4`, `6` or both (listable) |
| `port`, `port_range`, `port_exclude`, `port_range_exclude` | destination port predicates; ranges are `from-to` |
| `protocol` | `http`, `tls`, `quic`, `wireguard`, `dht`, `discord`, `stun`, `unknown` |
| `domain`, `domain_file`, `domain_exclude`, `domain_exclude_file` | zapret host/subdomain semantics: an entry matches the host and all subdomains; a `.example.com` entry matches subdomains only; exclusions win. While the hostname is unknown a rule whose positive or exclusion hostlist holds an effective entry cannot match (pinned `dp_match`/`PROFILE_HOSTLISTS_EMPTY`, where a file without entries contributes nothing); a rule whose hostlists stay empty is an ordinary catch-all, and `learning` rules are exempt |
| `ip_cidr`, `ip_cidr_file`, `ip_cidr_exclude`, `ip_cidr_exclude_file` | positive/negative IP prefixes. A positive `"any"` (inline or in a list file) removes the positive IP restriction only; a negative `"any"` excludes every destination; other predicates and exclusions still apply. An omitted positive source is unrestricted, and a positive IP aggregate that resolves to no entries (empty or comment-only file, empty selected bundle dataset) also imposes no positive-IP restriction, as in pinned zapret v72.9 (`old behavior compat: all include lists are empty means check passes`). A positive domain list that resolves to no entries still matches nothing |
| `methods` | ordered list of implemented stages: `fake`, `multisplit`, `multidisorder` (TCP); `fake` (UDP) |
| `start`, `cutoff` | upstream spelling `nN` (packets), `dN` (data packets), `sN` (sequence span); zero/unset is unlimited |
| `any_protocol` | disable protocol/SNI selection for this rule |
| `skip_no_sni` | default `true`; a protocol/host rule does not match before L7 information exists, and a completed QUIC ClientHello without a usable `server_name` extension is passed untouched even when this rule carries `any_protocol` |
| `ip_id` | `zero` implements the ALT11 zero IPv4 ID contract; other upstream modes are rejected in this increment |
| `fake` | `payloads`, `repeats`, `fooling`, `ts_increment`, `ttl`, `seq` |
| `multisplit`, `multidisorder` | `split_pos`, `seqovl`, `seqovl_pattern` |

`split_pos` accepts `N`, `-N` and marker forms `method`, `host`, `endhost`,
`sld`, `endsld`, `midsld`, `sniext` with an optional `+N`/`-N` offset. Numeric
zero is rejected. `seqovl` accepts an integer byte count or a position string.
`sniext` anchors on the first byte of the `server_name` extension body (the
two-byte name list length after the four-byte extension header), exactly like
the pinned `TLSPos` (`nfq/protocol.c:462-470,549-554`); a ClientHello without
that extension has no `sniext` position at all.

Each fake payload sets exactly one byte source: `file`, `hex` or `base64`, plus
an optional `offset`. Relative payload and list paths resolve through the
configuration path context (`filemanager.BasePath`), the same seam other
sing-box file options use; a caller without that context keeps process-relative
resolution, and a missing file is a compile error rather than an empty payload.
Payloads are read once at compile time, bounded to 9216 bytes and hashed; no
runtime downloads exist.

The optional `limits` object bounds native resources. Defaults follow the
architecture safety envelope: 4096 active leases, 256 KiB reassembly per flow,
256 held originals and 256 KiB held bytes per flow, 64 MiB held bytes per
engine, and a 250 ms incomplete-message hold deadline. `hold_timeout` accepts a
duration string and must be within `(0s, 10s]`; `max_held_bytes` must hold at
least one MTU. Unset fields keep their defaults; invalid values are rejected
rather than accepted as no-ops.

```json
"limits": {
  "max_leases": 4096,
  "max_reassembly_bytes": 262144,
  "max_held_packets": 256,
  "max_held_bytes": 262144,
  "max_held_bytes_total": 67108864,
  "hold_timeout": "250ms"
}
```

`max_leases` is the bound of **two independent ceilings** of one Engine:

- **Attempt admission** — the charged native attempts of that Engine (open
  attempts plus closed attempts whose native resources are still owned) stay
  within `max_leases`.
- **UDP peer state** — the sum of per-destination packet-UDP states across all
  packet-enabled leases of that Engine, listener and connected UDP alike, stays
  within the same value.

The two ceilings do not add up. One admitted listener can own up to
`max_leases` peer states, and peer state never consumes an attempt slot: with
`max_leases=1` a listener is admitted and still serves its first peer. Each
distinct captured destination tuple of a packet-enabled lease owns one peer
state, and that state (and its charge) is retained until the owning lease
closes and every in-flight user of it finished. Semantic conntrack expiry,
conntrack eviction, list reload, inactivity and rule cutoffs do not restore peer
capacity; there is no idle timer, LRU eviction or separate knob. Allocation is
first-admitted with no fairness between listeners. A destination-less UDP
listener scopes every peer by its complete captured tuple (family, local
address/port, peer address/port), so semantic counters and cutoffs stay per
peer.

When the peer allowance is exhausted, a datagram for a new destination is
passed untransformed: it is never injected, held, modified, completed, replayed
or turned into a lease error, and the listener keeps running. Already admitted
peers keep working, and capacity returns only when leases close. This is
exhaustion, not successful desync — the configured bypass/tamper behaviour is
lost for those additional destinations. State-only UDP (a stream-only outbound,
no packet backend) owns no peer state and no admission charge at all.

## Semantics implemented in this increment

- Fake payloads are emitted payload-major: two payloads A, B with `repeats=2`
  produce A, A, B, B. Every fake is sent at the captured packet's sequence and
  the original packet passes; `seq` advances the sequence by a payload's length
  only after all of that payload's repeats (upstream
  `--dpi-desync-fake-tcp-mod=seq`, `nfq/desync.c:1972,2002-2008`). Split methods
  suppress the original.
- `multisplit` emits ascending real intervals. `seqovl` applies only to the
  first interval of the reassembled request (`i == 0 && reasm_offset == 0`): the
  overlap pattern is prefixed and the TCP sequence is reduced by the overlap.
- `multidisorder` emits descending real intervals. The overlap belongs to the
  interval whose loop index is `0`, i.e. the interval that begins at the first
  split boundary, and only when `overlap < that interval's start`; otherwise it
  is cancelled exactly as upstream does.
- `fooling: ["ts"]` modifies TSval only, using a signed 32-bit increment
  (default `-600000`); TSecr is retained. If the captured packet has no
  timestamp option, the fake is sent without the modification (upstream does
  not synthesize timestamps).
- `ip_id: "zero"` builds a zero IPv4 ID and, on Linux, installs an owned
  nftables priority rule that clears the ID after kernel normalization and
  updates the IPv4 checksum. On Windows the WinDivert send path transmits the
  built header as-is.
- Semantic counters count eligible original-direction captured packets from
  capture registration: `n` includes retransmits, `d` counts data-bearing
  packets, `s` is `seq_last - seq0` in unsigned 32-bit arithmetic, exactly as
  upstream returns it (`nfq/desync.c`). `seq_last` is the last observed
  sequence, so an out-of-order retransmission moves it backwards; a reply feeds
  `seq_last` from its ACK and keeps separate reply counters. Empty outgoing
  ACKs are excluded by default (`capture.tcp_empty_ack` overrides this).
  Injected fakes and replacements are never recounted.
- TLS and HTTP messages are assembled across packets and TLS records before
  symbolic split positions are resolved. While a structured message is
  incomplete the captured originals are held; on completion one whole
  replacement batch per held original is planned in capture order and only then
  are the originals suppressed. Unknown traffic is never held.
- Holds are bounded by the `limits` above. On deadline expiry, budget
  exhaustion, cancellation, socket close or backend failure every held original
  is released unchanged in capture order, transformations are latched off for
  the rest of that message and no replay is counted. A released message never
  waits for a large initial flight.
- Reply packets of the owned tuple are captured on both platforms with their
  direction preserved: Linux uses a separate narrowly scoped INPUT queue,
  Windows a second explicitly inbound WinDivert handle. Replies feed
  handshake/sequence/ack/window observations only; a Linux inbound packet is
  never re-egressed through the raw injection socket.
- NFQUEUE delivery disables GSO (`NFQA_CFG_GSO` masked off) so captured packets
  are wire-shaped before counters or transformations. Linux uses the fixed
  persistent anchors described below: at most two tables (`ip`/`ip6 sb_desync`)
  and four base hooks (LOCAL_IN/LOCAL_OUT, filter, priority -150, policy accept)
  per already-used network namespace, independent of capture count or restarts.
  A capture owns only its regular chains, tagged entries and queue bindings;
  queue sockets explicitly bind a nonzero high-bit netlink port and control
  metadata sockets explicitly bind a nonzero low-bit port, so no class ever
  autobinds or steals the other's port. A foreign queue, table or hook is never
  bound, deleted, unbound, disabled or replaced. On Windows the send path clears
  the checksum-valid metadata so the driver materialises IPv4/TCP/UDP checksums
  from the bytes actually sent.
- UDP protocol classification is a byte-exact port of the pinned upstream
  dissectors: QUIC Initial structure, WireGuard 148-byte handshake initiation,
  bencoded `d1:...e` DHT, Discord IP-discovery request and STUN. QUIC hostname
  facts come from decrypting the Initial (HKDF/AES-GCM/header protection) and
  defragmenting its CRYPTO frames; a datagram that does not authenticate yields
  no hostname. Media-port guesses are not used.
- QUIC fake units follow the pinned delayed-replay admission
  (`nfq/desync.c:2905-3044`), not one unit per datagram of the flow: while a
  connection's CRYPTO ClientHello is incomplete the authenticated Initials are
  held in the existing per-peer hold queue (bounded by the `max_held_*` budget
  and the absolute `hold_timeout`) and the cycle owns no fake unit. When the
  cycle completes, exactly one configured fake burst is emitted before the
  oldest held original and the queued originals are then replayed in capture
  order, each with its own single native disposition and its exact captured
  bytes. The ordered selection at capture time is provisional only in the
  hostname predicates: family, transport, address, port, protocol and limit
  facts must already match, while a non-empty domain set or domain exclusion
  cannot be evaluated before the ClientHello is decrypted. Such a profile owns
  the bounded cycle; the validated hostname then re-runs the ordered selection
  from the top of the profile list, and a higher-priority rule, an exclusion or
  no final rule flushes the whole cycle without the provisional rule's burst.
  Traffic that is definitively ineligible on its non-host facts is never held.
  A datagram the QUIC session refuses cancels the reassembly: the queued
  originals are flushed unchanged, and only a rule with the explicit
  `any_protocol` bit (`desync_any_proto`) continues to tampering with the
  refused datagram. Reassembly-resource exhaustion, exclusions, `skip_no_sni`,
  an ended limit interval and a closed lease are not that permission and pass
  the originals. A completed ClientHello whose `server_name` extension is
  absent yields no hostname fact and honours `skip_no_sni` (default `true`)
  even for an `any_protocol` rule; a present extension with an empty
  `host_name` entry is a known-empty hostname. Only CRYPTO fragments are
  deduplicated; captured duplicate datagrams are always distinct originals.
- A fake stage reachable for UDP that has no QUIC payload gets the pinned
  `dp_fake_defaults` payload: exactly 620 bytes, `0x40` followed by 619 zero
  bytes (`params.c:265-271`). An explicitly configured QUIC payload replaces
  the default, and the existing payload order, multiplicity and repeats are
  kept. The unknown-payload path is unchanged (`fakeknown` still requires a
  recognized protocol). These defaults are source-derived from the pinned
  reference, not measured from a live run.
- A narrowly scoped reply path observes reverse packets of the owned tuple. It
  feeds bounded handshake/window/hop facts, and applies the two reply-side
  transformations the pinned source performs before its reverse-direction
  return: the obsolete `wsize` SYN-ACK window rewrite and the in-place
  `synack_split=syn` ACK clear. Inbound packets are never re-egressed through a
  raw socket on Linux; Windows delivers the rewrite on the same inbound handle
  so direction and `IfIdx` are preserved. `wssize`, `orig`, `dup` and the
  fake/split families are original-direction only and never touch replies.
- Source-faithful `orig`/`dup` limiters use the upstream orig-direction `n`
  (packet), `d` (data-packet) and `s` (relative sequence) counters. Cutoffs
  latch: once reached they stay reached even when a retransmission moves an
  `s` limit backwards. Generated, duplicated and replayed packets never
  increment the counters.
- Bounded reassembly (256 KiB default) discards duplicate retransmitted bytes.
  Exhaustion releases the original packet, disables transformations for that
  flow and reports a reason; it never holds unrelated traffic.
- A failed replacement batch releases the original packet and latches the flow,
  so user bytes are never lost. Cancellation, socket close and engine shutdown
  release the capture's own queues and tagged rules idempotently; the fixed
  persistent anchors and their `a`/`t` markers remain for every later capture
  of that namespace.

## Stage grammar and packet modifiers

`methods` is the upstream `<mode0>,<mode>[,<mode2>]` stage list. Aliases are
accepted with their upstream meaning (`split`/`disorder` → `fakedsplit`/
`fakeddisorder`, `split2`/`disorder2` → `multisplit`/`multidisorder`). A zero
stage may stand alone (`syndata`) or be followed directly by a second stage
(`syndata,multidisorder`): upstream consumes the zero token first and parses the
remaining mode slots independently, so the first stage is optional between them.
Invalid order, duplicate stages, unknown methods and unsupported transports stay
rejected.

| Stage | Names | Transport | Planned behaviour |
|---|---|---|---|
| zero | `synack`, `syndata` | TCP | fake SYN-ACK (`TH_SYN|TH_ACK`, fake TTL/fooling), or a SYN carrying the upstream 16-byte fake data (skipped for TFO/payload SYN) |
| first | `fake`, `fakeknown`, `rst`, `rstack` | TCP/UDP | fake payloads (fakeknown requires a recognized protocol), RST / RST+ACK decoys |
| first | `hopbyhop`, `destopt`, `ipfrag1` | TCP/UDP | upstream IPv6-only extension-header modes; on IPv4 they do not apply. They are final only when no second stage follows, exactly as upstream |
| second | `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `ipfrag2` | TCP | split/disorder families, fake-pattern altorder, host/SNI split with a fake hostname and optional `midhost`, two real fragments at an 8-byte aligned transport position |
| second | `udplen`, `tamper`, `ipfrag2` | UDP | datagram length change with pattern, DHT D1→D2 tamper, fragmentation |

Rule-level typed modifiers apply to every generated packet and never require a
fake object: `ttl`, `ttl6`, `autottl`/`autottl6` (`delta:min-max`, evaluated
from the observed reply hop count), `tcp_flags_set`/`tcp_flags_unset`, `fooling`
(`none`, `ts`, `badseq`, `badsum`, `md5sig`, `datanoack`, `hopbyhop`,
`hopbyhop2`), `repeats`, `ts_increment`, `badseq_increment`,
`badack_increment`, `ip_id` (`zero`, `seq`, `seqgroup`, `rnd`, `same`) and
`ipfrag_pos_tcp`/`ipfrag_pos_udp`. TLS fake payloads accept
`tls_mod` (`none`, `rnd`, `rndsni`, `sni=<host>`, `dupsid`, `padencap`).

`orig` rewrites TTL/flags of the captured original in the native disposition
(IPv4 `ttl`/IPv6 `ttl6`, with the upstream IPv6 fallback to the IPv4 value,
autottl, and checksums refreshed); `mod_start`/`mod_cutoff` use the upstream
`nN`/`dN`/`sN` limiters. `dup` sends `count` duplicates with their own
TTL/flags/fooling/IP-ID: the upstream raw-copy path preserves the exact captured
option bytes when no header/fooling/IP-ID change is requested, otherwise the
segment is reconstructed. `dup` has `start`/`cutoff` limiters of its own,
independent from the rule `start`/`cutoff` and from `orig`. `dup.replace`
suppresses the original only after every duplicate was sent; a partial send
failure falls back to delivering the original bytes. `wsize` is the obsolete
SYN-ACK-only window selector; `wssize` is the original-direction server-window
rewrite with `wssize-cutoff` (`nN`/`dN`/`sN`, default `n`) and
`forced_cutoff` (default true; latch the rewrite off once a complete
ClientHello/HTTP request is known). A configured window scale can only be
lowered, exactly like upstream. `synack_split=syn` clears TH_ACK in place;
`synack_split=synack|acksyn` replaces an original-direction SYN-ACK with its
SYN and ACK parts in the selected order.

`hostfakesplit` splits the request at the Host/SNI value boundaries
(`host`/`endhost`), inserts a fake hostname segment of the same length, and
optionally adds the `midhost` split. `mod` accepts `host=<hostname>` (reuse or
pad the configured host) and `altorder=0|1`; without a configured host the fake
name is generated with the upstream alphabet/TLD rules. The real segments still
reconstruct the exact request bytes.

Mutually conflicting combinations are rejected: `rndsni` with `sni=`, a
transport-inapplicable stage, out-of-order or duplicated stages, and any field
this schema does not implement. Upstream fields that do not exist in the pinned
source (for example a `hostfakesplit.split_pos` list, `orig.start`/`orig.cutoff`
or `dup.ip_id=seqgroup`) are rejected by strict decoding instead of being
silently ignored.

## Examples

Expanded reference presets are in `docs/examples/desync/`:

- `general.json` — Flowseal `general.bat`
- `alt2.json`, `alt6.json`, `alt11.json` — the corresponding Flowseal presets
- `direct-vpn-coexistence.json` — normal direct, an upstream VPN outbound and a
  desync-enabled direct outbound together

They use the pinned release payload file names. Payloads are **not**
redistributed here; acquire them from Flowseal 1.10.4
(`176f56dc3f11ce5915c26abcdde903f93d835b64`) or bol-van/zapret v72.9
(`c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`), verify the hashes in
`docs/examples/desync/provenance.sha256`, and set the paths accordingly.

The Flowseal `service.bat` IPSet **any** mode ships an effectively empty
positive list: these examples therefore express "IPSet any" by omitting the
positive `ip_cidr` list while keeping every exclusion, port, hostlist and
per-rule condition. An explicit `"any"` entry (inline or in a list file) is the
equivalent positive wildcard; a negative `"any"` excludes every destination.
Release `ACTIVE_*` payload bytes are the Flowseal defaults;
the user's local `ACTIVE_*.bin` overrides are unknown and are not claimed.

## Capture selectors

`capture` narrows what the owned capture registration accepts. Every selector
is intersected with the owned native socket tuple: it can never widen capture,
and a selector that excludes the owned attempt is a configuration error at
capture start, never a silent no-op.

```json
{
  "capture": {
    "tcp_empty_ack": true,
    "network": ["tcp"],
    "ip_version": [4, 6],
    "port_range": ["443", "8000-8100"],
    "port_exclude": [8080],
    "linux": {
      "qnum": 5000,
      "fwmark": 3,
      "bind_fix4": true,
      "bind_fix6": true,
      "packet_limits": {"tcp_out": 8, "tcp_in": 0, "udp_out": 8, "udp_in": 0},
      "tcp_keepalive_port_range": ["80"],
      "udp_keepalive_port_range": []
    }
  }
}
```

- `network`, `ip_version`, `port`, `port_range`, `port_exclude`,
  `port_range_exclude` are the portable selectors (upstream
  `--wf-l3/--wf-tcp/--wf-udp` equivalent). They are re-checked at runtime
  dispatch in addition to the ownership envelope.
- `linux.qnum` is the explicit NFQUEUE identity (`--qnum`, upstream range
  0..65535). It is range-validated at compile time, refused if another listener
  already owns it or another live capture of this process reserved it, and its
  in-process reservation is released only after the retirement receipts below
  prove the queue is gone. Absent keeps the managed allocator.
- `linux.packet_limits.{tcp_out,tcp_in,udp_out,udp_in}` mirror upstream
  `NFQWS_*_PKT_*`. Absent is unlimited capture of that direction, an explicit
  `0` disables capture of that direction, and `N` keeps the first `N` packets
  as counted inclusively by the kernel conntrack (`ct ... packets 1-N`), not by
  the semantic rule `cutoff`. The limit lives in the capture-owned dispatch or
  queue rule of the fixed table, so anchor ownership and cleanup are unchanged.
  Outgoing bounds use `ct original packets`; a positive `tcp_in`/`udp_in` bound
  uses `ct reply packets 1-N`, the actual reply-direction kernel counter, and
  is never replaced by the original direction. The reply rule is encoded with
  the pinned expression encoders plus the one direction attribute the pinned
  `github.com/sagernet/nftables v0.3.0-mod.4` omits for packet/byte counters; a
  batch the kernel rejects is an activation error, never a silently unlimited
  reply direction.
- `filter_ttl_expired_icmp` (default `false`) mirrors upstream
  `FILTER_TTL_EXPIRED_ICMP` with the accepted ownership narrowing: an
  ICMP/ICMPv6 time-exceeded error is suppressed only when its quoted inner
  packet is this attempt's own outbound low-hop packet. The quote is parsed
  strictly (IPv4 and IPv6, no non-first fragments, no inner extension headers,
  complete L4 ports); a foreign tuple, a truncated/malformed quote, a reply-side
  quote and any parameter-problem/PMTU message pass unchanged. The lease must be
  live (its generation) and must actually have injected a replacement. Linux
  installs an additional tagged NFQUEUE entry in the fixed table's input base
  chain that jumps to the capture-owned ICMP chain (family, time-exceeded type,
  owned interface and, when the local address is concrete, the quoted inner
  source address at its fixed offset); Windows opens an additional owned
  WinDivert time-exceeded handle scoped by the local address or the owned
  interface index. Neither platform ever installs a global ICMP drop rule:
  unmatched packets are re-injected/accepted.
- `linux.tcp_keepalive_port_range`/`linux.udp_keepalive_port_range` mirror
  `NFQWS_PORTS_*_KEEPALIVE` with the existing port-range grammar. A destination
  port in the range removes only the outgoing packet bound, exactly like the
  source's separate `keepalive` rule set; the inbound bound is unchanged.
- `linux.fwmark` is OR-ed into the routing mark of the owned socket for
  generated packets (upstream `desync_fwmark`); dialer-owned mark bits are
  never cleared.
- `linux.bind_fix4`/`linux.bind_fix6` mirror upstream
  `--bind-fix4/--bind-fix6`: the raw injection socket is bound to the generated
  packet's source address (and keeps the owned `SO_BINDTODEVICE`). A refused
  bind is ignored, as upstream does, so sending still uses the owned device.
- The interface dimension is never configured: it is the actual device of the
  owned native attempt (`SO_BINDTODEVICE` on Linux, the interface index on
  Windows), taken from the socket and used for both the IP cache key and the
  capture rule/isolation.

### Linux persistent-anchor lifecycle

Linux captures share one fixed set of nftables anchors per already-used network
namespace (the ordinary process namespace plus the configured, actually used
`netns` targets, deduplicated by pinned `(st_dev,st_ino)`):

| Object | Exact shape |
| --- | --- |
| table | `ip sb_desync` and `ip6 sb_desync` |
| base chains | `input`/`output`, type `filter`, hooks LOCAL_IN/LOCAL_OUT, priority `-150`, policy `accept` |
| marker chain | `__sbds_v1`, regular and unreferenced by any packet path |
| fixed markers | one RETURN rule `sbds:1:a:<family>:<epoch>` and one `sbds:1:t:<epoch>:<nexttag>` per family |
| capture objects | regular chains `c_<capture>_o/i/e`, tagged `entry-*`/`inject` rules in the base chains, tagged `queue-*` rules in the capture chains, and `m`/`p` records in the marker chain |

First enable creates the table, marker chain, `a` and `t` atomically with
`NLM_F_EXCL` before any hook; each missing base chain is then created in its own
EXCL transaction. The only rollback is the kernel-internal abort of the
currently uncommitted initial hook creation. A committed anchor is never
deleted, disabled, replaced or made dormant by ordinary operation, and
`Close`, process exit or an empty queue are never permission to remove it.
Full anchor removal stays separate external maintenance. Initialization errors
are explicit and no per-flow rule is attached before the anchors are READY.

A capture publishes a tagged manifest and a transient port record (`o`) before
its private queue socket exists, binds an explicit high-bit queue port under
the process-wide fork lock, binds `outq`, and durably publishes the `w` witness
before releasing that lock. Retirement is ordered and receipt-driven: exact
tagged entries are detached and read back; a separate zero-mutation
BEGIN/GETGEN/END batch yields the only accepted negated-`EINVAL` enqueue fence
(a lost reply repeats the no-mutation operation); the receive lane is joined,
drained, a no-attribute CONFIG on each own queue returns its ACK0, non-witness
queues are unbound explicitly, and only then is the owning socket closed with
`outq` still bound. A fresh kernel absence query plus a fresh
`nfnetlink_queue` read (or a genuine different-port row) is the witness
release-scan receipt. Exact own chains and `m`/`p` are removed last, before the
positive capture-retired receipt; the irreversible per-family tag high-water
stays. An unproven effect keeps the same record, queue/port reservation, lease
charge and endpoint and reports an incomplete close; it never becomes a silent
success. The last owner also closes its owner-liveness socket and proves the
exact abstract name is free before its final record is erased. When recovery
observes a matching live process it leaves that owner untouched; unknown
process visibility, an orphan guard or a busy inherited guard retains the
record and refuses a new generation instead of appending one.

### Windows capture (`capture.windows`)

Windows-only controls mirror upstream `winws` and are applicable only with the
WinDivert backend; a `capture.windows` block on another platform (or
`capture.linux` on Windows) is an explicit configuration error.

```json
{
  "capture": {
    "windows": {
      "wf_iface": "12.0",
      "wf_l3": ["ipv4"],
      "wf_tcp": ["443", "8000-8100", "~8080"],
      "wf_udp": ["443"],
      "wf_raw_part": ["tcp.Syn or tcp.PayloadLength > 0"],
      "filter_lan": true,
      "filter_save": "/var/log/sing-box/desync-filter.txt",
      "ssid_filter": ["HomeWifi"],
      "nlm_filter": ["Home network", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"]
    }
  }
}
```

- `wf_iface` is the upstream numeric interface/subinterface filter
  (`<int>[.<int>]`). It is intersected with the interface index the owned
  native attempt was actually bound to, queried from the socket
  (`IP_UNICAST_IF`/`IPV6_UNICAST_IF`) and resolved through
  `GetAdaptersAddresses`; a mismatch is refused before the driver opens.
- `wf_l3` selects `ipv4`/`ipv6` (absent = both, like upstream).
- `wf_tcp`/`wf_udp` are upstream `[~]port[-port]` lists. Outbound criteria use
  the destination port, inbound criteria the source port, exactly like
  `wf_make_pf`.
- `wf_raw` is a full WinDivert expression that replaces `wf_tcp`, `wf_udp` and
  `wf_raw_part`; mixing them is refused rather than silently ignored.
  `wf_raw_part` entries are OR-ed, like upstream.
- Every raw expression is parsed and compiled to the driver's instruction
  format by the in-tree compiler (`common/windivert`). It is then AND-ed with
  the owned envelope — direction, family, exact tuple, owned interface index —
  and with the non-LAN exclusion. No expression, including one using `or` or
  `not`, can widen capture beyond the owned socket; malformed or unsupported
  fields are explicit errors.
- `filter_lan` (default `true`) excludes non-global destination addresses for
  outbound and non-global source addresses for inbound packets.
- `filter_save` writes the composed filter text for both directions once, at
  capture activation, with mode `0600` and a bounded size. Absent writes
  nothing; configuration compilation never writes.
- `ssid_filter`/`nlm_filter` gate processing on the current WLAN SSID and
  Network List Manager network (name or GUID), like upstream
  `--ssid-filter`/`--nlm-filter`. The gate is queried at most once per second;
  while it is inactive or the query fails, every captured packet passes
  unchanged and cleanup/close behaviour is unaffected. Query errors are
  reported through `Engine.ActivationStatus`.
- Typed entrypoints for later explicit tooling: `Engine.QueryWindowsNetwork`
  (WLAN/NLM/adapter snapshot) and `Engine.CaptureFilterDump` (composed filter
  text and instruction count). Neither opens a native capture or writes files.

## Conntrack, IP cache and list reload

Two optional top-level objects mirror the upstream ctrack/ipcache controls and
are scoped to one direct outbound:

```json
{
  "type": "direct",
  "tag": "zapret",
  "desync": {
    "conntrack": {
      "disabled": false,
      "max_entries": 4096,
      "timeouts": {"syn": "60s", "established": "300s", "fin": "60s", "udp": "60s"}
    },
    "ip_cache": {"hostname": true, "lifetime": "2h", "max_entries": 4096},
    "rules": []
  }
}
```

- `conntrack` is the upstream semantic conntrack (`--ctrack-timeouts`,
  `--ctrack-disable`). The defaults are the source defaults 60/300/60/60
  seconds. Entries are bounded, expire on the per-state idle timeout
  (purge interval 10 s) and are independent from owned-socket cleanup.
  `disabled: true` keeps socket ownership and cleanup but makes start/cutoff
  limits unavailable, exactly like upstream running with a missing ctrack
  entry: a configured `start` blocks, cutoffs are never latched.
- `ip_cache` is the upstream ipcache (`--ipcache-lifetime`,
  `--ipcache-hostname`). Lifetimes default to the source 7200 s; an explicit
  `0` means "no expiration". Hostnames are learned only from validated L7
  facts (authenticated QUIC Initial, parsed TLS ClientHello, parsed HTTP
  request) and are keyed by the exact destination address plus the owned
  native-attempt interface (`SO_BINDTODEVICE`/dialer interface), so a host
  learned on one interface is never served to another attempt. A cached host
  carries the upstream `hostname_is_ip` marker: an IP literal matches hostlists
  exactly and never expands subdomains. `hostname` is opt-in; hop estimates
  feed `autottl`, `orig.autottl` and `dup.autottl` before the current flow sees
  a reply. Nothing is persisted.
- Domain/IP list files are read as unions. Plain text and gzip snapshots are
  accepted (bounded expansion), with `#`, `;` and `/` comment lines (pinned
  `nfq/hostlist.c`), blank lines and CRLF ignored and case/trailing dots
  normalized. A positive IP aggregate that resolves to no
  entries imposes no positive-IP restriction (pinned zapret v72.9
  compatibility), while an empty positive domain list still matches nothing.
  `Engine.ReloadLists` re-reads every source
  transactionally: packet lists, stream lists and the configured learned-file
  state are staged and published as one new selection snapshot. On any
  read/format/gzip/hash/budget error the last-good snapshot (all three parts and
  the list revision) stays active and the error is returned to the caller (a
  deliberate isolation adaptation; upstream exits the process). The per-outbound
  `list_revision` starts at 1 and increments once per successful *changed*
  publication. Existing connections keep the snapshot they selected; new
  selections use the new one. There is no signal handler, watcher, scheduler or
  background updater; the explicit entrypoints are the existing
  `Engine.ReloadLists` and, when the optional controller is safely configured,
  `sing-box tools desync reload`. The hostlist-auto snapshot is additionally
  re-read only when its size, modification time or mode changed since the last
  successful read or publish, so an unchanged file never replaces an in-memory
  learned set (upstream watches append+modtime; the transactional last-good read
  is the accepted adaptation).
- Legacy file reads are bounded before allocation: the regular-file size is
  checked first and the byte stream is then limited (4 MiB per file). The
  compiled snapshot additionally enforces one per-outbound selection budget of
  512 MiB decoded and 4,194,304 unique records across all selected sources
  (bundle datasets and legacy files), so a configuration cannot exceed memory
  limits by combining many individually valid files.

### Provider list bundles

`list_bundle` selects immutable datasets of a generation published by
`sing-box tools desync list-refresh`. The same reusable object is accepted by
packet rules and stream matches:

```json
{
  "type": "direct",
  "tag": "zapret",
  "desync": {
    "rules": [{
      "network": ["tcp"],
      "methods": ["multisplit"],
      "multisplit": {"split_pos": ["1"]},
      "list_bundle": {
        "manifest": "lists/current.json",
        "domain": ["hosts", "user_hosts"],
        "domain_exclude": ["exclude_hosts"],
        "ip_cidr": ["ip4", "user_ip4"],
        "ip_cidr_exclude": ["exclude_ip4"]
      }
    }],
    "stream_rules": [{
      "name": "stream-bundle",
      "list_bundle": {"manifest": "lists/current.json", "domain": ["hosts"]},
      "methods": ["split"],
      "split": {"split_pos": "1"}
    }]
  }
}
```

- `manifest` is required (relative paths resolve against the configuration base
  path). At least one dataset id must be selected; ids are unique and must match
  the dataset kind (`domain` arrays select `kind: domain`, `ip_cidr` arrays
  select `kind: ip` and the rule's IP families).
- `current.json` is read **once per distinct canonical bundle root per
  compile/reload**. The same pinned generation is used by every packet and
  stream rule of that outbound. Only the immutable generation directory it
  points at is read; no network, DNS or watcher participates.
- Every referenced dataset is verified (manifest, shard names, hashes, entry and
  byte limits) before publication. An explicitly selected empty domain dataset
  is a positive restriction that matches nothing; an all-empty positive IP
  aggregate (bundle datasets and/or `ip_cidr` files) adds no positive-IP
  restriction.
- A provisioned nonempty exclusion dataset (`exclude_hosts`, `exclude_ip4`,
  `exclude_ip6`) that is relevant to a selected positive must be selected in the
  matching negative array; otherwise the configuration is rejected instead of
  silently dropping exclusions. Exclusions always win over positives, including
  a positive list file on the same rule.
- Inline (`domain`, `ip_cidr`) and file (`domain_file`, `ip_cidr_file`) fields
  stay additive with exactly their previous semantics. The shared selection
  budget above applies to the combined set.
- A reload failure leaves the previous generation, the previous stream rules,
  the learned state and the revision active. There is no partial publication and
  no network code in the compiler.

- The sticky start/cutoff latches and the hostlist-auto request/retransmission
  counter (upstream `req_retrans_counter`, finalized request range and
  `hostname_ah_check`) live on the retained tuple entry, as they do on the
  upstream `t_ctrack`: a second concurrent or reused native attempt on the same
  tuple continues the same counter, a fresh SYN (`ConntrackReInitTrack`) clears
  it and tuple expiry discards it. Only captured originals feed the counters;
  generated and replayed packets never recount.
- A semantic TCP entry is created only for a source-valid SYN or SYN-ACK, and
  for every UDP datagram, exactly like upstream conntrack. An owned flow whose
  first captured packet is mid-stream keeps its socket ownership, capture
  registration and cleanup, but has no semantic counters: start limits block,
  cutoffs are never latched and no state is restarted from zero. This replaces
  the former mid-stream first-attach adaptation.

### Hostlist-auto learning (packet)

The opt-in hostlist-auto behavior of nfqws is available for packet rules. One
engine (one direct outbound) owns the learned set and the failure cache next to
conntrack/ipcache; configuration loading itself stays read-only.

```json
{
  "desync": {
    "learning": {"path": "/var/lib/sing-box/zapret-auto.txt", "max_hosts": 4096},
    "rules": [{
      "network": ["tcp", "udp"],
      "any_protocol": true,
      "methods": ["fake"],
      "learning": {"fail_threshold": 3, "fail_time": "60s", "retrans_threshold": 3}
    }]
  }
}
```

- Rule-level `learning` enables the upstream auto profile: the rule matches
  first, a known host that is neither explicitly listed nor learned keeps the
  original untouched while failures are counted, and once learned the host is
  eligible like a positive hostlist entry. `domain_exclude` always wins and is
  never learned. An auto profile is exempt from the unknown-hostname hostlist
  gate, so it stays selectable before any hostname is visible.
- Thresholds are the source ones: `fail_threshold` 1..20 (default 3),
  `fail_time` 1..255 s (default 60 s), `retrans_threshold` 2..10 (default 3).
  Explicit zeros are rejected; absent values keep the defaults. Fail windows
  expire with upstream's rate-limited purge; reaching the threshold adds the
  normalized hostname once (duplicates are rechecked) and deletes the counter.
- A RST or an HTTP 302/307 redirect to a different second-level domain for the
  first-sequence reply counts as a failure; any other reply payload resets the
  fail counter. TCP request retransmissions and later UDP datagrams for an
  eligible host drive the retransmission threshold.
- `learning.path` is the only persistence opt-in. It is a plain hostname
  snapshot (gzip is rejected, as upstream), bounded by `max_hosts` (default
  4096) and a 1 MiB read limit. Writes are atomic owner-private `0600`
  snapshots; symlinks and non-regular files are refused, a second active
  writer on the same canonical path is rejected, and construction errors leave
  an existing file untouched. `Engine.ReloadLists` re-reads it
  transactionally; a malformed snapshot keeps the last-good set. `debug_log`
  is a separate explicit opt-in and must be an owner-private regular file.
  Without both fields nothing is persisted and no host is logged.


## Compatibility and limits

- Enabled packet desync rejects `tcp_multipath`, `bind_address_no_port` and
  `reuse_addr` with actionable errors: additional subflow ownership and no-port
  semantics are outstanding parity gaps against exclusive pre-SYN ownership, and
  an owned packet UDP endpoint must be exclusive because capture identifies a
  flow by its local endpoint and cannot distinguish two sockets that share it.
  The `reuse_addr` conflict is refused before any desync state is created (no
  list/payload read, engine, capture or attempt charge); absent/disabled and
  stream-only configurations keep `reuse_addr` unchanged.
- Enabled packet desync also rejects a multicast `inet4_bind_address` or
  `inet6_bind_address` with an actionable error naming the option and the
  address. This is an additive compatibility restriction: a multicast local bind
  is not exclusive even with `reuse_addr:false`, because the standard library's
  multicast UDP listen path makes the endpoint shareable and binds the wildcard
  address (verified against the pinned POSIX implementation), so the resulting
  endpoint can be co-owned by another socket that tuple-based capture cannot tell
  apart. The classification is semantic
  (multicast address semantics, IPv4-in-IPv6 spellings unmapped), not a textual
  match, and the refusal is applied from the configuration on every supported
  platform before any desync state exists, rather than relying on
  platform-specific socket behaviour after a bind. Ordinary listeners that do
  not enable packet desync keep their multicast binds unchanged; absent,
  explicitly `enabled:false`, stream-only and all-packet-rules-disabled
  configurations keep them too, and unicast bind addresses are unaffected.
  `tcp_fast_open` is implemented for ordinary packet and stream configurations
  through the owned deferred attempt described in `direct-desync-stream.md`:
  no socket, no capture and no SYN exists before the first transformed send,
  and exactly one prepared `TCP_FASTOPEN_CONNECT`/ConnectEx attempt then carries
  that first segment. It is available on Linux and Windows only; other
  platforms fail the deferred attempt with an actionable error instead of
  silently disabling TFO. The `network_strategy`/`tcp_fast_open` conflict is
  unchanged, because a racing resolver cannot own a deferred pre-SYN attempt.
- `direct.desync.stream_rules` is the independent tpws-equivalent stream list.
  Stream-only objects are valid and require no packet backend. Stream rules are
  applied on every owned TCP attempt before kernel serialization, so packet
  capture (when both are enabled) sees the transformed packets; UDP and bound
  UDP listeners are unchanged. See `direct-desync-stream.md` for the complete
  stream grammar and the attachment model.
- A connection that also carries route `tls_desync`, `tls_fragment` or
  `tls_spoof` is rejected before user data for packet, stream and combined
  configurations; those legacy options continue to work on other routes and
  outbounds.
- `IsEmpty()` is false whenever packet or stream desync is enabled, so detour
  validation and direct optimizations never bypass the attachment. TCP/UDP
  `PreMatchContinue` and ICMP flow handling are unchanged.
- Status of the rows outside the packet/stream core: stream
  cache/learning/`tamper_in` (D4) and the explicit provider acquisition/list
  bundle path (D5) are implemented and covered by the existing unit suites;
  diagnostics and explicit reload are exposed through the existing console
  surfaces (`desync diagnostics`, `desync reload`, `desync list-refresh`); the
  Windows capture selectors (`capture.windows.wf_iface/wf_l3/wf_tcp/wf_udp/
  wf_raw/wf_raw_part/filter_lan/filter_save`, SSID and NLM activation) are
  implemented, compile on Windows and are validated hermetically. Their
  WinDivert driver and wire behaviour, and present-WLAN/SSID activation, were
  not executed; native Windows socket and ownership controls were exercised on
  a Windows Server 2022 test guest during the focused QA run. The UDP
  second-stage `fooling_orig` handling of `udplen`/`tamper`/`ipfrag2`
  (including the IPv6 extension chain), the tuple-owned conntrack cutoff
  latches with SYN/SYN-ACK-only TCP track creation, and the IP-cache
  `hostname_is_ip` marker with the interface-scoped key are implemented and
  covered by focused tests; the cache stays in memory exactly as documented
  above. The two remaining compatibility rows are accepted sing-box integration
  limitations (user decision, 2026-10-24), not open decisions: Linux packet
  desync combined with `tcp_multipath`, and `tcp_fast_open` with a first send
  that would need `MSG_OOB`/low-TTL disorder, are each rejected with an
  actionable error before network I/O and never silently disabled. Ordinary
  MPTCP use and the allowed stream-only configurations remain supported, and
  ordinary deferred TFO and the other supported combinations are unchanged.
  These refusals are not a claim that upstream zapret universally forbids
  those combinations, and not a claim of parity for every combination (see
  [`direct-desync-delivery.md`](direct-desync-delivery.md) for the delivery and
  verification record).
  Native wire and application evidence remains unverified (SKIP), not missing
  implementation; [`direct-desync-delivery.md`](direct-desync-delivery.md)
  lists the exact executed and not-executed checks. Accepted stage names never
  silently no-op: an unimplemented field, method or mode is rejected at compile
  time.

### Retained native admission

Packet and stream rules of one outbound share the single Engine, so admission
is already bounded by `limits.max_leases` (default 4096 for both packet and
stream-only objects; stream-only `capture`/`limits` remain rejected). A native
stream sender keeps a reference to its already charged attempt until a proven
terminal completion, so a closed attempt whose native resources are still owned
keeps its slot: `active_leases` counts charged attempts, not open connections.
The bound is per Engine instance/generation, not process-global, and it bounds
retained attempts/events/waiters rather than bytes. Admission refusal matches
`desync.ErrAdmissionRefused` and never falls back to plain I/O.

### Windows receive progress and saturation

Each Windows packet capture has one independent outbound native reader and one
serial disposition worker. A synchronous held-original release can block that
worker without blocking the next native receive. The worker preserves outbound
receive-order dispatch and fake-before-original ordering. This is not a global
wire-order guarantee across independent peer timers or inbound/ICMP handles.

The private staging limits are **256 records and 8 MiB of raw bytes per capture**,
plus one **65,575-byte receive scratch** and full 80-byte addresses. Reservation
precedes an exact-capacity packet copy. Copy-in-progress, queued, in-service,
semantic-held and unknown-completion records all share the same limits: dequeue
or `Hold` does not release a reservation. Both a known terminal disposition and
the worker's final nonuse are needed. This storage is separate from the existing
semantic held-byte budgets (including UDP's semantic copies).

Exhaustion is an explicit, sticky capture failure, not normal backpressure or a
silent drop. The already-received overflow record stays in the single scratch;
further endpoint operations through connected UDP, listener and cached
`RawConn.Write` gates fail without entering the underlying call. Already-admitted
operations keep their actual return values and completion responsibilities. One
RawConn callback can emit many packets; a returned Write is not a matched native
receive receipt. **Lossless delivery is not promised for traffic still below
native receive at saturation.** After failure the same worker drains the older
records, then borrows the same scratch one record at a time. There is no recovery
to ordinary service, allocation of another overflow queue, packet retry or
replacement endpoint on that lease.

Close still fences semantic dispatch, joins old dispatch and held completions,
releases ordered pass-through, joins endpoint producers, issues once-only
`ShutdownRecv`, and requires `ERROR_NO_DATA` for every opened lane plus all
reader/worker/callback joins and native `Done` receipts. A partial open drains
each successfully opened handle too; zero started users is not proof of an empty
native queue. The caller's two-second bound reports `ErrLeaseCloseIncomplete`
without cancelling an original. A later proven safe retirement can release the
endpoint while the capacity/delivery error remains nonnil. Unknown completion
instead retains records, native resources, the charged lease and the actual
endpoint reference. Ordinary resume never clears the sticky failure.

Allocation is lazy: an idle capture owns descriptors and scratch, not 8 MiB of
packet data. The new logical staging allowance is at most
`8 MiB + 65,575 + 257*512 + 16 KiB = 8,602,151 bytes` per capture (512 bytes per
record includes descriptors/ring/callback metadata; 16 KiB covers fixed
bookkeeping). The existing outbound native receive shadow adds another 65,575
bytes. Existing optional-lane/native buffers, semantic/parser state, goroutine
stacks, allocator rounding, garbage awaiting collection and kernel queues are
additional; this is **not an RSS bound**. With the default 4096 `max_leases`, raw
staging alone could reach **32 GiB per Engine** if every capture fills its budget.
Multiple Engines add their ceilings; this is not an 8 MiB process cap. Retained
unsafe captures continue to consume the existing lease allowance.

The permanent offline regression uses the actual Windows reader/worker, Lease,
QUIC release and returned direct wrappers with scripted native boundaries. Its
reversible overlay generator is
`common/desync/testdata/windows_receive_model.py`; tests require the
`desync_windows_model` build tag on Linux. Those results are source/model
evidence, not native Windows, downstream PCAP or public-application acceptance.

## Provenance and licenses

No upstream payload, list or executable bytes are redistributed in this
repository. `docs/examples/desync/provenance.sha256` pins every referenced
release file from Flowseal 1.10.4; the presets were expanded from the pinned
BAT files at commit `176f56dc3f11ce5915c26abcdde903f93d835b64`. Upstream
bol-van/zapret is MIT (copyright 2016–2024 bol-van). Flowseal is MIT with
bol-van/Flowseal attribution; its WinDivert component is distributed under
LGPLv3 or GPLv2 alternatives. This tree reuses the existing sing-box WinDivert
wrapper and does not redistribute the driver beyond what the repository
already contains. Review attribution before publishing any payload fixtures.
