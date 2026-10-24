# Direct desync — stream rules (`tpws` transformations)

`direct.desync.stream_rules` is the ordered tpws-equivalent stream rule list. It
is selected independently from the packet list `direct.desync.rules` and runs
before kernel TCP serialization, so packet capture (if also enabled) sees the
actual resulting TCP packets. Stream and packet rules use the same typed
matching grammar; this document covers only the stream subsystem.

Implementation status: the compiled stream subsystem, HTTP/TLS transformations,
native socket controls and wrapper are implemented and unit-tested in
`common/desync/stream*.go` and `option/direct_desync_stream.go`. The top-level
`direct.desync.stream_rules` field, stream-only configuration, per-attempt
`PrepareSocket` and exactly-once `WrapConn` are attached on every owned TCP
native attempt (Linux standard/parallel-interface/fallback and Windows
ConnectEx); see "Attachment" below. Stream rules need no packet backend or
capture privileges. Packet capture, when enabled, observes the transformed
packets because the wrapper writes before kernel serialization.

Reference: bol-van/zapret v72.9 `c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`,
`tpws/tamper.c`, `tpws/tpws_conn.c`, `tpws/protocol.c`, `tpws/tpws.c`.
The derived stream sources carry the pinned upstream MIT copyright and
permission notice in [`common/desync/UPSTREAM_LICENSE_zapret_tpws.txt`](../../common/desync/UPSTREAM_LICENSE_zapret_tpws.txt);
that notice is independent of the sing-box GPL license at the repository root.

## Shape

```json
{
  "type": "direct",
  "tag": "direct",
  "desync": {
    "stream_rules": [
      {
        "name": "http",
        "network": ["tcp"],
        "port": [80],
        "protocol": ["http"],
        "methods": ["http_tamper", "split"],
        "http_tamper": {
          "hostcase": true,
          "hostspell": "HoSt",
          "unixeol": false
        },
        "split": {
          "split_pos": ["method+1", "host+3"]
        }
      },
      {
        "name": "tls",
        "network": ["tcp"],
        "port": [443],
        "protocol": ["tls"],
        "methods": ["tls_record", "split"],
        "tls_record": {"pos": "sniext"},
        "split": {
          "split_pos": ["1"],
          "disorder": "tls",
          "oob": "tls",
          "oob_data": "0x00"
        }
      }
    ]
  }
}
```

Rules are evaluated in order; the first matching enabled rule owns the stream.
`network` is TCP by construction: a `udp` entry is rejected. `ip_version`,
`port`, `port_range`, `port_exclude`, `port_range_exclude`, `protocol`,
`domain`/`domain_file`/`domain_exclude`/`domain_exclude_file` and
`ip_cidr`/`ip_cidr_file`/`ip_cidr_exclude`/`ip_cidr_exclude_file` have the same
spelling and semantics as packet rules (lists OR inside a category, categories
AND, exclusions win). The optional `list_bundle` object has the same spelling and
semantics as on packet rules and selects immutable datasets of a provider list
bundle; `current.json` is read once per canonical bundle root and the same
pinned generation is shared with the packet rules of the outbound. A rule that
matches but declares no methods is a deliberate first-match terminator and
performs no transformation.

## Methods

`methods` is an ordered list of `http_tamper`, `tls_record`, `split`. The source
order of tpws is fixed: the protocol tamper runs before the split stage, so
`split` must be listed last. Each listed method requires its object, and an
object without its method is rejected; unknown methods and unknown fields are
errors, never no-ops.

### `http_tamper` (`tamper.c` HTTP branch)

| Field | tpws flag | Behavior |
|---|---|---|
| `hostcase` | `--hostcase` | Rewrite the `Host` header name to `hostspell` (default `host`). |
| `hostspell` | `--hostspell` | Exact 4-byte header spelling; implies `hostcase`. |
| `hostdot` | `--hostdot` | Insert `.` at the end of the host value. |
| `hosttab` | `--hosttab` | Insert a tab at the end of the host value. |
| `hostnospace` | `--hostnospace` | Remove the single space after `Host:`. |
| `hostpad` | `--hostpad` | Insert at least N bytes of dummy header lines before `Host:`. |
| `domcase` | `--domcase` | Alternate upper/lower case over the host value. |
| `methodspace` | `--methodspace` | Insert an extra space after the request method. |
| `methodeol` | `--methodeol` | Insert an end of line before the method. |
| `unixeol` | `--unixeol` | Replace CRLF with LF up to and including the end of headers. |

The transformations run in exactly this order: `unixeol`, `methodeol`,
`methodspace`, `hostdot`/`hosttab`, `domcase`, `hostnospace`, `hostcase`,
`hostpad`. `hostdot` and `hosttab` are mutually exclusive. These are intentional
representation changes: the peer must still receive a stream the transformed
request describes, not bit-identical bytes. Bytes after the transformed region
are preserved.

`domcase` uses the block offset parity as the deterministic equivalent of the
source's pointer parity for an aligned receive block. `hostpad` dummy header
names/values use a per-connection random source (crypto/rand by default; tests
inject a deterministic reader).

### `tls_record` (`tamper.c` TLS branch)

| Field | tpws flag | Behavior |
|---|---|---|
| `pos` | `--tlsrec` | Split the first ClientHello record at this position. |
| `record_pos` | `--tlsrec-pos` | Deprecated numeric alias. |

`pos` accepts `N`, `-N`, `marker`, `marker+N`, `marker-N` with markers
`host,endhost,sld,endsld,midsld,sniext`, plus the deprecated tpws aliases
`sni` (`host+1`) and `snisld` (`midsld`). Positions `<= 5` or outside the block
do nothing, as upstream. A position at or beyond the first record's handshake
length (but still inside the block) is clamped to 6. The split copies the
content type and record version into a new 5-byte record header and rewrites
both lengths; split positions greater than the record boundary are shifted by
5 bytes, matching `tamper.c`.

The ClientHello must be a complete first record for the split; a partial record
is held until it is complete, until the bounded hold fallback releases it, or
until `Close`. Fact extraction for rule matching also handles a ClientHello
spanning several TLS records; symbolic split anchors stay tied to the first
record, exactly like tpws.

Anchor edge cases follow the source rather than the matcher. A zero-length
second-level domain (`..`, `a..b`, `x..`, `..x`) is a *found* SLD, so
`sld`/`midsld`/`endsld` resolve to the upstream pointer offset instead of
dropping the split. An empty `server_name` value keeps its host anchor
(so `endhost-1` still resolves) but is never a matchable hostname, and a
rejected host_name (wrong name type, truncated body, name length past the
extension) leaves the host markers at zero while `sniext` still resolves.

### `split` (`tpws_conn.c` multisplit branch)

| Field | tpws flag | Behavior |
|---|---|---|
| `split_pos` | `--split-pos` | Ordered position list (`N`, `-N`, `marker±N`). |
| `split_http_req` | `--split-http-req` | Deprecated `method` or `host` form. |
| `split_tls` | `--split-tls` | Deprecated `sni`, `sniext`, `snisld` form. |
| `disorder` | `--disorder[=http|tls]` | `any`, `http` or `tls`: send even fragments with TTL 1. |
| `oob` | `--oob[=http|tls]` | `any`, `http` or `tls`: send one out-of-band byte. |
| `oob_data` | `--oob-data` | One character or `0xHH`; default `0x00`. |
| `split_any_protocol` | `--split-any-protocol` | Resolve absolute positions for non-HTTP/TLS blocks. |

Positions resolve, sort and deduplicate exactly like `ResolvePos` /
`ResolveMultiPos`; numeric zero is invalid. For HTTP they resolve after the HTTP
tamper transformations; for TLS they resolve before the record split and are
then shifted. `split_pos`, `split_http_req` and `split_tls` together may declare
at most 16 positions, the upstream `tpws` `MAX_SPLITS` limit. `disorder` is the
tpws stream behavior, not packet multidisorder:
even fragments are sent with TTL 1 so the native TCP stack retransmits them
after the odd fragments, and the socket TTL is restored after each send. `oob`
sends fragment 0 plus one trailing OOB byte using `MSG_OOB`/`WSASend`.
`oob` and `disorder` may be combined only on Linux, exactly as upstream; other
platforms reject the combination instead of claiming support. When a fragment
send is short, the split is cancelled and the remaining block bytes are sent
unsplit, byte-for-byte preserving the transformed stream.

### Connection controls

| Field | tpws flag | Behavior |
|---|---|---|
| `mss` | `--mss` | Preconnect `TCP_MAXSEG` (Linux). Accepted range `88..32767`, as upstream; rejected elsewhere. |
| `skip_nodelay` | `--skip-nodelay` | Do not set `TCP_NODELAY`; no cork/TTL shaping. Incompatible with `split`. |
| `fix_seg` | `--fix-seg` | Wait up to N ms for the kernel send queue to drain between fragments (Linux `TCP_INFO tcpi_notsent_bytes`), explicit range `0..1000`. `true` is the bare upstream flag and selects the upstream 50 ms default; `0` is an explicit zero that inspects the queue once without waiting. Rejected elsewhere. |

These are rule-level controls because tpws keeps them per desync profile and
applies them at connect/send time. `mss` can only use facts known before
connect: a rule filtered by domain cannot rely on future SNI, exactly as
upstream's pre-connect profile selection.

`fix_seg` keeps the three upstream spellings distinct:

```json
{"fix_seg": true}   // bare --fix-seg: upstream default of 50 ms
{"fix_seg": 0}      // --fix-seg=0: inspect the send queue once, never wait
{"fix_seg": 250}    // --fix-seg=250: wait up to 250 ms (0..1000 allowed)
```

The wait is applied between split fragments only; a block that is not split is
sent without inspecting the queue, exactly like the tpws multisplit loop.

## Intervals

`start` and `cutoff` are tpws `--tamper-start` / `--tamper-cutoff` values:
`<pos>` or `n<pos>`. A bare number is an outbound stream byte position; `nN` is
the 1-based data block number. The range is tested once per block at the block
start, so a block that starts inside the range is transformed in full even when
it extends past the cutoff. These are stream/block positions, never packet
`n/d/s` counters.

## Attachment

`stream_rules` and packet `rules` are two independent ordered lists in the same
`direct.desync` object; they are never merged and stream rules are never
packet methods.

* A stream-only object (`rules` empty, `stream_rules` non-empty) is valid. It
  compiles no engine, opens no capture and requires no packet privileges.
* Every owned TCP native attempt, including each losing parallel-interface and
  Windows ConnectEx attempt, calls `PrepareSocket` after the existing native
  interface/mark/namespace controls. The socket fd stays owned by the dialer.
  Only preconnect facts are used, so a domain-filtered rule cannot promise
  preconnect MSS from future SNI.
* Each successful TCP attempt is wrapped exactly once. The wrapper owns the
  connection, runs before kernel TCP serialization and preserves
  close/deadline/error semantics. A wrapper failure is terminal: the attempt
  fails, no unwrapped connection is returned and no silent fallback happens.
* UDP attempts and bound UDP listeners never run stream work; their existing
  behavior is unchanged.
* A TCP connection also closes its packet capture lease exactly once when it
  closes, so combined capture observes the whole connection and is released
  with it, including losing parallel attempts.
* `tcp_fast_open` with an enabled stream configuration is supported through the
  deferred owned attempt. The real socket is created by the first transformed
  send (the first split fragment, or an explicit empty/server-first connect),
  and that segment becomes the TFO payload, so per-attempt `PrepareSocket`,
  capture registration and the single stream wrapper still happen before the
  first SYN. Linux uses `TCP_FASTOPEN_CONNECT`, Windows uses ConnectEx initial
  data; other platforms return the actionable platform error instead of
  silently disabling TFO. A deferred connection that is closed before activation
  creates no socket, a losing parallel candidate is closed before activation and
  never opens a late socket, and a failed first send is terminal: no candidate is
  retried after early data may have left. The adopted socket is not usable and
  is not exposed through the unwrap/replaceability interfaces until the call
  deadlines of that moment have been published on it; a concurrent `Read`,
  `Write` or copy that arrives during that publication waits under its own
  half deadline and is refused with `os.ErrDeadlineExceeded` if that deadline
  expires first. `fix_seg` on the first fragment has
  nothing in flight to inspect, so it does not activate the connection early.
  Two combinations are accepted limitations and are visible guards, not silent
  fallbacks: a first split fragment that needs OOB or low-TTL disorder is
  refused before any byte is written, because SYN data cannot carry a
  per-segment socket option, and Linux packet capture combined with
  `tcp_multipath` is rejected before network I/O.
  `mss`/`skip_nodelay` are applied
  from the preconnect rule selection and, like tpws, are not retroactively
  changed when a later host-based re-selection picks another rule. `TCP_NODELAY`
  is re-asserted (to 0) on the connected socket for every attached Go TCP
  entrypoint, because Go's `net` package enables it again after the dial; a
  failed re-assert fails the attach instead of silently ignoring the option.

## Cache, learning and reply observation (D4)

* A stream-only object still owns one per-outbound Engine: the same ip cache and
  hostlist-auto learner as the packet rules, never a second store. Its backend
  is `state-only` and opens no capture or native handle; list files are not read
  at compilation beyond the configured learning/ip-cache configuration.
* Before connect, a rule filtered by domain can be selected from the engine's
  IP-to-hostname cache entry for the attempt destination (upstream
  `apply_desync_profile` + `ipcache_get_hostname`). The cached host is
  provisional: the first block's `Host:`/SNI re-selects the rule, and the
  engine then re-evaluates the learned eligibility for the revealed host.
  Cache entries remain scoped to this outbound; the interface dimension is used
  wherever the observation path knows the actual attempt interface.
* `stream_rules[].learning` uses the same typed `DirectDesyncRuleLearning`
  thresholds and the same per-outbound `desync.learning` configuration as the
  packet rules. `fail_threshold` and `fail_time` are the tpws
  `--hostlist-auto-fail-*` values; `retrans_threshold` is accepted for type
  compatibility and intentionally has no effect, because tpws has no TCP
  retransmission learning for a stream connection.
* Applicability mirrors upstream `b_ah_check`: the selected rule has
  `learning`, the host is known, the host is not excluded by the rule and it is
  not already in the learned set.
* Reply observation mirrors `tamper_in`/`rst_in`/`hup_out` and runs
  independently of the outgoing `start`/`cutoff` interval: on the first inbound
  block an HTTP 302/307 redirect to a different second-level domain counts as a
  failure and any other reply (including a non-HTTP first block) resets the fail
  counter; a read failure before the first inbound block counts as a failure.
  Only the first inbound block is observed, it is observed on a bounded copy,
  and the bytes returned to the caller are never changed or consumed twice.

## Runtime model and bounds

* Each connection is wrapped once after a successful owned TCP attach. Nil or
  empty configuration returns the original connection without allocating state.
* Up to 64 KiB (`tpws RD_BLOCK_SIZE`) is tampered as one block; a transformed
  block may grow to 65542 bytes (`RD_BLOCK_SIZE + 6`) like the tpws segment
  buffer. Writes are serialized per connection; reads pass through byte for
  byte and are only observed (never modified) for hostlist-auto.
* Rule selection may be deferred for a bounded prefix so that a hostname that
  arrives in the same block can change the first-match rule: up to 2048 bytes
  for HTTP without a host, 16 KiB or a complete ClientHello for TLS. After that
  the block is processed with the facts it has.
* The deferred prefix is never held indefinitely. A structurally complete
  HTTP header block or TLS ClientHello - including a ClientHello without SNI -
  is released at once; a genuinely incomplete prefix is released by a
  200 ms progress fallback (restarted by each Write that adds bytes) even if no
  further `Write` or `Close` arrives. The fallback runs the normal
  transformations and ordering on the retained bytes, so partial HTTP/TLS
  transformations are preserved rather than dropped.
* `split_pos` is limited to 16 entries in total, including deprecated
  `split_http_req`/`split_tls` entries (`tpws` `MAX_SPLITS`); this is separate
  from the packet-rule limit of 64. `hostpad` is limited to the segment
  buffer. No packet engine, global cache or cross-connection mutable state is
  used.
* Deadlines are the underlying connection's deadlines; the wrapper also records
  the write deadline for native senders that bypass the Go poller, and
  `SetDeadline` records its write half the same way. Every store to the wrapper
  deadline sources advances a publication generation, and both publications (the
  underlying connection and the native sender) repeat until the generation they
  read before the last delivery is still current. A single
  `SetWriteDeadline`/`SetDeadline` that computed its value before the `Close`
  flush bound was installed therefore republishes the bound instead of leaving a
  cleared or later deadline behind, and the same holds for the reverse order.
  Native senders receive the same value through that one generation-ordered
  publication: adoption of a new sender and every caller update publish the
  effective deadline and then re-read the source, so a publication that
  snapshotted an older value cannot remain the last one the sender enforces -
  neither a stale clear/later value after a completed stricter setter nor a
  stale stricter value after a completed extend/clear, for any number of
  concurrently completed setters. The protocol bounds no number of passes: each
  repetition requires an observed source change, so it ends as soon as the
  callers stop, while no publisher can return with a value it knows is stale.
  The Windows overlapped sender additionally checks the live connection deadline
  immediately before submitting, so no submission follows a completed expired
  setter even while a publication is in flight. `net.Conn` allows those calls
  concurrently with `Close` and with each other; the flush bound additionally
  does not rely on the deadline slot at all (see the `Close` bullet). A
  context cancelled after a successful `WrapConn` closes the underlying
  connection. A failed write is sticky: the stream is not reused. Following
  bytes of a block are never dropped or duplicated by a split, including on
  short writes: a short or zero-progress native send forwards its unsent tail on
  the same connection. A send whose transferred prefix is unknown - the terminal
  completion could not be established, the completion was observed but its
  count could not be read, or the provider reported the operation aborted - is
  never treated as zero: the provider may already have transmitted an unknown
  prefix, so no tail is forwarded and the error is reported unchanged. A
  completion that was observed without a readable count is terminal, so its
  submitted allocation, `OVERLAPPED` and completion event are retired instead of
  being kept for a count that will never arrive; an observed completion stays
  terminal when `Close` or the write deadline wins the caller-visible error
  selection, so the single auto-reset signal the provider already delivered is
  never required a second time.
* `Close` never waits for a blocked `Write`: it closes the underlying
  connection (and cancels an in-flight native send) first, so pending I/O is
  interrupted. When no write is in flight, `Close` flushes the retained block
  with the normal transformations under a 250 ms bound. The same bound is
  published as the wrapper write deadline, so a native sender that bypasses
  the Go poller (the Windows overlapped `WSASend`) and is first constructed by
  that flush waits at most the same 250 ms; an earlier caller deadline remains
  stricter. Concurrent `SetWriteDeadline`/`SetDeadline` calls cannot extend the
  flush: the flush arms a lifetime watchdog with the effective deadline (the
  earlier of the caller deadline and the 250 ms bound) and, when the connection
  has not finished the flush shortly after that deadline, it cancels the pending
  native send and closes the connection - the same abort `Close` performs for a
  blocked `Write`. A caller whose publication is still in flight therefore
  cannot make `Close` unbounded: the publication converges on the capped
  effective deadline, and the watchdog bounds the connection lifetime
  independently of the slot. The fixed watchdog grace is 25 ms, so a flush ends
  at 275 ms at the latest, and a stricter caller deadline ends the flush
  earlier. After the flush the effective deadline is published once more for
  observers; every publication that starts later reads the bound, and one that
  was already in flight re-reads and republishes it before returning. Repeated
  `Close` is safe. Ownership is
  settled once: a successful `WrapConn` returns a wrapper that owns and closes
  the connection, while a `WrapConn` error leaves the connection with the
  caller, who must close it.
* `Write` reports how many bytes of the caller buffer the wrapper owns, and
  that count is what a caller may not send again. Bytes whose block reached the
  connection are owned, bytes retained for the deferred first block are owned
  as well (the 200 ms fallback, the next `Write` or the bounded `Close` flush
  delivers them), and bytes still unsent after a send error are not owned, so a
  strict caller that retries `p[n:]` neither replays nor skips stream bytes.
  Only original caller bytes are counted: the single OOB urgent byte is extra
  wire data and never part of `p`. A block that is only split, disorder-marked
  or OOB-marked keeps a byte-for-byte mapping, so a partial send of it is
  reported exactly. `http_tamper` and `tls_record` change the payload length, so
  they are accounted per block: the block counts when its whole transformed
  payload reached the connection, and contributes nothing when the send stopped
  inside it, because there is no byte boundary back into `p`. Any send error
  stays sticky, so no counted byte is flushed or sent a second time.

### Retained native admission

An enabled outbound owns one Engine; each actual native attempt owns exactly one
Lease. A native sender factory and every native submission take a *reference* to
that already charged attempt - never a second lease, pool or registry:

* the sender factory references the attempt before its completion event or
  native socket work exists, and every native send references it before any
  socket option or `WSASend`/`sendmsg`;
* one unresolved native operation per attempt is enough: a send that cannot
  prove its terminal completion keeps its exact submitted buffer, event and
  `OVERLAPPED` (Windows) and its admission reference;
* the charged slot is released exactly once, after a proven terminal receipt
  (success, abort or documented terminal failure) and after capture teardown
  finished. A timeout, `CancelIoEx` result, failed wait, socket-close return or
  canceled context is not a receipt;
* `Close` closes the admission gate first and tears down capture/stream state
  without waiting for a receipt. A closed attempt with outstanding native
  references is a charged tombstone, not a live capture, and
  `active_leases` reports charged attempts including those tombstones;
* admission refusal (engine closed, attempt closed, or the per-engine lease
  limit reached) is returned as an error matching `desync.ErrAdmissionRefused`.
  A refused native send reports the known prefix and the refusal and performs no
  fallback write.

The bound is **per outbound Engine instance/generation** and identical to the
existing `limits.max_leases`; a stream-only object uses the existing state-only
Engine and its default of 4096 without any new JSON field. Reload reuses the same
authority. A replacement Engine is a different pool, so old retained operations
stay charged to the old one. The bound covers retained attempts, events and
waiters, not process bytes: an arbitrarily large deferred first write, the
trailing OOB byte and the surrounding wrapper state are not covered by a
`max_leases x fixed bytes` promise, and this stage adds no silent truncation or
chunking.

A provider that never reports a terminal receipt can therefore exhaust this
finite pool. Its resources stay owned and further attempts are refused; there is
no timeout free, no unaccounted replacement and no process-global cap across
outbounds.

## Platform applicability

* Linux: all tpws stream controls implemented (`TCP_CORK`, TTL shaping,
  `MSG_OOB`, `TCP_MAXSEG`, `TCP_INFO` fix-seg, `TCP_NODELAY`).
* Windows: ordinary stream transformations, `split`, `disorder`, `oob` and
  `skip_nodelay` implemented through an overlapped `WSASend` lifecycle with a
  completion event: readiness and the write deadline are enforced by a bounded
  wait (an expired deadline returns `os.ErrDeadlineExceeded`; an aborted
  operation has no documented transfer count, so its prefix is reported as
  unknown and the block is not replayed), `Close` cancels the pending operation,
  and the completion event is released with the sender. A completion-status
  query that cannot report the operation is not a completion receipt: the exact
  submitted allocation, the `OVERLAPPED` and the completion event stay owned by
  an autonomous completion owner until the provider signals the completion, and
  are then released exactly once - `Close` and a later `Write` are not required,
  and `Close` never waits for it. A prefix harvested while the wait itself
  failed is preserved, so only the unsent tail is forwarded, and a completion
  whose count the provider refuses after the operation finished (a synchronous
  `WSASend` success, a signalled event, or an aborted operation) is reported as
  an unknown prefix instead of zero: its allocation and event are retired, and
  the wrapper does not replay the block. `mss`, `fix_seg`
  and the OOB+disorder combination
  are rejected because upstream tpws has no equivalent there (U3 source
  applicability); a plain `syscall.RawConn.Write` is deliberately not used
  because it cannot observe the Go poller deadline.
* Other platforms: compile, but native-only knobs are rejected rather than
  accepted as no-ops.

Unit tests are pure and hermetic; native OOB/TTL/fix-seg and real-wire
verification remain pending VM/network evidence.

## Remaining gaps (outside this subsystem)

* tpws `hostlist-auto` learning, the IP-to-hostname cache and `--tamper-in`
  reply inspection are implemented for stream rules through the per-outbound
  Engine (see above). A TLS reply is not inspected, exactly like upstream
  `tamper_in`, which only monitors HTTP. Remaining open rows are the D3 kernel
  capture packet limit / owned quoted-ICMP gap, D5 command/provider surfaces and
  the D6 foundation helpers; they are not claimed here.
* tpws SOCKS/transparent listener plumbing, multi-bind/interface controls,
  socket buffer/timeout/maxconn lifecycle options remain mapped to existing
  sing-box inbound/dialer owners (U4); they are not reimplemented here.
* Full tpws/zapret parity is not claimed: packet families (`hostfakesplit`,
  `orig`/`dup` intervals, reply depth, conntrack/cache/learning/gzip/reload),
  provisional matching/QUIC cross-datagram and native selectors remain open in
  the packet and support lanes.
