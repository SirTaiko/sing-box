# TCP socket, listen-binding and admission controls

These fields extend the existing TCP listener, dialer and direct outbound
owners. They are console configuration only: no Desktop, service, RPC, proto
or installer surface is involved. Every field is optional and absent keeps the
previous sing-box behavior. The source boundary is bol-van/zapret v72.9
(`c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`, `tpws/tpws.c`).

## `tcp_socket_options`

The same typed object is accepted by `listen` options (inbounds) and dialer
options (outbounds):

```json
{
  "tcp_socket_options": {
    "receive_buffer_size": 1048576,
    "send_buffer_size": 524288,
    "user_timeout": "20s"
  }
}
```

- `receive_buffer_size` / `send_buffer_size` are optional bytes. A value of
  zero (or absence) makes no `setsockopt` call; it is not a forced zero-sized
  buffer. Values above the signed socket-option range are rejected. Linux
  passes the requested bytes divided by two to `SO_RCVBUF`/`SO_SNDBUF`
  (`tpws.c:1364-1390`); other targets pass the requested bytes directly. The
  kernel clamp/minimum stays observable, so the exact allocated memory is not
  promised.
- `user_timeout` is optional and bounds unacknowledged transmitted data
  (`TCP_USER_TIMEOUT`), not an idle or read deadline. It must be a whole
  number of milliseconds; positive sub-millisecond and overflowing values are
  rejected. It is implemented on Linux. On Windows the source option is
  inapplicable, so a positive value is an explicit configuration error; it is
  not emulated with read deadlines or `TCP_MAXRT`.
- Local listening sockets receive the buffer options before bind; accepted
  sockets verify the inherited values and re-apply them when the platform did
  not inherit them, then apply the local user timeout after accept. Remote
  dialer sockets receive all options before connect on every actual socket,
  including standard, parallel-interface, fallback and Windows `ConnectEx`
  attempts. A socket-option failure closes the socket and fails the attempt;
  it never continues with an unprepared connection.
- The object never applies to UDP sockets.

## `tcp_listen_bindings`

`listen`-side inbounds may replace the legacy `listen` field with up to 32
TCP bindings. Each entry selects one endpoint:

```json
{
  "type": "http",
  "listen_port": 1080,
  "tcp_listen_bindings": [
    {"address": "192.0.2.10"},
    {"interface": "eth0", "ip_version": 4},
    {"interface": "eth0", "ip_version": 6, "link_local": "prefer",
     "wait_ifup": "5s", "wait_ip": "10s", "wait_ip_linklocal": "3s"}
  ],
  "tcp_max_connections": 512
}
```

- `address` is an explicit endpoint (an IPv6 zone may be written as
  `fe80::1%eth0`). `interface` plus `ip_version` selects the first suitable
  address on that device. An interface next to an explicit address only scopes
  its zone/wait condition and never selects another address.
- `link_local` is `unwanted` (default), `no`, `prefer` or `force`. IPv6
  ranking follows `tpws.c:1727-1777`: `unwanted` = ULA, non-link-local, then
  link-local; `no` excludes link-local; `prefer` = link-local, ULA, then
  others; `force` = link-local only. Enumeration order is preserved inside a
  rank. A selected link-local address always carries the interface name as its
  zone; a scoped explicit address without a resolvable zone is an error, never
  scope 0.
- `wait_ifup` waits for the named interface to be up, then `wait_ip` is an
  independent address budget. During the first `wait_ip_linklocal` of the
  address budget, `prefer` behaves as `force` and `unwanted` as `no`. An
  explicit address may retry `EADDRNOTAVAIL` only inside `wait_ip`. All waits
  stop on cancellation.
- A non-empty list conflicts with the legacy `listen` field, with
  `set_system_proxy` (one unambiguous endpoint is required) and with a
  UDP-listening protocol. All bind sockets are acquired under rollback
  ownership before the inbound reports ready; a later failure closes only the
  sockets this inbound already acquired. One logical inbound keeps one
  connection handler and one admission budget.
- `tools desync bind-wait --input bindings.json` uses the same resolver and
  prints the resolved endpoints as JSON. It never creates a listener, socket,
  core instance, capture engine or native driver:

  ```json
  {"bindings":[{"address":"192.0.2.10","ip_version":4},
               {"address":"fe80::1%eth0","interface":"eth0","ip_version":6}]}
  ```

## `tcp_max_connections`

One optional integer from 1 to 10000. It bounds concurrently accepted TCP
connections across every bind socket of the inbound. The token is acquired
immediately after `Accept` and before a handler/goroutine is published; an
excess connection is closed before dispatch. Release is idempotent on
connection close, the handler `onClose` callback and shutdown. Outbound
parallel/fallback attempts are not counted; the accepted socket keeps its
original destination, syscall and half-close capabilities. Absence keeps the
previous unlimited behavior.

## `tcp_disable_splice`

One optional boolean, default `false`. When set, the accepted connection pair
is relayed with ordinary `Read`/`Write` copies in **both** directions: the copy
owner receives read/write-only adapters that cannot be unwrapped into a
syscall splice, `io.ReaderFrom` or `io.WriterTo` fast path. Deadlines,
`CloseWrite`/`CloseRead`, error values and byte counters stay in effect because
every call is forwarded to the wrapped connection. The adapters claim the
half-close capability only when the wrapped connection has it, so an ordinary
EOF still half-closes a duplex peer and closes a non-duplex one exactly as
before. Absence keeps the previous copy path unchanged: no wrapper, no extra
allocation, no changed fast path.

A Windows inbound already uses an ordinary copy; the option is accepted there
and has no additional effect. The option is relay policy of one listening
inbound, not a global setting, and it does not disable packet-level desync or
stream transforms.

## `tcp_max_orphan_time`

One optional duration. Absence keeps the previous behavior: the route
connection pair only dials and starts copying after the remote connection is
available, with no pending reader, buffer or timer.

When configured, the existing route connection-pair owner keeps a single
pending-connect state while the remote side is unavailable (destination
resolution and the native connect both belong to the dialer attempt):

- One bounded upload reader owns the accepted local leg; no sniff, handshake or
  watch reader reads the same connection concurrently. It buffers at most
  64 KiB and then stops reading, so backpressure reaches the local leg. The
  buffer is allocated only for an inbound that configured this policy.
- A normal read EOF or half-close is **not** a terminal close. The pending
  attempt keeps running, and after a successful connect the queued bytes are
  flushed exactly once and the pending read half-close is forwarded as
  `CloseWrite`.
- A terminal local close/error (a read error, not EOF) while the remote is
  still unavailable and queued real bytes are unsent starts the orphan timer.
  At expiry the pending resolve/connect is cancelled. Connect success disarms
  the timer, so a remote that becomes available is never subject to it; a late
  resolve or connect result after cancellation is closed instead of reviving
  the pair.
- Empty pending data cancels the pending attempt immediately, without waiting
  for the timer.
- An explicit `"0s"` configures the policy but disables only the orphan timer:
  the pending attempt continues under the configured connect deadline, caller
  cancellation and shutdown.
- Caller cancellation and core shutdown cancel the pending attempt immediately
  and override the orphan grace. The accepted-connection admission token and
  an orphaned remote's own Engine/lease accounting stay independent; the close
  is reported once, so admission is released exactly once.

```json
{"type":"socks","tag":"relay-in","listen":"127.0.0.1","listen_port":1082,
 "tcp_disable_splice":true,"tcp_max_orphan_time":"5s"}
```

## Accepted compatibility limits

MPTCP with Linux packet capture and TFO with a first send that needs
`MSG_OOB`/low-TTL disorder are accepted sing-box integration limitations (user
decision, 2026-10-24), not open compatibility rows. Each combination is refused
with an actionable error before network I/O and is never silently disabled.
Ordinary MPTCP use, the allowed stream-only configurations and ordinary
deferred TFO remain supported. These are limits of this integration, not a
claim that upstream zapret universally forbids those combinations, and not a
claim of parity for every combination. The shared SOCKS resolver policy is a
separate increment; deferred-TFO connections count as unavailable until their
actual native connect completes.

## Detour and admission ownership

`tcp_disable_splice` and `tcp_max_orphan_time` are supplied by the original
accepting inbound and travel as a value with the connection metadata. An
inbound detour carries the same metadata, so the detour target neither
re-derives the policy nor takes a second admission token for the same accepted
connection.

The same rule applies to the direct desync attachment: admission is owned by the
outbound's Engine (`Lease` presence), while packet capture, exclusive packet
binding and packet-only dialer conflicts require the packet capability
(`Engine.PacketEnabled()`). A stream-only object uses the existing state-only
Engine for admission, ip cache and learning but performs no packet socket
preparation and opens no capture. A detour, a deferred TFO first payload or a
retry does not create a second admission token: it references the attempt it
already owns.
