---
icon: material/shield-alert
---

# Zapret engine ownership

!!! warning "Local fork extension"

    This option is not part of upstream sing-box. It is a local production
    slice for the `mvpn-zapret2-outbound-20261106` deliverable and implements
    **Windows and Linux**. On other platforms a profile is rejected with an
    explicit error; outbounds without the `zapret` field are unchanged
    everywhere.

`direct` outbounds may reference an original [zapret2](https://github.com/bol-van/zapret2)
profile. When a profile is present, sing-box owns the socket-level
association and the lifecycle of one original `winws2` (Windows) or `nfqws2`
(Linux) process for that outbound. The engine is never exposed as a proxy
protocol, is not ported to Go, and upstream C/Lua files are not modified.

## Structure

```json
{
  "type": "direct",
  "tag": "zapret-a",
  "bind_interface": "eth0",
  "zapret": {
    "profile": "profiles/zapret-a.json"
  }
}
```

### Fields

#### profile

Required. Path to a zapret profile file. A relative path is resolved against
the directory of the loaded sing-box configuration, not the process working
directory. Programmatic users without a configuration directory must use an
absolute path.

#### bind_interface

Required when `zapret` is present. The physical interface used both for
ordinary socket binding and for the engine capture. This is the only
supported egress for a zapret outbound; `network_strategy` is rejected on the
same outbound because the physical egress must be deterministic.

## Profile file

```json
{
  "engine": "zapret2",
  "executable": "../zapret2/binaries/linux-x86_64/nfqws2",
  "strategy_file": "zapret-a.strategy.json"
}
```

| Field | Description |
|-------|-------------|
| `engine` | Must be `zapret2`. |
| `executable` | Original `winws2.exe` (Windows) or `nfqws2` (Linux). Relative to the profile file directory. |
| `strategy_file` | JSON array of literal argv tokens. Relative to the profile file directory. |
| `reservation_ports` | Optional, Windows only. Ports reserved per socket family and protocol. Default `256`, allowed `16..4096`. Ignored on Linux, where ownership uses a socket mark and a queue number instead. |

All files referenced by the recipe (`--lua-init`, `--blob`, hostlists and
IPsets) are resolved relative to the **strategy directory** (the directory of
`strategy_file`), which is also the child working directory.

## Strategy file

The strategy file is a JSON array of complete literal argument tokens:

```json
[
  "--lua-init=@../zapret2/lua/zapret-lib.lua",
  "--lua-init=@../zapret2/lua/zapret-antidpi.lua",
  "--blob=lab_tls:0x16030100f0",
  "--filter-tcp=80,443",
  "--payload=http_req",
  "--lua-desync=fake:blob=lab_tls:repeats=3",
  "--lua-desync=multisplit:pos=1"
]
```

This format is not the upstream `@config` format. Every array element becomes
exactly one argv element: there is no shell, no environment expansion, no glob
expansion and no variable or command substitution.

### Validation

Before any process is started, sing-box validates:

* `engine`, `executable` and `strategy_file` exist and are regular files;
* the strategy is a JSON array of at most 512 non-empty string tokens;
* every token is a long option from a fixed recipe allowlist;
* `--filter-tcp` / `--filter-udp` port syntax and ranges;
* `--lua-init=@file`, `--blob=<name>:@file`, `--ipset*` and `--hostlist*`
  input files exist relative to the strategy directory;
* at least one `--lua-init`, one `--lua-desync` and one TCP or UDP filter are
  present;
* the engine reports `github version v1.0.7 (...)` with `lua_compat_ver 6`.

Inline Lua (`--lua-init=<code>`) is explicitly unsupported in this slice.

### Filter modes (no game_filter/ipset_filter fields)

The profile document intentionally has no `game_filter` or `ipset_filter`
fields; any unknown field is rejected. Modes are expressed directly by strategy
tokens, so the manager, ownership model and profile contract stay unchanged:

* **Game Filter TCP+UDP** — put the real TCP/UDP ranges in the last
  `--filter-tcp` / `--filter-udp` branches. Flowseal 1.10.4 defaults are
  `1024-65535`; the sentinel port `12` means disabled.
* **IPSet Filter "any"** — omit the positive `--ipset` token from the affected
  branches and keep `--ipset-exclude`. The original v1.0.7 engine treats an
  empty include collection as "no positive restriction"
  (`nfq2/ipset.c`: "all include lists are empty means check passes"); keeping a
  non-empty placeholder file is not the same as "any".
* **Unknown-payload actions** — the profile-level `--payload=unknown` filter
  only gates whether the instance is called. The stock `fake` and `multisplit`
  functions default their own payload filter to `known`, so the documented
  per-instance argument must also be passed, for example
  `--lua-desync=fake:blob=name:payload=unknown`. No Lua or C change is needed.

`examples/zapret2/strategy/alt11-games-any.conf.json` is the shipped example of
all three points. A mode is a static choice: a different range, a loaded IP set
or a different payload restriction is a different strategy/profile file.

### Manager-owned options

The following upstream options are owned by sing-box and are **rejected** in a
profile rather than merged or overridden: every `--wf-*` capture option,
`--qnum`, `--fwmark`, `--filter-mark`, `--port`, `--pidfile`, `--daemon`,
`--chdir`, `--writable`, `--user`, `--uid`, `--ssid-filter`, `--nlm-filter`,
`--intercept`, `--debug`, `--dry-run`, `--version` and file redirection with
`@file`. Options are matched exactly, so abbreviations and aliases are
rejected as well. On Linux `--bind-fix4`, `--bind-fix6`, `--qnum`, `--fwmark`
and `--pidfile` are composed by sing-box.

## Windows runtime behaviour

The manager composes one complete argv:

```
winws2.exe --debug=1 --intercept=1 --wf-priority=0 --wf-raw=<generated><recipe tokens>
```

The raw WinDivert filter is generated from the OS-assigned reservations and
contains, in both directions, only this outbound:

```
!impostor and !loopback and ifIdx == <physical> and subIfIdx == 0 and
((outbound and (own TCP/UDP source ranges)) or
 (inbound  and (own TCP/UDP destination ranges)))
```

There is no global port, hostlist or `80/443` OR term.

On Windows, `SIO_ACQUIRE_PORT_RESERVATION` runs on four anchor sockets
(TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6) before the child starts. The
`INET_PORT_RANGE.StartPort` field is transported in network byte order, both in
the request and in the returned `INET_PORT_RESERVATION_INSTANCE`, while
`NumberOfPorts` and the reservation token keep the native structure layout. The
returned range is validated before it is used: a zero start or count, a range
that wraps past port 65535, a grant wider than `reservation_ports`, and two
ranges of one protocol that overlap are explicit startup errors. Every real
socket of the outbound receives `SIO_ASSOCIATE_PORT_RESERVATION` in its control
callback, which runs before `bind`, before `connect`/`ConnectEx` and before the
first delayed-TFO write. Connected UDP sockets are given an explicit local
address with port `0`, so the port is consumed by `bind`. Exhaustion of the
reservation is a connection error, never an ephemeral fallback. Readiness
requires both the capture marker and `LUA INIT DONE`, because the capture
marker is printed before the sandbox and Lua initialization.

On stop, admission closes first, the tracked flows are closed, the child is
terminated with a direct process kill (Windows offers no graceful console
signal or `SIGTERM` equivalent on this path) and awaited for up to the stop
timeout, and only then are the four reservation anchors released. A wait
timeout is reported as a stop error instead of being treated as success.

## Linux runtime behaviour

Requirements:

* sing-box runs with `CAP_NET_ADMIN` (SO_MARK, nftables, NFQUEUE) and
  `CAP_NET_RAW` (raw packets sent by the original engine), for example as
  root or with an equivalent privileged runtime; the original engine child
  inherits the same capabilities;
* the `nft` user space binary (`nftables >= 1.0.1`) is installed; it is
  executed directly with a fixed argv and the ruleset batch on standard input,
  never through a shell;
* the kernel provides `nf_tables`, `nf_socket` (`socket mark`) and
  `nfnetlink_queue` (for example kernel 6.x; verified kernels at design time
  were 6.8).

The manager composes one complete argv:

```
nfqws2 --debug=1 --intercept=1 --qnum=<Q> --fwmark=0x40000000 \
       --pidfile=<fresh runtime path> --bind-fix4 --bind-fix6 <recipe tokens>
```

Ownership values are allocated by sing-box, never by a profile:

```
R            = 0x40000000              generated-packet mark (nfqws2 --fwmark)
Q_i          = 10000 .. 10063          finite per-process queue pool
O_i          = 0x20000000 | Q_i        unique per-outbound socket mark
table        = sb_zapret_<sanitized outbound tag>
```

`O_i` is non-zero and `O_i & R == 0`. Every real socket created for the
outbound — TCP, connected UDP, unconnected UDP (`ListenPacket`), parallel
attempts and delayed TFO — receives `SO_MARK = O_i` in its control callback
before `bind`/`connect`. A socket that already carries a different non-zero
mark is reported as an error instead of being overwritten.

The engine child writes its pidfile only after Lua initialization and NFQUEUE
binding, so the manager requires a fresh non-empty pidfile whose pid is the
child pid, then installs the ownership table with one atomic `nft -f`
transaction and only then reports `ready`. No socket is admitted before that
point.

The single managed `inet` table contains:

```
chain predefrag    output      priority -401    meta mark & R != 0 -> notrack
chain postrouting  postrouting priority srcnat+1
                                                oifname "<physical>"
                                                meta mark == O_i
                                                tcp / udp counter queue num Q_i
chain input        input       priority filter iifname "<physical>"
                                                socket mark == O_i
                                                tcp / udp counter queue num Q_i
```

* Outgoing packets are selected by the exact `.sk_mark` the socket carries;
  generated packets carry `R` and are excluded by the exact match, and are
  marked `notrack` so NAT cannot reject them.
* Incoming packets are selected by the live `socket mark` lookup in the input
  hook. This is what makes an ordinary, wildcard-bound UDP socket work: no
  `transparent`, `wildcard` or conntrack owner mark is used. A closed socket or
  a TIME_WAIT tuple is not owned, so its late packets are not captured.
* Queues are installed **without** `bypass`: if the engine is gone, owned
  packets are dropped instead of continuing unprocessed.
* Each rule has its own counter, so the tester can read per-direction and
  per-protocol packet/byte counts with `nft list table inet <table>`.

Queue/mark allocation is finite and process-local. A candidate is skipped when
the queue number is referenced by any existing nftables queue rule, is already
bound by a process (`/proc/net/netfilter/nfnetlink_queue`), or when the derived
mark is positively selected by an existing rule; the first free slot wins and
exhaustion is an explicit startup error. Queue rules are compared through their
actual `num` expression: a scalar selects one queue and an `A-B` range selects
the whole interval, so a foreign range containing the candidate is never
treated as free. A missing or otherwise unresolvable `queue num` expression (for
example a set, map or variable reference) is an explicit startup error instead
of being skipped as unused. The scan covers queue statements and
`meta mark` / `socket mark` comparisons in the machine-readable ruleset; mark
comparisons through named sets and policy-routing (`ip rule`) fwmark selectors
are not scanned, so the allocated mark is logged at startup and must not be
reused for policy routing. Bit `0x40000000` is reserved for packets generated
by the original engine (they are marked `notrack` at output priority `-401`);
no other component on the host should set it.
A leftover table with the managed
name (for example after an unclean stop) is an explicit startup error and is
never reflushed or replaced; remove it with `nft delete table inet <table>`.
Foreign tables, rules, marks and queues are never modified, and the ruleset is
never flushed.

Normal stop: admission closes first, owned flows are closed, the child is sent
`SIGTERM` and is `SIGKILL`ed if it is still alive after the stop timeout, then
only the managed table and the runtime pidfile directory are deleted. (Windows
uses a direct process kill plus anchor release instead; see above.)
Cleanup errors name the remaining resource. If the child exits on its own, the
manager enters `failed` and refuses new sockets; there is no silent fallback to
plain Direct.

### Linux limits

* The first supported Linux path is TUN `auto_route` **without**
  `auto_redirect`. `tun.auto_redirect`, `routing_mark`, `route.default_mark`
  and `netns` are rejected together with `zapret`, because auto-redirect and
  routing marks manage the same socket mark and the ownership table lives in
  the sing-box network namespace. The combination with `auto_redirect` remains
  an open case, not a pass.
* `protect_path` is not rejected up front; any mark it applies is detected by
  the socket-level check and reported as an error instead of being discarded.
* Every packet of an owned TCP/UDP flow in both directions is queued, which is
  the price of exact ownership and adds per-packet cost. This slice makes no
  throughput claim.
* The original engine sets `NFQA_CFG_F_FAIL_OPEN` and suppresses `ENOBUFS`.
  Removing the queue bypass does **not** provide a fail-closed guarantee under
  engine overload; that upstream limit stays.
* If the original engine dies, capture disappears earlier than the parent
  necessarily notices. This is explicit-failure behaviour, not a security
  kill-switch and not a crash-atomic guarantee.
* IPv4 and IPv6 are covered by the same `inet` rules and the same socket mark,
  but IPv6, dual-stack, TFO and large/fragmented UDP are not natively verified.
  Raw-send egress under TUN was observed only in a narrow IPv4 `/32` case
  (`WP12`/`LP10` in the deliverable QA), not as a full default-route or VPN
  qualification.
* ICMP is not covered by zapret ownership and is not reported as processed
  TCP/UDP; DNS resolution keeps its configured role.
* Hot reload is intentionally outside the current mandate; the mVPN UI/Rust
  generator is not delivered because the private repository was not reachable
  through the allowed existing methods, so that is missing scope rather than a
  rejected option. The game configuration
  (`examples/zapret2/strategy/alt11-games-any.conf.json`) has native synthetic
  IPv4 evidence on both platforms (`WP12`/`LP10`): unknown TCP and UDP payloads
  run the stock branch 8/9 actions, the shared reference and the B/Direct
  controls held, and the private exclusions still force `no_action`. A real
  game or voice session, an installed game executable, concurrency, IPv6 and a
  successful UDP application/server report remain unverified.

## Limits of this slice

* Windows and Linux only. Other platforms report
  `zapret: original engine ownership is implemented for Windows and Linux only in this slice`.
* On Windows, IPv4 and IPv6 are reserved separately; a dual-stack IPv6 socket
  uses its IPv6 reservation, and `subIfIdx` must be `0`.
* The engine is spawned without `--daemon` and terminated on stop. If the
  child dies on its own, the failure is detected asynchronously.
* Hot reload and the mVPN UI/generator are not delivered: hot reload is
  intentionally outside the current mandate, and the generator is unavailable
  because the private mVPN repository could not be reached with the allowed
  methods. The games-any example profile is configuration plus native synthetic
  IPv4 evidence on both platforms (`WP12`/`LP10`, narrow `/32` TUN). Real
  game/voice sessions, IPv6 and a full default-route or VPN qualification remain
  unverified, and the single independent final review is pending.
