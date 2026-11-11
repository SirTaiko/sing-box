# zapret2 production web/Discord and games-any profile bundle

Minimal, reproducible configuration for the local `zapret` field of a `direct`
outbound (see [`docs/configuration/outbound/direct-zapret.md`](../../docs/configuration/outbound/direct-zapret.md)).
The packet engine is the original, unmodified [bol-van/zapret2](https://github.com/bol-van/zapret2)
`v1.0.7` C binary plus its stock Lua. The strategies are the preserved ALT11 web
recipe (Flowseal `zapret-discord-youtube` 1.10.4) translated to the literal-argv
strategy format of this branch, plus a games-any variant of the same recipe
(real TCP/UDP game ranges and the IPSet-any equivalent). No custom Lua, no
upstream edits, no shell/eval and no test harness are involved.

Target scenario: YouTube and the public Discord web/gateway endpoints are
routed to one zapret outbound; every other flow follows the normal rules
(Direct, or the VPN outbound of the surrounding mVPN configuration). Selecting
the games-any profile instead additionally applies the preserved game branches
to TCP/UDP ports 1024-65535 of that same outbound.

## Qualification status (read first)

* **Web/Discord strategy (`alt11-web.conf.json`): native public QA on both
  platforms, scoped results only.** The public runs did not execute these
  routing files byte-for-byte: ordinary copies were used with
  `log.level=debug` plus an explicit `log.output`, Direct-role DNS over HTTPS
  (`1.1.1.1`) and a local `geoip-ru` rule set downloaded from the shipped URL.
  Profile, strategy, assets, rule order and selectors were unchanged. Evidence:
  `artifacts/windows-public-qa/HANDOFF.txt` (WP02/WP04/WP05/WP07/WP08) and
  `artifacts/linux-public-qa/HANDOFF.txt` (LP02-LP05, LP07, LP08) in this
  workspace (`artifacts/...` paths in this README are workspace-relative, not
  relative to the bundle directory).
* Proven there with real per-connection action and sender-side wire evidence:
  one/shared/two zapret outbounds over IPv4/TCP, real stock `fake`/`multisplit`
  replacement on the physical NIC, public Discord discovery plus an
  unauthenticated gateway `HTTP 101` / WebSocket server `op10` HELLO, ordinary
  post-Lua startup rollback and normal foreground stops. Linux additionally has
  real `SO_MARK`/nft per-rule counters. This is sender-side evidence: there is
  no independent public receiver vantage, no every-packet or no-loss claim, and
  no universal-cleanup claim.
* **Not proven:** YouTube media. Both stages reached YouTube HTML/player APIs
  but received a service sign-in/bot challenge, so no media file was produced
  and decode/playback is UNVERIFIED. HTML bytes are not media.
* **Game strategy (`alt11-games-any.conf.json`): native synthetic QA on both
  platforms, scoped mechanics only.** Two independent stages executed the
  shipped game profile: WP12 on Windows105 (`t_79abe8a3`/run1459,
  `artifacts/windows-games-qa/HANDOFF.txt`) and LP10 on Linux104
  (`t_2b36721a`/run1461, `artifacts/linux-games-qa/HANDOFF.txt`). Both used a
  controlled narrow IPv4 TUN `/32` composition - the exact shipped game profile
  as outbound A, a frozen tiny recipe as B and a genuine Direct outbound - with
  paired sender/receiver capture:
  * `WP12.2`/`LP10.2` - an unknown-payload TCP flow on `1024-65535` selects
    branch 8 (not the earlier HTTP/TLS branch 7) and runs the stock
    per-instance `payload=unknown` actions `fake_8_6`, `fake_8_7` and
    `multisplit_8_8`: 8 x 120 B STUN fakes plus 8 x 661 B sferum fakes,
    `seqovl=664` producing a 665 B overlap packet (661 fake bytes plus the
    first 3 repeated bytes) and a remainder, then the `--out-range=-n3`
    cutoff. Independently captured receiver bytes match the shipped
    `assets/stun2.bin` and `assets/tls_clienthello_www_sferum_ru.bin` hashes,
    and the first 664 B hash is identical on both platforms.
  * `WP12.3`/`LP10.3` - an unknown-payload UDP flow selects branch 9 and issues
    three stock `rawsend` rounds of ten 1278 B packets (1250 B payload) on the
    first three original datagrams, with no fake on the fourth or any later
    datagram. Every unique fake payload matches `assets/ACTIVE_GAME_UDP.bin`.
  * `WP12.4`/`LP10.4` - a second rule that shares outbound A uses the same
    child (and on Linux the same queue and mark), while B and Direct keep their
    own port reservations and show no A fake/split action on the observed
    tuples.
  * `WP12.5`/`LP10.5` - the shipped private `192.168/16` exclusion still
    selects `no_action` (stock profile 0): the sockets remain owned, but the
    receiver sees unmodified payload and zero game fakes. IPSet-any widens
    inclusion; it does not erase the exclusions.
  * `WP12.6`/`LP10.6` - ordinary foreground Ctrl+C and a zero-flow restart were
    observed on both platforms, and reuse of a recently owned port was observed
    on Windows.
  The UDP alias fixture never produced a successful application/server report
  (no final ACK). The same warning also appears on the B and Direct controls
  and with no product or TUN running at all, so it is a receiver-fixture limit,
  not a sing-box result; no UDP application PASS is claimed. All of the above
  is synthetic IPv4 traffic over a `/32` TUN route: it is not a game, voice,
  public-DPI, application, concurrency, IPv6 or full default-route/VPN
  qualification, and no game executable name was available or guessed.
* **Engine version.** The original ALT11 web adaptation was exercised with
  zapret2 **v1.0.6**. Both the web and the games-any strategies were later run
  natively with the official **v1.0.7** engine (the cases above). Stock Lua is
  byte-identical between v1.0.6 and v1.0.7; no wire equivalence between the two
  engine versions is claimed.
* **Aggregate acceptance: NOT_ESTABLISHED.** Nothing here is project approval.
  The single independent final review of this frozen candidate is still
  pending, and real game/voice sessions, a genuine VPN, full default-route TUN,
  IPv6/dual-stack/TFO/large UDP, the mVPN UI/generator and public YouTube media
  remain unverified.

## Layout

```
examples/zapret2/
  README.md
  profiles/
    profile-linux.json            # web strategy, executable: ../engine/nfqws2
    profile-windows.json          # web strategy, executable: ../engine/winws2.exe
    profile-linux-games-any.json  # game strategy, same engine paths
    profile-windows-games-any.json
  strategy/
    alt11-web.conf.json           # preserved ALT11 web/Discord literal argv
    alt11-games-any.conf.json     # ALT11 + real game ranges + IPSet any
  assets/                       # ALT11 fake/QUIC/STUN blobs (provenance below)
  lists/                        # ALT11 hostlists and IP set placeholders
  lua/                          # stock v1.0.7 zapret-lib.lua, zapret-antidpi.lua
  routing/
    linux/01-single-outbound.json
    linux/02-shared-outbound.json
    linux/03-two-outbounds.json
    linux/04-direct-baseline.json
    linux/05-tun-single-outbound.json
    linux/06-games-any-outbound.json
    windows/01-single-outbound.json
    windows/02-shared-outbound.json
    windows/03-two-outbounds.json
    windows/04-direct-baseline.json
    windows/05-tun-single-outbound.json
    windows/06-games-any-outbound.json
```

The `engine/` directory is **not** shipped (binaries are large and are taken
from the official release). Place it beside `profiles/` as described below; the
profile `executable` path and the strategy asset paths resolve relative to
their own files, never to the process working directory.

## Engine (original zapret2 v1.0.7)

The manager probes the child and requires `github version v1.0.7
(038c97e5819df10f8e8c22a2f1fffe57f2f7379b) lua_compat_ver 6`.

| Platform | File in `examples/zapret2/engine/` | SHA256 |
|----------|-----------------------------------|--------|
| Linux x86_64 | `nfqws2` | `4bb2634f0266bcc3cbe5988f4fc8c5e824649dd11edc418e71a415096c2505b0` |
| Windows x86_64 | `winws2.exe` | `9f25492575ff7c3f9e0d6211daac85704c309a0ca695423f0276d9ebde3156aa` |

Windows additionally needs the release files that `winws2.exe` loads from its
own directory: `WinDivert.dll`, `WinDivert64.sys` (from the same release) and
`cygwin1.dll`. Copy them into `engine/` next to `winws2.exe`.

`engine/` is also required by `sing-box check`, because profile validation
stats the executable before any process is started.

## Profiles

```json
{
  "engine": "zapret2",
  "executable": "../engine/nfqws2",
  "strategy_file": "../strategy/alt11-web.conf.json"
}
```

* `engine` must be `zapret2`.
* `executable` is the original `nfqws2` / `winws2.exe`, resolved relative to the
  profile file. Programmatic users without a configuration directory must use
  absolute paths.
* `strategy_file` is a JSON array of complete literal argv tokens, resolved
  relative to the profile file. The strategy directory also becomes the child
  working directory, so `--lua-init`, `--blob`, `--hostlist*` and `--ipset*`
  paths inside it are relative to the strategy file's directory.
* `reservation_ports` (Windows only; Linux ignores it) reserves this many local
  ports per socket family and protocol for the outbound. The Windows profile
  states the default `256` explicitly; allowed range is `16..4096`. Exhaustion
  is a connection error, never an ephemeral fallback.
* Capture/queue/mark/interception options are owned by sing-box and are
  rejected if a strategy contains them: every `--wf-*`, `--qnum`, `--fwmark`,
  `--filter-mark`, `--port`, `--pidfile`, `--daemon`, `--chdir`, `--writable`,
  `--user`, `--uid`, `--debug`, `--dry-run`, `--version` and `@file`
  redirection.

`profiles/profile-linux.json` and `profiles/profile-windows.json` select the web
strategy. `profiles/profile-linux-games-any.json` and
`profiles/profile-windows-games-any.json` have the same engine fields and differ
only in `strategy_file` (`alt11-games-any.conf.json`). Any routing example can
reference either profile without editing Lua; only the profile path changes,
and the 06 examples verify that the games-any reference resolves statically.

Each outbound gets its own engine process and its own ownership resources: on
Linux one queue from the finite pool `10000..10063` and a unique socket mark
`0x20000000 | Q` per outbound; on Windows four port-reservation anchors
(TCP/UDP, IPv4/IPv6) per outbound. The same profile file may be referenced by
more than one outbound; each instance is still an independent process.

## Strategy: ALT11 web translation

`strategy/alt11-web.conf.json` has 97 tokens and nine profiles delimited by
`--new`, in the original order:

| # | Filter | Host/IP selector | Payload / action |
|---|--------|------------------|------------------|
| 1 | UDP `443` | `list-general*.txt` | `quic_initial` -> `fake` quic blob, repeats 11, `ip_id=seq` |
| 2 | UDP `19294-19344,50000-50100` | `--filter-l7=discord,stun` | `discord_ip_discovery,stun` -> `fake` discord blob, repeats 6 |
| 3 | TCP `2053,2083,2087,2096,8443` | `--hostlist-domains=discord.media` | `tls_client_hello` -> google fake (repeats 8, TS) + `multisplit` `pos=1` `seqovl=681` |
| 4 | TCP `443` | `list-google.txt` | TLS hello -> google fake `ip_id=zero` + `multisplit` 681 |
| 5 | TCP `80,443` | `list-general*.txt` | TLS hello -> stun+sferum fakes (TS) + `multisplit` 664; `http_req` -> sferum fake + `multisplit` 664 |
| 6 | UDP `443` | `ipset-all.txt` (placeholder) | `quic_initial` -> quic fake, repeats 11 |
| 7 | TCP `80,443,8443` | `ipset-all.txt` (placeholder) | same as branch 5 |
| 8 | TCP `12` | `ipset-all.txt`, `--out-range=-n3` | TLS/http/unknown: stun+sferum fakes + `multisplit` 664 (game sentinel, disabled) |
| 9 | UDP `12` | `ipset-all.txt`, `--out-range=-n3` | `unknown` -> game fake, repeats 10 (game sentinel, disabled) |

Branch/target mapping for the shipped routing examples:

The preserved list files keep their original CRLF line endings. The original
engine's hostlist parser explicitly strips CR and LF (`nfq2/hostlist.c`), so no
conversion is applied here and none is required on either platform.

* YouTube (`youtube.com`, `youtu.be`, `googlevideo.com`, `ytimg.com`,
  `youtubei.googleapis.com`) is present in `lists/list-google.txt`, so HTTPS
  video/page traffic is handled by branch 4. `youtubei.googleapis.com` is listed
  explicitly because a broad `googleapis.com` suffix is deliberately **not**
  routed or matched. The preserved `list-google.txt` also contains other Google
  entries (`play.google.com`, `fonts.googleapis.com`, `www.gstatic.com`,
  `google.ru`, ...); they are inert for this outbound unless the routing
  configuration also sends those domains here, because the engine only ever
  sees sockets of its own outbound.
* Discord domains (`discord.com`, `discord.gg`, `discordapp.com`,
  `discordapp.net`, `discord.media`) are present in `lists/list-general.txt`
  (the preserved ALT11/Flowseal list), so TLS is handled by branch 5 and QUIC
  by branch 1; voice/media UDP ports are covered by branch 2.
* YouTube QUIC (UDP 443) has no matching hostlist branch in ALT11 either; those
  packets are returned unchanged and the client falls back to TCP TLS. This is
  the preserved ALT11 behaviour, not a new guarantee.

### Games-any strategy

`strategy/alt11-games-any.conf.json` (93 tokens, same nine branches and order)
materializes the two Flowseal switches the task asked for: Game Filter **TCP and
UDP** and IPSet Filter **any**.

| Branch | Web strategy (`alt11-web`) | Games-any strategy |
|--------|----------------------------|--------------------|
| 1-5 | domain/hostlist and Discord special branches | byte-identical |
| 6 | UDP `443` + `--ipset=ipset-all.txt` | same, positive `--ipset` removed |
| 7 | TCP `80,443,8443` + `--ipset` | same, positive `--ipset` removed |
| 8 | TCP `12`, `--ipset`, unknown group inert | TCP `1024-65535`, no positive `--ipset`, per-instance `payload=unknown` |
| 9 | UDP `12`, `--ipset`, unknown group inert | UDP `1024-65535`, no positive `--ipset`, per-instance `payload=unknown` |

Exact mapping (this is a static, token-level translation; it is not a new
profile schema - the native synthetic scope is `WP12`/`LP10`):

* **Game Filter TCP+UDP = real filter ranges.** Flowseal 1.10.4 `service.bat`
  defaults `GameFilterTCPRange=1024-65535` and
  `GameFilterUDPRange=1024-65535`; the disabled/opposite mode uses the sentinel
  port `12`. The game strategy uses the real ranges in branches 8 and 9 and
  keeps the original TCP/UDP desync actions, `--out-range=-n3` (the adapted
  form of Flowseal `--dpi-desync-cutoff=n4`) and the same fake/split values.
* **IPSet Filter "any" = no positive IP include.** Flowseal implements "any" by
  making `lists/ipset-all.txt` empty; zapret2 v1.0.7 `nfq2/ipset.c:256` says
  "all include lists are empty means check passes" (exclusions are checked
  first). The static equivalent removes the `--ipset=../lists/ipset-all.txt`
  token from branches 6-9 and keeps every `--ipset-exclude` token. That widens
  IP inclusion only; exclusion and hostlist conditions stay, and branches 1-5
  still run first. `lists/ipset-all.txt` remains in the bundle for the preserved
  web strategy and is not referenced by the game strategy.
* **Unknown-payload actions now actually run.** The preserved adaptation used
  the C-level `--payload=unknown` filter, but every stock anti-DPI function
  defaults its own `desync.arg.payload` filter to `known`
  (`lua/zapret-lib.lua` `payload_match_filter`/`payload_check`;
  `lua/zapret-antidpi.lua` `fake`/`multisplit`; manual "default payload filter -
  known"). The C filter admits the instance, then the function silently skips an
  `unknown` packet. This is why the earlier iperf/UDP stimulus produced no
  stock action. The game strategy passes the documented per-instance
  `payload=unknown` argument to the three unknown TCP actions and the UDP game
  action. No Lua or C file is modified, and no recipe value is tuned.
* **Known TLS/HTTP are still processed on game ports.** Branch 8 keeps the
  preserved `--payload=tls_client_hello` and `--payload=http_req` groups, so
  known TLS/HTTP game traffic is handled as in the original any-protocol branch.
  Empty payloads are not processed by this strategy; the original v1
  `--dpi-desync-any-protocol=1` also covered empty packets, so that is a
  documented narrowing, not asserted equivalence.
* **Native scope.** `WP12`/`LP10` exercised these branches natively on both
  platforms (synthetic IPv4 only, see
  [Qualification status](#qualification-status-read-first)): branch 8 and
  branch 9 run their stock fake/split/rawsend actions for unknown payloads,
  branch 9 emits ten stock `rawsend` packets per original datagram for the first
  three datagrams, and the private exclusions still force `no_action`. No game,
  voice, application, concurrency, IPv6 or full default-route/VPN result is
  implied, and no game session or game executable was available. The game
  branches are reachable only for flows already sent to this outbound; nothing
  here selects a process, IP or port globally.

Upstream evidence: Flowseal 1.10.4 `service.bat` (game defaults, IPSet status
and switch), preserved `profiles/alt11/original-ALT11.bat.txt` game branches,
and zapret2 v1.0.7 source (`nfq2/ipset.c`, `nfq2/protocol.c`, `nfq2/nfqws.c`,
`lua/zapret-lib.lua`, `lua/zapret-antidpi.lua`, `docs/manual.en.md`). Exact
quoted lines and file hashes are recorded in
`artifacts/games-profile/PROVENANCE.txt` and
`artifacts/games-profile/checks/semantics-evidence.txt`.

### Exact deviations from the ALT11 `zapret2.conf`

1. **Engine version.** ALT11 was exercised with v1.0.6. This bundle targets the
   official v1.0.7 binary and both strategies were run natively with it
   (`WP02`/`WP04`/`WP05`/`WP07`/`WP08`, `LP02`-`LP05`/`LP07`/`LP08` for web and
   `WP12`/`LP10` for games-any). The two stock Lua files are byte-identical
   (`zapret-lib.lua` `6bf528fe...`, `zapret-antidpi.lua` `6d1fa916...`), and the
   strategy text is unchanged apart from the items below. No wire equivalence
   is claimed.
2. **Capture options removed.** `--wf-iface=6`, `--wf-tcp-out=...` and
   `--wf-udp-out=...` are manager-owned and rejected. Capture now selects the
   exact sockets of this outbound (Linux: socket mark + nftables queues;
   Windows: WinDivert filter generated from the port reservations), so it is
   narrower in ownership but broader in port scope than the original
   `--wf-*-out` lists. Packets on ports that no profile matches are queued and
   returned unchanged; on Linux that is extra per-packet cost.
3. **Paths rebased** to this bundle; blob names (`alt11_quic`, `alt11_google`,
   `alt11_sferum`, `alt11_stun`, `alt11_discord`, `alt11_game`) are unchanged.
4. **Manager-composed arguments are absent by design.** Linux adds
   `--bind-fix4 --bind-fix6 --qnum=<Q> --fwmark=0x40000000 --pidfile=<path>`;
   Windows adds `--debug=1 --intercept=1 --wf-priority=0 --wf-raw=<generated>`.
5. **In `alt11-web.conf.json`, games remain the original disabled sentinels**
   (`--filter-tcp=12`, `--filter-udp=12`, `--out-range=-n3`) over the
   placeholder IP set `203.0.113.113/32` (TEST-NET-3). The separate
   `alt11-games-any.conf.json` materializes the real ranges and the IPSet-any
   equivalent (see [Games-any strategy](#games-any-strategy)); no game
   executable name is shipped in either strategy.
6. **No launcher and no global OS side effect.** ALT11's `start.cmd` enabled
   TCP timestamps globally with `netsh`. This bundle ships no script; the
   required commands are documented in [Client requirements](#client-requirements).

### Filter modes and schema

The design sketch in the task brief had `game_filter` and `ipset_filter`
fields. The implemented profile document deliberately accepts only `engine`,
`executable`, `strategy_file` and `reservation_ports`; any other field is
rejected at `sing-box check` time, for example:

```
zapret: parse profile "...": json: unknown field "game_filter"
```

(recorded in `artifacts/games-profile/checks/negative-unknown-fields.txt`).
Filter modes are therefore expressed by the literal strategy tokens, which is
the smallest change that needs no new Go subsystem, no template language and no
Lua edit:

| Requested mode | Concrete representation |
|----------------|-------------------------|
| Game Filter `disabled` | game branches keep the sentinel port `12` (`alt11-web.conf.json`) |
| Game Filter `TCP` | branch 8 gets the TCP range; branch 9 keeps port `12` |
| Game Filter `UDP` | branch 9 gets the UDP range; branch 8 keeps port `12` |
| Game Filter `TCP+UDP` | both branches get `1024-65535` (`alt11-games-any.conf.json`) |
| IPSet Filter `none` | positive `--ipset` points at the TEST-NET placeholder (web strategy) |
| IPSet Filter `loaded` | positive `--ipset` points at a real list file |
| IPSet Filter `any` | no positive `--ipset` token; `--ipset-exclude` stays (game strategy) |

These are static equivalents, not runtime-switchable profile fields: changing a
mode means selecting a different profile/strategy file, exactly like the two
shipped profiles. A custom range or a loaded IP set is a new strategy/profile
file and needs its own qualification. The game profile keeps the engine,
ownership manager, port reservations and profile contract unchanged.

## Routing examples

All examples use the fixed evaluation order required by the mVPN task:

1. service/management/DNS exceptions,
2. RU Direct (`geoip-ru` rule set),
3. selected zapret domains/processes,
4. browser/application VPN (inserted by the surrounding configuration),
5. default.

| File | Purpose |
|------|---------|
| `01-single-outbound.json` | one zapret outbound; narrow YouTube suffixes -> `zapret-a`; default Direct |
| `02-shared-outbound.json` | one zapret outbound referenced by several rules: YouTube, Discord domains, and (Windows) `Discord.exe` |
| `03-two-outbounds.json` | two independent zapret outbounds: YouTube -> `zapret-a`, Discord -> `zapret-b`; both use the same shared strategy file |
| `04-direct-baseline.json` | identical rule skeleton with no `zapret` field at all: ordinary Direct baseline for A/B comparison |
| `05-tun-single-outbound.json` | TUN `auto_route` example, one zapret outbound, same order; Linux uses `auto_route` **without** `auto_redirect` |
| `06-games-any-outbound.json` | one zapret outbound using `profile-<platform>-games-any.json`: the same narrow YouTube and Discord domain rules plus a game-process placeholder, all to the game profile |

Notes that apply to every example:

* **RU shadowing is intentional.** The `geoip-ru` rule is above the zapret
  rules, so a destination already resolved to a Russian address takes Direct
  before a zapret domain/process rule can match. That includes CDN and game
  servers; it is the agreed priority, not a defect. With only a domain in the
  connection metadata (no resolved address yet), the domain rule decides.
* **OFF / clash_mode.** `{"clash_mode":"Direct","outbound":"direct"}` is the
  current early bypass: when the mode is Direct, none of the lower rules
  (RU, zapret, VPN) is evaluated. The zapret outbound still exists, so its
  engine process starts and stays idle with no owned sockets. Real hot reload
  is not implemented; a restart is required to release the engine. Switching a
  selector does not migrate existing flows.
* **No VPN example is included.** This bundle has no credentials or transport,
  therefore no genuine VPN outbound exists to show. A `direct` outbound is
  never named `vpn`. In the mVPN-generated config, insert your real VPN
  outbound between the zapret rules and `final`; the examples keep
  `"final": "direct"` as a lab/baseline default only.
* **DNS role is Direct.** Each example resolves through a single direct UDP
  resolver (`dns-direct`; `8.8.8.8` in the examples, replace it with your own),
  with no fakeIP. Zapret traffic therefore keeps the Direct DNS role. If a
  deployment introduces
  fakeIP or an mVPN DNS role, the domain -> process -> default precedence must
  be kept consistent with these route rules; that generator work is not part
  of this bundle and the Rust mVPN implementation is not claimed here.
* **Process rules.** The Windows shared and two-outbound examples contain
  `{"process_name":["Discord.exe"],"outbound":"zapret-a"}` as a template.
  `Discord.exe` is the official Windows client executable name but was **not**
  verified in the lab; confirm it with `Get-Process` before relying on it, and
  keep the domain rules as the primary selector. Both `06-games-any-outbound`
  examples contain the literal sentinel
  `"process_name":["REPLACE_WITH_VERIFIED_GAME_EXECUTABLE"]`. It is a
  placeholder, not an installed executable name, and it therefore matches
  nothing as shipped. Replace it only after checking the real name on the test
  machine (`Get-Process` on Windows, `ps -o comm=` on Linux; a Windows value
  normally needs the `.exe` suffix). No game executable name is guessed or
  shipped.
* `geoip-ru` is a remote rule set
  (`https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs`)
  downloaded at startup by the Direct path. GeoIP fields were removed in
  sing-box 1.12, so the rule-set form is the only supported one. A fully
  offline deployment must replace it with a local rule set.

## Client requirements

### Linux

* Root, or `CAP_NET_ADMIN` (SO_MARK, nftables, NFQUEUE) **and** `CAP_NET_RAW`
  (raw packets sent by the engine). The engine child inherits them.
* `nft` user space `>= 1.0.1`; kernel with `nf_tables`, `nf_socket`
  (socket mark) and `nfnetlink_queue` (verified on 6.8).
* TUN: `auto_route` only, `auto_redirect` must stay off. `routing_mark`,
  `route.default_mark` and `netns` are rejected together with `zapret`.
* `bind_interface` is the physical uplink name (`eth0` in these examples;
  check with `ip route get 1.1.1.1`). An interface index change fails the
  outbound instead of continuing with a stale capture.

### Windows

* Administrator, because the original engine loads the WinDivert driver.
* `winws2.exe`, `WinDivert.dll`, `WinDivert64.sys`, `cygwin1.dll` in `engine/`.
* `bind_interface` is the physical adapter name (`Ethernet` in these examples;
  `Get-NetAdapter`). Never the TUN name. `subIfIdx` must be `0`.
* TCP timestamps must be enabled for the `tcp_ts=-600000:tcp_ts_up` recipe.
  This is a **global, persistent** setting:
  `netsh interface tcp set global timestamps=enabled` (Administrator).
  Restore with `netsh interface tcp set global timestamps=default`.
  The bundle does not run or ship a launcher for this.

### Both platforms

* The engine writes into its own runtime directory, and on Linux installs one
  `inet` table `sb_zapret_<tag>` plus one queue per outbound. A leftover table
  with that name is an explicit startup error; remove it with
  `nft delete table inet sb_zapret_<tag>` (the manager never flushes it).
* Queues are installed without the nftables `bypass` flag, so own packets are
  not handed back to the stack unprocessed at the queue level. That is not a
  fail-closed guarantee: the original engine itself sets `NFQA_CFG_F_FAIL_OPEN`
  and suppresses `ENOBUFS`, so engine overload and internal failure are not
  covered (see [Limits of this bundle](#limits-of-this-bundle)). Engine failure
  is reported, never silently replaced by plain Direct.
* Normal stop closes admission and the owned flows the manager tracks, then
  terminates the child and releases only its own resources. On Linux the child
  receives `SIGTERM`, is `SIGKILL`ed after the 10 s stop timeout, and only then
  is the managed table and the pidfile directory removed. On Windows there is
  no graceful console signal: the child process is terminated (a direct process
  kill, no `SIGTERM` equivalent), and the four port-reservation anchors are
  released after it exits; a wait timeout is reported as a stop error. Use the
  canonical foreground console or `log.output`; redirected PowerShell `*>` with
  Ctrl+C showed a confounded orphan case in Windows QA (W05) and is not a
  supported stop method.
* IPv6, dual-stack, TFO and large/fragmented UDP are not natively verified.
  Raw-send egress under TUN was observed only in a narrow IPv4 case over a
  single receiver `/32` (WP12/LP10); that is not a full default-route TUN or VPN
  qualification.

## Commands

Place the engine, then check the exact configuration you intend to run:

```sh
# from the sing-box repository root (engine placed as described above)
./sing-box check -c examples/zapret2/routing/linux/01-single-outbound.json
./sing-box check -c examples/zapret2/routing/linux/06-games-any-outbound.json

# run (Linux TUN example needs root/CAP_NET_ADMIN+CAP_NET_RAW)
sudo ./sing-box run -c examples/zapret2/routing/linux/05-tun-single-outbound.json

# stop: Ctrl+C in the foreground console; verify cleanup
nft list tables | grep sb_zapret_ || echo "no managed table"
```

Windows (elevated console):

```powershell
.\sing-box.exe check -c .\examples\zapret2\routing\windows\05-tun-single-outbound.json
.\sing-box.exe run   -c .\examples\zapret2\routing\windows\05-tun-single-outbound.json
```

For an A/B comparison against the no-engine path use
`routing/<platform>/04-direct-baseline.json` with the same rule skeleton: it
contains no `zapret` field, so no engine and no capture are created.

## Limits of this bundle

* Web strategy: scoped native public evidence only (see
  [Qualification status](#qualification-status-read-first)); no independent
  public receiver vantage, no every-packet capture and no universal cleanup
  claim. YouTube media/decode/playback is UNVERIFIED (bot-gated extraction).
* Game strategy: native synthetic mechanics only (`WP12`/`LP10`, IPv4 `/32`
  TUN). Unknown TCP and UDP payloads reach the stock branch 8/9 actions, the
  shared reference, the B/Direct isolation controls and the private exclusions
  all held, and the captured receiver bytes match the shipped assets. Not
  established: a real game or voice session, an installed game executable,
  concurrent or multi-flow cross-capture behaviour, IPv6, arbitrary payloads
  beyond the exercised datagrams, and a successful UDP application/server
  report. A narrow `/32` route is not a full default-route TUN or VPN
  qualification.
* UDP action content is verified only for the exercised 200 B iperf datagrams
  over that narrow route: the stock per-instance `payload=unknown` admits them
  and produces ten 1250 B fake payloads for each of the first three datagrams
  before the cutoff. The earlier all-unknown iperf stimulus without that
  argument is explicitly **not** evidence: the preserved game branches used the
  stock per-function default payload filter `known` and skipped unknown
  payloads.
* No throughput, CPU, ISP or universal-operator claim. The original engine
  keeps `NFQA_CFG_F_FAIL_OPEN`/`ENOBUFS` behaviour, so the queue statement
  without `bypass` is not a fail-closed guarantee under engine overload.
  Cleanup is verified for the ordinary foreground-stop and zero-flow-restart
  paths exercised in QA, not as a universal theorem and not as a repeated
  `Close`/`WaitClosed` API proof.
* Not delivered and not claimed: the mVPN UI/Rust generator (the private
  `SirTaiko/mVPN` repository was not reachable through the allowed existing
  methods, so DNS/fakeIP coordination and route generation are missing scope,
  not a rejected option), core hot reload (intentionally outside the current
  mandate - a sidecar restart is not hot reload; the requirements for a future
  implementation are recorded in the task's deliverable report), selector flow
  migration and an authenticated Discord/voice check. The single independent
  final review of this frozen candidate is still pending.

## Provenance

Engine and stock Lua (official v1.0.7 release, commit
`038c97e5819df10f8e8c22a2f1fffe57f2f7379b`):

| File | SHA256 |
|------|--------|
| `binaries/linux-x86_64/nfqws2` | `4bb2634f0266bcc3cbe5988f4fc8c5e824649dd11edc418e71a415096c2505b0` |
| `binaries/windows-x86_64/winws2.exe` | `9f25492575ff7c3f9e0d6211daac85704c309a0ca695423f0276d9ebde3156aa` |
| `lua/zapret-lib.lua` | `6bf528fef1f0fc3c65e189216fc8a06bb873f6e25d1c29d2bfa4695a09b73440` |
| `lua/zapret-antidpi.lua` | `6d1fa9168e5de1682fef91fd174f68b58c50f6739ef00f42ca7db2b940b6246d` |

Recipe and assets (preserved ALT11 package, from Flowseal
`zapret-discord-youtube` 1.10.4, original `general (ALT11).bat` SHA256
`6003f63ed86e6b5d4b6a3f3a6d38d710af6a7d515325dfc7ad0ce77e85961b0d`):

| File | SHA256 |
|------|--------|
| `assets/tls_clienthello_www_google_com.bin` | `936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c` |
| `assets/quic_initial_www_google_com.bin` | `f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a` |
| `assets/tls_clienthello_www_sferum_ru.bin` | `e6dd8d724eecc6a7340bf64e2ebec81c60bc4e078c6f702b4b6ba9bf184180ad` |
| `assets/stun2.bin` | `b7c2497496039c541f7337ac8536813f0a1cf52363ab2faa5213b7816d458813` |
| `assets/ACTIVE_DISCORD_UDP.bin` | `2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf` |
| `assets/ACTIVE_GAME_UDP.bin` | `e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e` |
| `lists/list-general.txt` | `9ff3ae9e4bf0edbcf8fecb1bba7aac951aace2036cdb732ec3ef65dfc6db443b` |
| `lists/list-general-user.txt` | `131ee4d9c64f627c88554da52ee68a4962c68fb12c1453e55d728a38cde5ec55` |
| `lists/list-google.txt` | `4104b8f5119f76a3642e3176987bbcf817d98daa4899a7ecf9ee2c254958e33b` |
| `lists/list-exclude.txt` | `e2de8403e1d2bd8ebd9de6b2cbfaab488d710681cbdcde2b219e71bc4490a56d` |
| `lists/list-exclude-user.txt` | `a55959f2708d2a68c84aceb2b0de737850aef9afb0c5dff55cc8ddc8318d171b` |
| `lists/ipset-all.txt` | `19123a22bf1108815c07bda3cda8df282b30bd63e4939949928969c0fd195873` |
| `lists/ipset-exclude.txt` | `96c03954012765ce4ab03b9c30f29ab1ca1b698c6752224d03828e6d182eb0fc` |
| `lists/ipset-exclude-user.txt` | `050887f9de1329575e7c6dcb22d634d44e36d7e9e4ebb2ed25242ac45c884d8d` |
| `LICENSE-zapret2.txt` | `d089978dd77d53cb6aa5dff51cfdbff617e52dd44af1ac44a6df02c6644f17d5` |

The preserved ALT11 package carries the zapret2 MIT license text (copied here
unchanged); the Flowseal release that provided the recipe and the six blobs is
identified in its `manifest.json` (`source_file`, `source_sha256`).

`lists/ipset-all.txt` contains only `203.0.113.113/32` (TEST-NET-3). In
`alt11-web.conf.json` it is referenced by the IP-set branches and the two game
branches are sentinel port `12`; those tokens are preserved from ALT11 and are
inert by construction. `alt11-games-any.conf.json` does not reference
`ipset-all.txt` at all (IPSet-any equivalent) and uses the real game ranges; its
native behaviour is qualified only in the synthetic IPv4 `/32` scope described
above (`WP12`/`LP10`). Do not present the placeholder list or the web sentinels
as a working game or IP-set filter.

Native qualification evidence (identity only, not correctness):

* Product binaries actually executed: Windows
  `bd5a96d11a915bfb1f2de05b5894c85551a2527715c740658cfe31314d90eebd`
  (`artifacts/windows-public-qa/bin/sing-box.exe`, Windows105) and Linux
  `f123b946766d922895fe61846c1939fe16e74c5c151d0a60194e7dd0a5566553`
  (`artifacts/linux-nft-repair/bin/sing-box-linux-amd64`, Linux104). Both are
  local `go1.27.3` builds of this branch at HEAD `c005f353...` with
  `-trimpath -buildvcs=false`; the native version string is unknown and not
  claimed. The official engine and stock Lua hashes are in the tables above.
* Web cases: `artifacts/windows-public-qa/HANDOFF.txt`
  (`WP02`/`WP04`/`WP05`/`WP07`/`WP08`) and
  `artifacts/linux-public-qa/HANDOFF.txt` (`LP02`-`LP05`, `LP07`, `LP08`).
* Game cases: `artifacts/windows-games-qa/HANDOFF.txt` (`WP12.0`-`WP12.6`) and
  `artifacts/linux-games-qa/HANDOFF.txt` (`LP10.0`-`LP10.6`), with the exact
  commands and exits in the sibling `COMMANDS.txt` and the evidence file hashes
  in each directory's `MANIFEST.sha256`.
* Those manifests seal provenance of the evidence files; they do not establish
  correctness. `aggregate_acceptance` stays NOT_ESTABLISHED until the
  independent final review.

Static filter translation sources (read-only, not shipped in the bundle):

* Flowseal `zapret-discord-youtube` 1.10.4 `service.bat` (SHA256
  `968cca9bd0ae685f0dababeb75cb9181950da3b64fd4948fb53ee39291baf413`):
  `GameFilterTCPRange`/`GameFilterUDPRange` defaults `1024-65535`, sentinel
  port `12` when disabled, and IPSet mode "any" implemented as an empty
  `lists/ipset-all.txt`.
* zapret2 v1.0.7 (commit `038c97e5...`) source: `nfq2/ipset.c:256` ("all
  include lists are empty means check passes"), `nfq2/protocol.c` payload-name
  table (`unknown` is a valid `--payload` value), `lua/zapret-lib.lua`
  `payload_match_filter` (per-function default `known`), and the stock
  `lua/zapret-antidpi.lua` `fake`/`multisplit` call sites quoted in
  `artifacts/games-profile/checks/semantics-evidence.txt`.
