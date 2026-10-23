# Direct desync provider bundles and runtime diagnostics

This page documents the **explicit** provider refresh and runtime inspection
surface of the direct outbound desync feature. It is an operator surface: nothing
here runs when a configuration is loaded. There is no scheduler, daemon,
background downloader, watcher, second cache, learner or listener.

The helper deliverable in this repository contains:

- `sing-box tools desync list-refresh` — acquire one pinned provider recipe,
  normalize, aggregate, publish one immutable generation.
- `sing-box tools desync list-refresh --rollback GENERATION` — republish an
  already committed generation offline.
- `sing-box tools desync reload` — ask one direct outbound to reload its list
  snapshot through the running controller.
- `sing-box tools desync diagnostics` — read one bounded runtime section of one
  direct outbound.
- The `/desync/diagnostics` and `/desync/reload` controller routes documented
  below. They exist only when the existing optional Clash controller is safely
  configured.

Everything is derived from bol-van/zapret v72.9
(`c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`). Flowseal configurations remain a
regression input, not the feature ceiling.

## What is not part of this surface

- No automatic download on start, no `get_config.sh` sourcing, no
  `get_ipban.sh` execution, no cron job.
- No `ipset`/`nft`/`pf`/firewall command, no DNS cache flush, no OOM score
  change, no `killall`/`pkill`, no shell hook.
- No new listener, no new secret store, no new RPC, no signal handler.
- No packet work at all: provider refresh only produces list files.

## Publication model

```
DIRECTORY/
  current.json                     the only commit point
  generations/
    <32 lowercase hex>/            immutable generation
      manifest.json                archived byte-identical manifest
      zapret-hosts.txt.00000.gz
      ...
  .refresh.lock                    short-lived OS publication lock
```

Rules:

1. All twelve datasets always exist, including explicitly empty ones with a
   recorded origin (`generated`, `local`, `not_provided`, `disabled`).
2. A generation is complete and immutable before it is visible. Files are
   written with `0600`, directories with `0700`, and synchronized.
3. `current.json` is replaced atomically through a private same-directory
   temporary file: POSIX rename, or the native `MoveFileEx` replacement primitive
   on Windows. There is no remove-then-rename fallback and no `O_TRUNC` on a live
   file.
4. Any failure or cancellation before the commit leaves `current.json` and all
   previous generations unchanged. A committed generation is never pruned
   automatically.
5. Symbolic links, reparse points and hardlinked live leaves are refused. Inputs
   are opened without following a final symlink and checked for identity.
6. `.refresh.lock` is an OS file lock whose lifetime ends with the process. The
   Engine never acquires it.
7. `current.json` is read once per distinct canonical bundle root per compile or
   reload by the core owner; this helper only writes and verifies it.

`current.json` is a complete `desync.list-bundle/v1` manifest, maximum 1 MiB. A
generation carries the same manifest archive at
`generations/<generation>/manifest.json` for offline rollback. Rollback validates
every referenced shard hash before republishing that manifest; it performs no
network access and no generation mutation.

## Refresh request

`tools desync list-refresh --request REQUEST.json --output-dir DIRECTORY`

The request must be a real local file (not stdin), at most 1 MiB, strict JSON:
unknown keys, duplicate keys, trailing documents and wrong types are rejected.
Relative paths inside the request resolve against the process working directory;
an operator should use absolute paths.

```json
{
  "format": "desync.list-refresh/v1",
  "provider": "reestr-preresolved",
  "acquisition": "remote",
  "families": [4, 6],
  "snapshots": [],
  "inputs": {
    "user_hosts": [], "exclude_hosts": [], "ipban_hosts": [],
    "user_ip4": [], "user_ip6": [],
    "exclude_ip4": [], "exclude_ip6": [],
    "ipban_ip4": [], "ipban_ip6": []
  },
  "compression": "gzip",
  "resolve": {"threads": 30, "eagain": 10, "eagain_delay_ms": 500},
  "aggregate": {
    "ipv4": {"prefix_length": "22-30", "threshold": "3/4"},
    "ipv6": {"prefix_length": "56-64", "threshold": 5}
  },
  "limits": {
    "max_entries": 522288,
    "max_exclude_entries": 65536,
    "max_decoded_bytes": 134217728,
    "max_total_bytes": 536870912,
    "timeout_seconds": 600
  }
}
```

Absent optional fields take exactly these defaults. `max_entries` translates
`config.default` `SET_MAXELEM` (522288), not the `def.sh` fallback 262144, and is
not the packet engine lease count. Explicit out-of-range values are errors; they
are never silently clamped. A limit violation fails the whole publication and
the previous generation stays current: counts and the reason are reported, the
data is never truncated.

### Recipes

| Recipe | Source URL | Notes |
|---|---|---|
| `reestr-preresolved` | `https://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved4.txt`, `..._resolved6.txt` | already resolved; no extra DNS or aggregation |
| `reestr-preresolved-smart` | `.../reestr_smart4.txt`, `.../reestr_smart6.txt` | already smart; no local density aggregation |
| `reestr-resolvable-domains` | `.../reestr_hostname_resolvable.txt` | domain feed; "resolvable" is a provider label |
| `antifilter-ip` | `https://antifilter.download/list/ip.lst` | IPv4; source `cut_local`, then ip2net |
| `antifilter-ipresolve` | `https://antifilter.download/list/ipresolve.lst` | same; no local DNS of provider records |
| `antifilter-ipsum` | `https://antifilter.download/list/ipsum.lst` | same, including ip2net |
| `antifilter-allyouneed` | `https://antifilter.download/list/allyouneed.lst` | same |
| `antifilter-ipsmart` | `https://antifilter.network/download/ipsmart.lst` | not `antifilter.download` |
| `refilter-ipsum` | `https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ipsum.lst` | summarized feed; no extra aggregation |
| `refilter-domains` | `.../domains_all.lst` | domain feed |
| `antizapret-domains` | `https://antizapret.prostovpn.org:8443/domains-export.txt` | gzip required |
| `user` | none | user inputs only, local acquisition |
| `exclude` | none | exclude inputs only, local acquisition |
| `ipban` | none | exclude/ipban inputs, local acquisition |
| `local` | none | typed local snapshots only |
| `empty` | none | deliberate empty complete generation |

`acquisition` is `remote` or `local`. Remote requires a remote recipe, fetches
only its fixed URLs and accepts no snapshots. Local requires a snapshot for every
active source (`hosts`, `ip4`, `ip6` typed dataset names) and performs **no HTTP**
but still resolves explicit host inputs. There is no local-to-remote fallback.
`user`, `exclude`, `ipban`, `local` and `empty` are local-only. `empty` forbids
all inputs and snapshots and deliberately publishes empty datasets.

`families` is a nonempty unique subset of `4, 6`. It controls provider family
sources and explicit host resolution; domain acquisition is independent of it.
An IPv4-only provider requested without 4 is an error; asking for both keeps its
real IPv4-only nature and still allows IPv6 user data.

Each input role accepts at most 32 explicit local files, text or gzip by magic.
Absent means empty; no default path in a home directory or upstream directory is
ever discovered or copied. Malformed local records are errors, not silently
dropped. Domain spelling follows the existing normalizer: ASCII/punycode,
lowercase, one trailing dot removed, a leading dot preserved. A host resolution
input cannot start with a dot.

### Source semantics

- Provider IP ranges are validated (endpoints, family, order) and converted to
  their exact minimal CIDR cover, never expanded per address, before the entry
  budget applies.
- `cut_local` is the exact upstream predicate. IPv4 drops only `192.168.`, `127.`
  and `10.`; `172.16/12` stays. IPv6 drops the textual equivalents of
  `^::|^fc..:|^fd..:|^fe8.:|^fe9.:|^fea.:|^feb.:`. Exclude-host resolution has no
  `cut_local`.
- DNS uses the existing mdig resolver seam and EAGAIN policy. Permanent negatives
  are counted and skipped; exhausted temporary failures and resolver
  infrastructure errors abort the generation instead of publishing a transiently
  emptied exclusion set. Counts are recorded, never host names in ordinary
  stderr.
- Negative datasets (`exclude_*`, `ipban_*`) are retained for runtime suffix
  matching of partially overlapping prefixes. Positive sets are filtered before
  and after density aggregation, so aggregation cannot reintroduce an excluded
  address.
- IPv4 density aggregation uses the pinned ip2net algorithm and only for the
  recipes whose upstream script aggregates. A non-default aggregate object for
  any other recipe is rejected rather than accepted as a no-op.

### Network acquisition safety

The real transport:

- accepts only fixed `https` URLs with certificate and host name verification
  against the system roots and a minimum of TLS 1.2;
- disables the ambient proxy, cookie jars, credentials and user info, and never
  has an insecure option;
- sends `Accept-Encoding: gzip` where the upstream script does, disables automatic
  transport decompression, and decodes gzip exactly once by magic (required for
  AntiZapret);
- follows at most five HTTPS redirects only for AntiFilter and ReFilter, within
  an exact host allowlist, with no downgrade, port change, user info or fragment;
- resolves the destination once per attempt and connects only to validated public
  addresses, so loopback/private/link-local/multicast/unspecified destinations
  and DNS-rebinding gaps are rejected;
- hashes the wire bytes before decoding and records the redacted final URL
  (scheme/authority/path) plus a SHA-256 of the complete final URL, never the
  expiring GitHub query;
- retries only transient transport errors and HTTP 408/429/5xx, with 1/2/4/8 s
  delays inside the source attempt budget and the invocation deadline.

All of that is bypassed in tests: the library takes an injected HTTP client,
resolver and clock, and a local refresh must fail the test if the transport is
called.

## Output manifest

`current.json` is a strict `desync.list-bundle/v1` document:

- header: `format`, `generation` (32 lowercase hex from 32 random bytes),
  `created_at` (UTC RFC3339), `recipe_revision` (pinned zapret SHA), `provider`,
  `acquisition`, `families`, `request_sha256`, `limits`;
- `sources[]`: exactly one of `path` or `url`/`final_url` metadata plus
  `sha256` of the raw body, `size`, `compression`, `decompressed_size`, line and
  record counts;
- `resolution`: DNS and aggregation accounting only;
- `datasets[]`: the twelve fixed datasets, each with `kind`, `family` for IP,
  `origin`, entry count, canonical uncompressed size/hash and ordered shards.

Fixed dataset IDs: `hosts`, `ip4`, `ip6`, `user_hosts`, `exclude_hosts`,
`ipban_hosts`, `user_ip4`, `user_ip6`, `exclude_ip4`, `exclude_ip6`, `ipban_ip4`,
`ipban_ip6`.

Shards are split on complete newline boundaries into at most 3 MiB decoded
chunks, named `<base>.00000` onward with `.gz`, with at most 1024 shards total
and at most 4 MiB per wire or decoded shard. Gzip has a zero modification time
and no original file name. Every dataset is ASCII-compatible UTF-8 text with a
trailing newline per record. The reader hashes the bytes it reads and never
trusts manifest counts.

The refresh receipt is `desync.list-refresh-result/v1`:
`{format, committed, generation, previous_generation, manifest, manifest_sha256,
dataset_entries, warnings}`. It carries no fetched data and no host names. A
post-commit durability problem reports `committed: true`; it never claims a
rollback that did not happen.

## Runtime reload and diagnostics

`tools desync reload --server http://127.0.0.1:9090 --outbound TAG`

`tools desync diagnostics --server http://127.0.0.1:9090 --outbound TAG
[--kind status|conntrack|failure-pool|ipcache|windows-network|capture-filter]
[--limit 128] [--include-sensitive] [--all-networks] [--output PATH|-]`

The CLI requires exactly `http://<numeric-loopback>:<port>` with no path beyond
an optional `/`, no user info, query or fragment. Host names, TLS, redirects,
proxies, implicit controller startup and automatic retries (especially for the
POST) are not supported. The credential is read once from the existing
`BOX_API_SECRET` environment variable, required nonempty, and sent only as the
`Authorization` header. There is no `--secret`/`--token` flag, no query token, no
secret echo and no header log. A missing controller is an error: the command
never prints a fabricated empty snapshot.

### Controller routes

```
GET  /desync/diagnostics?outbound=TAG&kind=status&limit=128&include_sensitive=false&all_networks=false
POST /desync/reload
Content-Type: application/json
{"outbound":"TAG"}
```

The core owner mounts these routes inside the existing authenticated controller
group **only when** the controller secret is nonempty and `ExternalController` is
a numeric loopback address with an explicit nonzero port. The feature-local
middleware additionally rejects URL credentials, any `token`/`access_token`/`auth`
query key (including the shared WebSocket fallback), `Upgrade`, browser `Origin`,
non-loopback `RemoteAddr`, unknown or duplicate parameters, malformed bodies and
oversized requests. Forwarded headers never grant locality. Responses are
`Cache-Control: no-store`, JSON, `nosniff`, at most 1 MiB, encoded from a bounded
buffer with explicit truncation metadata instead of partial JSON.

Error mapping: unknown tag `404 outbound_not_found`; outbound without the
optional interface (including selectors) `409 diagnostics_unsupported`; missing
or invalid bearer `401`; feature disabled `404`; nonlocal/origin/upgrade/query
token `403`; malformed `400`; wrong method `405`; oversized `413`; busy `409`;
platform-inapplicable query `422`; native or read failure `503`. Error documents
are `{format:"desync.error/v1", code, retained_last_good}`.

### Snapshot and reload DTOs

The optional interface lives in `adapter/desync.go`:

```go
type OutboundDesyncDiagnostics interface {
    DesyncDiagnostics(context.Context, DesyncDiagnosticsRequest) (DesyncDiagnosticsSnapshot, error)
    ReloadDesyncLists(context.Context) (DesyncReloadResult, error)
}
```

`DesyncDiagnosticsRequest{Kind, Limit, IncludeSensitive, AllNetworks}` is
validated at the HTTP boundary and again inside the interface implementation.
The zero kind means `status`, limit 0 means 128 and accepted explicit limits are
1..1024; `all_networks` is legal only for `windows-network`.

A direct outbound implements the interface even when desync is disabled and
returns `state: disabled` without instantiating an Engine. The handler resolves
exactly one outbound with `OutboundManager.Outbound(tag)`; it never chases a
selector, default outbound or group.

Default snapshots are redacted: endpoint addresses and ports, domain names, SSIDs,
network and interface identifiers, file paths, filter expressions and native
error text are omitted, not hashed. Sensitive mode only adds the documented
optional fields, capped (host 253, identifier/name 256, filter 16384). Snapshot
ages and expiries reflect observation time and never mutate caches, TTLs,
counters or activation state.

Reload invokes the existing Engine reload authority, serialized with close, and
keeps the last good runtime state when any packet list, stream list, bundle or
learned source fails to validate. A reload error reports
`retained_last_good: true` and the failed generation stays on disk; roll back the
directory explicitly and reload again if required.

## Platform notes

- Linux: publication and locking use POSIX rename and `flock`. Native packet
  backends are unchanged.
- Windows: publication uses the native atomic replacement primitive and
  `LockFileEx`; a platform without a supported atomic replacement fails
  explicitly instead of falling back to remove-then-rename. Native Windows
  publication and runtime behavior was **not** executed by this helper lane; only
  compile/vet/source checks are claimed. `windows-network` all-networks scope and
  the owned capture-filter dump belong to the core integration and its native
  verification.

## Integration requirements owned by the core integrator

This helper deliberately does **not** edit shared or foundation files. The core
owner must:

1. Attach `option.DirectDesyncListBundle` to both existing rule types, read
   `current.json` once per distinct bundle root per compile/reload, verify hashes
   and bounds, and keep exclusions mandatory when selected.
2. Wire `desyncRouter(outbound)` into `experimental/clashapi/server.go` behind the
   existing `authentication(options.Secret)` group and the
   `desyncRouterEligible(secret, listenAddress)` gate, with no route when the gate
   does not hold.
3. Implement the optional adapter interface on the direct outbound, including the
   bounded state copies, redaction, `QueryWindowsNetwork` scope extension, owned
   endpoint capture-filter dump, and one list revision per successful changed
   publication.
4. Stage packet lists, stream lists and learned-file state as one validated
   snapshot in `Engine.ReloadLists`, preserving `Capture` and every unrelated
   config field.
5. Keep `list_bundle` selection additive with existing inline/file fields and
   enforce the per-outbound bundle budget.
6. Update the frozen command registration expectation in
   `cmd/sing-box/cmd_tools_desync_test.go` (`TestToolsDesyncRegistration`) to
   accept the three additive subcommands `list-refresh`, `reload` and
   `diagnostics`. This helper lane must not edit that frozen foundation test; it
   fails only on the exact subcommand count assertion, while the new command
   constructors are exercised by their own tests.

## Documentation delta proposal (core-owned files)

Labelled proposal only; this helper does not edit these files:

- `docs/configuration/direct-desync-tools.md`: add a "network and admin commands"
  section that separates `list-refresh`, `reload` and `diagnostics` from the
  offline tools, links here, and keeps the v3 threshold and non-truncation
  guarantees.
- `docs/configuration/direct-desync.md`: add the optional `list_bundle` selector
  example and a warning that selecting a positive dataset is a restriction, that
  an explicitly empty positive dataset matches nothing, and that a nonempty
  negative dataset relevant to selected positives must also be selected.
- `docs/configuration/direct-desync-tools.md` blockcheck procedure: replace the
  "no Linux VM" statement with the authorized lab procedure; keep checksum/option
  normalization narrow, never erase the field under test, and record native,
  wire and application evidence separately. This helper ran no lab test.

## Verification status

- Library unit tests, fault controls and race checks: see the task report.
- No external HTTP, DNS, product binary, service, privilege or network state was
  used.
- Native Windows publication/runtime and the authorized Linux packet lab remain
  pending for their owners; nothing here claims overall parity.
