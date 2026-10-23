# Offline desync support tools

`sing-box tools desync` is a group of explicit, operator-invoked offline tools
that support the direct outbound packet desync feature. The group is registered
as a child of the existing `tools` command; it does not load a configuration,
does not create a client, does not start a service, does not touch a firewall,
route or interface and does not schedule anything in the background.

```text
sing-box tools desync ip2net
sing-box tools desync mdig
sing-box tools desync dns-make-query
sing-box tools desync dns-parse-query
sing-box tools desync list-normalize
sing-box tools desync blockcheck-report
```

Three explicit provider/runtime commands are part of the same group. They are
**operator-invoked**, never automatic:

```text
sing-box tools desync list-refresh --request REQUEST.json --output-dir DIRECTORY
sing-box tools desync list-refresh --rollback GENERATION --output-dir DIRECTORY
sing-box tools desync reload --server http://127.0.0.1:PORT --outbound TAG
sing-box tools desync diagnostics --server http://127.0.0.1:PORT --outbound TAG
    [--kind status|conntrack|failure-pool|ipcache|windows-network|capture-filter]
    [--limit 128] [--include-sensitive] [--all-networks] [--output PATH|-]
```

`list-refresh` is the only command that performs provider HTTP acquisition, and
only when the request says `"acquisition": "remote"`. `reload` and `diagnostics`
talk to an already running instance through its existing Clash controller
surface; they require `BOX_API_SECRET` in the environment and an explicit
numeric-loopback `--server`. They never start a controller, never read a
configuration themselves and have no secret/token flag. See
`docs/configuration/direct-desync-providers.md` for the request/bundle format.

Basic config-driven desync (packet rules, stream rules, inline/file lists and
`list_bundle`) works with the console `sing-box run -c CONFIG` path alone. The
optional Clash controller is not a prerequisite: without it, `reload` and
`diagnostics` are simply unavailable while `list-refresh` and `list_bundle`
keep working, and a configuration reload remains the explicit alternative.
The `/desync/*` routes are mounted only when that existing controller is
configured with a nonempty `secret` and a numeric loopback listener with an
explicit nonzero port; otherwise the routes are absent (404) and every other
controller endpoint is unchanged.

Everything is stream oriented. Commands accept an explicit `--input`/`--output`
path (or `-` for the process standard streams where the table below says so).
Diagnostics go to standard error; a command never writes a host name anywhere
except to a log file the operator named explicitly.

Explicit paths of one command are checked before they are opened: the lexical
comparison above plus the actual filesystem identity (hard links, input symbolic
links, symlinked parent directories). A write role that is the same file as an
input role is refused, and a write path whose final component is a symbolic link
or a directory is refused. Files opened for writing are not truncated until the
identity of the opened descriptor has been compared with the open inputs; on
POSIX the final component is opened with `O_NOFOLLOW`. On Windows the final
component is opened with `CreateFile` and `FILE_FLAG_OPEN_REPARSE_POINT`, and a
non-zero reparse tag on the acquired handle is refused before truncation, so a
symbolic link or junction installed after the cheap inspection is never
followed. Native Windows runtime verification of the reparse-point and hard-link
behavior remains pending the disposable VM; this is a testing gap, not a waiver
of the Linux behavior.

A path containing a `..` component that follows a symbolic link is rejected
explicitly before any file is opened or replaced. The operating system resolves
such a `..` after following the link, while a lexical clean resolves it before,
so the same spelling would name two different objects for inspection and for
the later open, truncate or rename. The command does not silently rewrite the
operator path to its cleaned spelling; the error asks for the resolved path.
An ordinary `..` behind a real directory, and paths without `..`, keep their
usual filesystem meaning.

Explicit file destinations are regular-file-only: a FIFO, socket or device path
is refused instead of being opened, so a named output cannot block the command
or be written outside the staged publication path. Standard input and standard
output remain available for streaming.

Cancellation is observed between input lines and at command-owned boundaries. A
read that is blocked inside an arbitrary `io.Reader` supplied by the caller
(stdin, a pipe or a FIFO opened by the caller) is not preemptible; the command
does not detach the reader or leak a goroutine, so it returns once that read
completes and the next context check runs. Command-owned regular-file inputs are
read to their bounded end.

## Provenance

The `ip2net` aggregation and the `mdig` DNS query/answer codec reproduce the
observable behavior of bol-van/zapret v72.9, commit
`c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`:

- `ip2net/ip2net.c` - address list aggregation
- `mdig/mdig.c` - batch resolver, DNS query blob construction, DNS answer parsing

Upstream is distributed under the MIT license, Copyright (c) 2016-2024
bol-van. The Go implementation is not a line-by-line translation and does not
claim full parity: it keeps the pinned semantics, replaces unchecked C
arithmetic and unbounded buffers with bounded equivalents, and makes the
remaining deliberate differences explicit. Those differences are listed with
the affected command below; the list is not a completeness claim about every
possible input.

Flowseal 1.10.4 configuration examples remain regression fixtures. They are not
part of this tooling and are not evidence of parity.

## ip2net

```text
sing-box tools desync ip2net [--family 4|6] [--prefix-length min[-max]]
                            [--v4-threshold mul/div] [--v6-threshold N]
                            [--input path|-] [--output path|-]
```

Newline separated input, newline separated output. Defaults are the upstream
defaults:

| Flag | Default | Meaning |
|---|---|---|
| `--family` | `4` | address family of the bare address list |
| `--prefix-length` | `22-30` (4), `56-64` (6) | prefix lengths considered for aggregation, `min` or `min-max` |
| `--v4-threshold` | `3/4` | include an IPv4 network with at least `mul/div` of its addresses |
| `--v6-threshold` | `5` | include an IPv6 network with at least `N` addresses |

Behavior, matching `ip2net.c`:

- Lines that are not a bare address of the selected family, `ip/bits` or
  `ip1-ip2` are dropped. Bare addresses are sorted numerically, deduplicated and
  greedily aggregated: for every cursor position the prefix lengths are
  considered from the largest to the smallest network, a prefix length is
  skipped when the cursor address is too deep inside the block to reach the
  density threshold, and the network with the most addresses wins. An equal
  address count found at a longer prefix replaces the candidate, which is the
  upstream "do not carpet bomb" tie-break.
- `ip/bits` is passed through as `ip/bits` and is never masked, so a provider
  entry keeps its meaning. `ip/bits` with `bits` equal to the full length
  becomes a bare address and participates in aggregation; a longer prefix is
  dropped.
- `ip1-ip2` is passed through. IPv4 ranges are re-rendered from the parsed
  octets, IPv6 ranges are emitted verbatim.
- Trailing `\n`, `\r`, space and tab characters are trimmed. A line longer than
  the internal limit (4096 bytes) is an error instead of being split into
  several records (the C `fgets` buffer is 255 bytes). An input with more than
  4194304 bare addresses is an error instead of growing without bound. The
  aggregation work is bounded; cancellation through the process context stops
  the run.
- `--v4-threshold` accepts the upstream `uint32` range (`1 <= mul < div`,
  `div >= 2`) and `--v6-threshold` accepts `1..4294967295`; values that do not
  fit `uint32` or that are outside those ranges are rejected before any input
  or output file is opened. A prefix range that cannot apply to the selected
  family (for example `--family 4 --prefix-length 32`) is rejected at the same
  point. The library options keep their zero value as "use the built-in
  default"; an omitted command flag still applies `3/4`, while an
  explicit pair such as `0/0` is an error rather than a silent default.
  Numeric flag values use a strict unsigned decimal spelling: leading signs and
  trailing non-space characters, which the C `%u` conversions tolerate, are
  rejected by this parser. Space around each side of `/` and around the
  `--v6-threshold` value is trimmed, so `1 / 2` is accepted even though
  `sscanf("%u/%u")` rejects the interior space; this is an acceptance-only
  superset. The threshold arithmetic uses 64-bit integers. The C original
  computes both the density threshold and the cursor pre-check by multiplying
  the 32-bit subnet size by `mul` or by `div - mul` in 32-bit unsigned
  arithmetic, which can wrap for extreme `--v4-threshold` values; this
  implementation cannot, which only changes the result for inputs whose 32-bit
  product would have wrapped.
- Rendered addresses follow `inet_ntop(AF_INET6)`/glibc, including the
  IPv4-compatible `::a.b.c.d` form (`::1.2.3.4` stays dotted while `::1` and
  `::2` use the compressed form) and the `::ffff:a.b.c.d` mapped form.

## mdig

```text
sing-box tools desync mdig [--family 4|6|both] [--threads 1..100]
                           [--eagain 1..1000] [--eagain-delay ms]
                           [--verbose] [--stats N]
                           [--log-resolved path] [--log-failed path]
                           [--input path|-] [--output path|-]
```

Newline separated names on input, resolved addresses on output. Defaults:
family `4`, one worker, ten `EAGAIN` attempts, 500 ms delay, no statistics and
no log files.

- Literal addresses and `ip/bits` of a selected family are passed through
  verbatim (the mask is dropped for a full-length prefix), exactly like the
  upstream tool. A literal of an unselected family is a failure, not a lookup.
- Names are validated with the upstream character set and then resolved by
  worker goroutines. `--threads` bounds the number of concurrent lookups and
  every worker writes complete lines under one lock.
- A temporary failure (the `EAI_AGAIN` analog) is retried up to `--eagain`
  attempts with `--eagain-delay` between attempts. A permanent failure is not
  retried. A lookup that returns no address counts as a failure. The delay is
  not applied after the last attempt; the C original sleeps once more after the
  final `EAI_AGAIN`, which only delays a failure that is already decided.
- `--stats N` prints `mdig stats : HH:MM:SS : domains=N success=N error=N` to
  standard error every `N` input lines and once at the end, like upstream.
  `--eagain-delay` is limited to the library maximum of 100000 ms and `--stats`
  must not be negative; both are rejected before any input, output or log path
  is opened, so a rejected flag value cannot truncate an existing output.
- `--log-resolved`/`--log-failed` must be different files from the input, the
  output and each other; the same filesystem identity rules as above apply.
- Host names appear only in `--log-resolved`/`--log-failed` files and, with
  `--verbose`, in progress diagnostics on standard error. Empty lines are
  counted as failures and are never logged.
- An input line longer than 1024 bytes is an error; the C reader splits a longer
  line at its 255 byte `fgets` buffer into several domain records.
- Output is bounded (1024 addresses per name) and the run stops on context
  cancellation.

The real resolver is wired to the platform resolver (`net.DefaultResolver`) and
only runs when the operator invokes `mdig`. **No DNS query is executed by the
test suite**; all resolver behavior is covered with an injected mock resolver
and an injected clock. A mocked resolution is not DNS evidence.

## dns-make-query and dns-parse-query

```text
sing-box tools desync dns-make-query --name NAME [--family 4|6] [--id 0..65535]
sing-box tools desync dns-parse-query < binary-response > addresses
```

`dns-make-query` writes one binary DNS message to standard output: a 12 byte
header with `RD` set and `QDCOUNT=1`, the label encoded QNAME (one trailing dot
is stripped), `QTYPE` `A` (1) or `AAAA` (28) and `QCLASS` `IN` (1). `--id` pins
the message id for reproducible fixtures; without it a random id from
`crypto/rand` is used (upstream derives the id from the real time clock, which
is not reproducible). Labels longer than 63 bytes, names longer than 253 bytes,
a double trailing dot and empty interior labels are rejected. This matches the
C encoder rather than extending it: an empty label makes the unsigned
`j-i-1u > 62u` check at `mdig.c:351` wrap to a huge value, so
`dns_mk_query_blob` returns 0 and the C tool exits 1 with
`could not make DNS query`.

`dns-parse-query` accepts at most 8191 bytes of a binary response from standard
input and prints the `A`/`AAAA` addresses it contains; the pinned tool reads
into an 8192 byte buffer and additionally requires EOF (`mdig.c:431-443`), so an
empty blob and a blob of 8192 bytes or more are errors. It follows the pinned
rules: `QR` must be set, the question section is skipped, every answer name must
be a compression pointer, and only `TYPE 1` class `IN` with length 4 and
`TYPE 28` class `IN` with length 16 produce output. Name compression pointers
are validated but never dereferenced, so a self-referential pointer cannot loop.
A structurally invalid blob is an error and prints no addresses at all (the C
tool may print answers it already parsed before failing); an empty `A`/`AAAA`
answer set is not an error.

## list-normalize

```text
sing-box tools desync list-normalize --kind domain|ip --manifest path
                                    [--input path|-] [--output path|-]
                                    [--exclude path]...
```

Normalizes one **local** provider snapshot. The command never downloads a list,
never schedules a refresh, never extracts an archive, never executes a path read
from the file and never publishes the result to a running instance. The output
is a sorted, deduplicated newline separated list plus a provenance manifest.

- Input may be plain text or gzip; compression is detected by the magic bytes,
  not by the file name. Decompression is bounded (default 128 MiB) and the input
  file is bounded (default 64 MiB); exceeding either is an error, so a
  decompression bomb stops instead of expanding.
- Blank lines and lines starting with `#` or `;` are ignored. Other lines that
  do not normalize are counted and dropped.
- `--kind domain` lowercases entries, removes one trailing root dot and keeps a
  leading dot (the upstream "subdomains only" spelling) so the normalizer never
  changes matching semantics. Labels must be 1-63 characters of `a-z0-9-_` and
  the name at most 253 characters. There is no IDNA conversion; a Unicode name
  is dropped and must be supplied in punycode form.
- `--kind ip` canonicalizes addresses and masks prefixes to their network
  address, then sorts by address and prefix length.
- `--exclude` files are normalized with the same rules and removed from the
  result. Domains are matched exactly. IP entries are removed when an excluded
  prefix contains the entry (a narrower exclusion never removes a broader
  entry).
- `--manifest` is required and records the raw input hash and size, the
  compression, the decompressed size, line/accepted/invalid/duplicate/excluded
  counts, one record per exclusion file and the hash, size and entry count of the
  normalized output:

```json
{
  "format": "desync.list-manifest/v1",
  "kind": "domain",
  "source": {
    "path": "lists/provider.txt.gz",
    "sha256": "…",
    "size": 167,
    "compression": "gzip",
    "decompressed_size": 222,
    "lines": 9,
    "accepted": 5,
    "invalid": 3,
    "duplicates": 1,
    "excluded": 0
  },
  "excluded": [],
  "output": {"sha256": "…", "size": 96, "entries": 4}
}
```

The output, the manifest and every exclusion file must be different files. The
guard runs in two steps before anything is opened: a cheap lexical comparison of
the absolute, cleaned paths (case-insensitive on Windows, with the trailing dots
and spaces Win32 ignores folded) for names that do not exist yet, and a
filesystem identity comparison for names that do. A path containing `..` after a
symbolic link is refused before either step, because cleaning it would make the
inspection and the later rename refer to different objects (see above). The
identity step resolves input symbolic links and symlinked parent directories and
compares the actual file objects, so hard links, an input symlink that points at
the output, an output reached through a symlinked parent, and a manifest or
exclusion entry that is a hard link of another role are all refused. A write path
whose final component is a symbolic link or a directory is refused, and the
output is never opened with `O_TRUNC` before the check.

Publication is staged, not a two-file transaction: the list and the manifest are
written to temporary files in the destination directories, the manifest
destination is created first, and both are renamed into place only after the
whole import and manifest encoding succeeded. The list is renamed before the
manifest. If the list rename succeeds and the manifest rename fails, the command
reports that the list was published and the manifest was not; it does not roll
the list back. A rejected import (invalid gzip header or CRC, an over-long line,
an invalid flag, a manifest destination that is a link, a directory or under a
missing parent) therefore leaves an existing last-good list and manifest
untouched and does not create a new output. Crash-atomic replacement of both
files as a unit is not provided.

Staging assumes a trusted output directory. A process that can replace entries
in that directory can replace the staged temporary file after it is closed and
before the rename, or replace the destination itself; staging limits accidental
partial files and preserves last-good bytes across validation errors, but it is
not an ownership, signature or authenticity guarantee. Use a directory writable
only by the intended operator account or protected by the platform's access
controls.

With `--output -` the normalized list is streamed to stdout and cannot be rolled
back; the manifest is still staged and published after a successful stream. A
stdout write error reports the partial stream, while every file output is
replaced only by the rename above.

Exclusion filtering is indexed by prefix: an entry is compared against the
distinct excluded prefix lengths instead of every exclusion entry, so a
disjoint IP list is no longer `N*M` work, cancellation is checked every 1024
entries inside the filtering phase, and the accumulated exclusion entries from
all `--exclude` files share a limit (default: the entry limit). The deterministic
prefix-comparison budget is documented in the library options; an entry is
removed only when an excluded prefix contains it (a narrower exclusion never
removes a broader entry).

## blockcheck-report

```text
sing-box tools desync blockcheck-report [--input path|-] [--output path|-]
```

Validates and normalizes an **offline** captured lab result document. The
command performs no network, packet or application check; it validates the
document and re-encodes it deterministically (cases sorted by platform and id,
two-space indent, trailing newline).

```json
{
  "format": "desync.blockcheck/v1",
  "reference": {
    "zapret_revision": "c849e55ef0f1c244206f5a05ff7b1ab41a3824ee",
    "flowseal_revision": "1.10.4"
  },
  "cases": [
    {
      "id": "linux-tls-fake",
      "platform": "linux",
      "strategy": "fake",
      "status": "PASS",
      "evidence": {"artifact": "runs/2026-01-01/linux-tls-fake.pcap", "sha256": "…"},
      "reason": ""
    }
  ]
}
```

Validation rules:

- `format` must be `desync.blockcheck/v1`; both reference revisions must be the
  pinned revisions above.
- Unknown fields at any level, duplicate case ids, more than 4096 cases and an
  empty case list are rejected.
- `id` is `[a-z0-9][a-z0-9._-]{0,63}`, `platform` is `linux` or `windows`,
  `status` is `PASS`, `FAIL` or `SKIP`.
- `PASS` requires an `evidence` object with a non-empty `artifact` and a
  64 character lowercase hex `sha256`. `evidence` is local reference metadata;
  the validator never opens the artifact. `FAIL` and `SKIP` require a non-empty
  `reason`.
- Evidence is not proof. A `PASS` in a document is an operator assertion with a
  pointer to captured material, never a result produced by this tool.

Test fixtures for this parser are synthetic and are labelled as parser inputs;
see `common/desync/tools/testdata/NOTICE.md`. The reproducible Linux/Windows
comparison procedure, which is **not executed in this environment**, is
`docs/examples/desync-tools/blockcheck-reference-procedure.md`.

## Inventory delta

This increment covers, and only covers:

| Row | Coverage |
|---|---|
| D (bulk DNS and diagnostics) | offline `mdig` batch semantics, binary DNS query/answer codec, injectable resolver/clock, no live DNS |
| I (IP aggregation utility) | pinned `ip2net` density/min-count aggregation, options in the upstream `uint32` range, pass-through |
| support / U5 | offline local provider list normalization with provenance, offline `desync.blockcheck/v1` validation and normalization |

Still open, and not claimed by this increment:

- automatic refresh scheduling or a provider updater daemon (not implemented,
  not authorized; `list-refresh` is explicit and operator-invoked only);
- publication of a normalized list into a running instance without an explicit
  `reload` call (the explicit `reload` command and the existing lifecycle own
  it; there is no watcher);
- native blockcheck execution, packet capture and wire comparison on the
  authorized lab (reserved tester stage; no result is claimed here, and
  cross-builds are not native evidence);
- `config.default` and service integration for any of the above;
- full parity of the remaining `nfqws`/`winws`/`tpws` option families owned by
  the packet and stream work.

## Safety notes

- No command starts a client, a service, a tunnel or a subprocess.
- No command changes host firewall, route, interface, namespace or privilege
  state.
- No command writes to the network. `mdig` uses the platform resolver only when
  the operator runs it; everything else is pure local transformation.
- Write destinations are opened with `O_CREATE` but without `O_TRUNC`, after
  refusing a final-component symbolic link, a directory or another non-regular
  file. The opened descriptor is compared with the open inputs and only then
  truncated: POSIX uses `O_NOFOLLOW`, and Windows uses
  `FILE_FLAG_OPEN_REPARSE_POINT` plus a reparse-tag check on the acquired handle
  before truncation. This refuses redirection through a replaced final entry; it
  is not a crash-atomic multi-file publication and does not provide durability
  across a crash.
- Staged list publication assumes a trusted output directory: a writer able to
  replace entries in that directory can replace the staged file or the
  destination, which is outside the tool's protection boundary.
