# Building the console core with the SOCKS wire-contract dependency patch

This document describes the reproducible console build path for the narrow
downstream dependency delta accepted as `direct-desync/socks-wire-contract/v1.1`.
It applies to the standalone console `sing-box` core on Ubuntu and Windows. It
does not cover Desktop integration, services, installers or any runtime daemon.

## Why a prepared dependency is required

The pin `github.com/sagernet/sing v0.9.7-0.20260929150544-0ad23b637bd4` exposes
neither the original SOCKS request address form nor a place to hand the
already-buffered handshake bytes to the inbound. The accepted fix is a narrow,
hash-locked downstream patch to exactly three production files:

- `protocol/socks/handshake.go` — bounded `Peek(4)` (SOCKS5) / `Peek(7)`
  (SOCKS4) at the existing shared handshake boundary, plus one exact transfer of
  the already-buffered parser tail into an existing `buf.Buffer`/`CachedConn`.
- `protocol/socks/lazy.go` — immutable `RequestMetadata{Version,
  DestinationFamily}` and the optional `RequestMetadataProvider` capability on
  the existing `LazyConn`.
- `common/bufio/cache.go` — the shared `CachedConn` now owns its cached tail
  under one short critical section, so concurrent `Read`, `ReadCached`,
  `WriteTo`, `ReaderReplaceable` and `Close` deliver the tail exactly once and
  release the pooled buffer exactly once, while `Close` still unblocks a
  blocked socket read without holding a lock across socket I/O.

The patch does not fork the parser, change the serializer, add a dependency,
change the Go or toolchain directive, or modify the module cache.

**Standard build limitation:** an ordinary `go build ./cmd/sing-box` in this
repository still uses the unmodified cached module and therefore does **not**
contain the wire-provenance contract. The patched console build requires the
preparation step and the generated alternate modfile described below. This
route is a maintained downstream patch, not an upstream release.

## Ubuntu (preparation and build)

Prerequisites: the pinned module and Go 1.25.5 available in the local module
cache (`GOMODCACHE`), Python 3, and `git` (or GNU `patch`).

```sh
# 1. Prepare an isolated, verified copy of the pinned dependency.
#    --output-dir is explicit and must be a new, empty directory.
python3 release/patches/prepare-sing-socks-wire.py \
    --product-dir "$PWD" \
    --output-dir /tmp/sing-socks-wire-build

# 2. Build the console core for Ubuntu with the generated alternate modfile.
CGO_ENABLED=0 go build \
    -modfile=/tmp/sing-socks-wire-build/go.sing-socks-wire.mod \
    -o /tmp/sing-socks-wire-build/sing-box-linux-amd64 \
    ./cmd/sing-box

# 3. Optional: run the affected tests against the prepared dependency.
go test -modfile=/tmp/sing-socks-wire-build/go.sing-socks-wire.mod \
    ./protocol/socks/... ./option/...
```

The helper verifies the pinned module archive hash, derives the complete source
tree from that verified archive only, verifies the patch hash, the base hashes
and every patched file hash, and finally compares the whole prepared tree
membership and content against the archive bytes plus the approved patched
files. The archive is read exactly once into a bounded in-memory buffer, the
pinned SHA-256 is checked on exactly that buffer, and extraction plus the
whole-tree comparison consume those same bytes; replacing the cached `.zip`
pathname, or rewriting the same inode, after the hash check therefore cannot
change the prepared tree. Archive entries with absolute paths, parent
traversal, symbolic links or excessive size are rejected. An expanded copy of
the module in `GOMODCACHE` is never copied or trusted, so a modified or
extended expanded cache cannot change the prepared tree. The helper never
writes to `GOMODCACHE`, never edits the product `go.mod` or `go.sum`, and
refuses a non-empty output directory.

## Windows toolchain qualification (required)

The Windows console build has one additional, hard requirement:
**unmodified Go 1.26.9**, selected as an explicit cached executable. This is not
a Go version preference and it is not a `go.mod` change: the module keeps
`go 1.25.5`, Linux keeps the existing Go 1.25.5 build, and `go.sum` and the
module cache are untouched.

Why: the enabled Windows TCP path adopts a native ConnectEx socket through one
`net.FileConn` call, and the `*os.File` carrier that call needs must be created
by the socket-aware constructor `net.newWindowsFile`. `os.NewFile` classifies a
Winsock descriptor as an ordinary file, so both `File.Close` and the `File`
finalizer would dispose of it with `CloseHandle`, which Microsoft forbids for
sockets. The carrier is also where `net.FileConn` performs its own duplication;
the Go1.25.5 body loses a `WSADuplicateSocket`/`WSASocket` error behind a
successful `SyscallConn().Control` callback and can return a zero descriptor
with a nil error, while the inspected Go1.26.9 body propagates it.

Two consequences must be stated honestly:

* The qualified toolchain applies to **every** Windows console build, including
  deployments that disable desync at runtime. The disabled fast path is a
  runtime guarantee, not a return of Go 1.25 Windows build compatibility, because
  the constructor file is compiled into the console binary.
* The single internal symbol is reachable only because the project already links
  the console with `-checklinkname=0` (see `release/LDFLAGS` and
  `cmd/internal/build_shared`). That is a blanket linker policy, **not** a
  per-symbol permission and not a general internal-ABI waiver; a checked link
  rejects the reference with `link: ... invalid reference to net.newWindowsFile`.

Qualify the exact cached toolchain before building (exit 0 required):

```sh
GOOS=windows GOARCH=amd64 python3 release/check-windows-adoption-go.py \
    --go /path/to/go1.26.9/bin/go
```

The helper checks the exact `go1.26.9` version, the requested target, the pinned
SHA-256 of the five audited standard-library sources (socket-aware constructor,
`FileConn` duplication, poll disposal, linker linkname restriction) and the
presence of `-checklinkname=0` in `release/LDFLAGS`. Any mismatch fails the
qualification; there is no generic-File or plaintext fallback. The Windows build
constraint refuses other Go minor versions at compile time
(`windows && go1.26 && !go1.27`); the patch-release requirement is enforced by
this qualification gate, not by a build tag.

## Windows (cross build from Ubuntu or native preparation)

The preparation step is identical; only the build environment changes:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -ldflags="$(cat release/LDFLAGS)" \
    -modfile=/tmp/sing-socks-wire-build/go.sing-socks-wire.mod \
    -o /tmp/sing-socks-wire-build/sing-box-windows-amd64.exe \
    ./cmd/sing-box
```

The Windows `-ldflags` are required (the qualification helper verifies them);
the Ubuntu build does not need them for this path. Windows test binaries need
the same linker setting, for example
`GOOS=windows GOARCH=amd64 go test -c -ldflags=-checklinkname=0 ./common/dialer`.

The generated modfile contains one added line:

```
replace github.com/sagernet/sing => /absolute/path/to/sing-socks-wire-build/sing-socks-wire
```

`go.sing-socks-wire.sum` is a copy of the product `go.sum`; no checksum for the
patched source is implied, because filesystem replacements are not authenticated
by module sums. The bundle therefore records the base archive hash, the patch
hash and the patched source manifest together
(`release/patches/sing-socks-wire-contract.json`).

## Reproducibility record

Every preparation writes `sing-socks-wire-manifest.json` in the output
directory with the verified identities of the module archive, patch, alternate
modfile and prepared tree: `source_archive_sha256`, `patch_sha256`,
`tree_sha256` (a digest over every prepared path and its SHA-256) and
`file_count`. Two independent output directories prepared from the same bundle
must produce byte-identical patched source trees and the same `tree_sha256`.
`release/patches/prepare-sing-socks-wire_test.py` permanently covers the
ordinary preparation, pre-validation tamper rejection, post-validation
pathname replacement and same-inode rewrite; in the last two controls the
cached archive is altered after its real hash check and the prepared tree must
still contain only the verified bytes.

## Configuration

The wire-provenance contract is a correctness repair of `no_resolve`; it adds no
option. See `docs/configuration/direct-desync-socks.md` for the policy.
