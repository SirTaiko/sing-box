#!/usr/bin/env python3
"""Qualify a cached Go toolchain for the Windows console build.

The direct-owned Windows socket adoption references exactly five non-public Go
symbols of the standard-library connection lifecycle:

    net.newFD, net.(*netFD).init, net.(*netFD).setAddr,
    net.(*netFD).Close, net.newTCPConn

so the Windows console build must use the unmodified, audited Go1.26.9
toolchain. The module's `go 1.25.5` directive is not a toolchain qualification;
a build constraint can only refuse other minor versions, not select the audited
patch release.

This helper performs that exact-version qualification without installing
anything and without running the product:

    GOOS=windows GOARCH=amd64 python3 release/check-windows-adoption-go.py \
        --go <cached-go-executable>

It verifies:
  * the toolchain reports exactly go1.26.9;
  * GOOS/GOARCH are windows/amd64;
  * the fifteen audited standard-library sources under GOROOT have the pinned
    SHA-256 values (FD construction, addresses/finalizer/Close, TCPConn and its
    keepalive/NoDelay defaults, public Read/Write ownership, poll disposal and
    destruction, runtime IOCP/poll lifecycle, linker policy);
  * the adoption constructor declares exactly the five enumerated symbols with
    their exact signatures, and neither the constructor nor the adoption path
    references net.FileConn/os.NewFile, mirrors private layouts, or converts the
    FD through uintptr;
  * the project release link flags contain `-checklinkname=0`.

Exit 0 only when every check matches. Any mismatch is a failed build
qualification: there is no FileConn, generic-File or plaintext fallback.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

EXPECTED_VERSION = "go1.26.9"
EXPECTED_GOOS = "windows"
EXPECTED_GOARCH = "amd64"
REQUIRED_LDFLAG = "-checklinkname=0"

# Audited go1.26.9 standard-library sources. Paths are relative to GOROOT/src.
AUDITED_SOURCES = {
    "net/fd_windows.go": (
        "8008f4a0bd9fc58a23b3fea17ffdb15e4739c19585c60589b764076d225972ff",
        "net.newFD exact allocation and (*netFD).init",
    ),
    "net/fd_posix.go": (
        "31e1ad8e0ed8b6a86d9f547c9695a1d67b35a553e0e251ea66362fb22c5354f2",
        "netFD structure, setAddr/finalizer and Close",
    ),
    "net/tcpsock.go": (
        "0c3392bd7c2966f894e01ea27514623cf09dc2660e426049219f7e5ee3ec0f74",
        "net.newTCPConn exact five-argument signature and body",
    ),
    "net/dial.go": (
        "9963e94645bb8620e61bf219236a5d859b17de161344d433b93bedd6f3ad1e1e",
        "existing TCP keepalive defaults",
    ),
    "net/tcpsockopt_posix.go": (
        "16d8565b480a743e5d75ccc457fbb2dc46f4fcf3a681ea01bf45be0f057e348d",
        "NoDelay setter",
    ),
    "net/tcpsockopt_windows.go": (
        "4492fd3fe6d4e7e131a04547f0f2e6c7ea36bae8d442569112e1168fed401c5e",
        "Windows keepalive setters",
    ),
    "net/tcpsock_windows.go": (
        "91054c727154f7e7b3ad3dd44a19ebf0e8846b11df7b9bb79b30b6b887fb3762",
        "TCPConn.SetKeepAliveConfig",
    ),
    "net/net.go": (
        "35a3d5047c156a1395c4c197fad5a99e123567a12ae7bc08ba7d5c723281ae03",
        "public conn Close forwarding and Read/Write ownership",
    ),
    "internal/poll/fd_windows.go": (
        "a6ed6ff45e39c6c49eb42c43bc07f2290315edcd63a2fb6e4028782ac3a8e950",
        "Init/IOCP/completion policy/Close/destroy",
    ),
    "internal/poll/fd_poll_runtime.go": (
        "88fda43019c5dcf42545effdebd1747aaea377560dd041a35df8499538ee07c5",
        "poll init, evict, close, deadlines",
    ),
    "internal/poll/fd_mutex.go": (
        "ad10a59470d3848a745f9549afcee67aae9553e385ec41988d7e5266c2bc3902",
        "unpublished FD direct destruction error propagation",
    ),
    "internal/poll/hook_windows.go": (
        "b63c32b4a5f03051f4bd78bb4440232fd929ba90be8e66cb404aa2f31dc12c5b",
        "default CloseFunc is syscall.Closesocket",
    ),
    "runtime/netpoll_windows.go": (
        "9a0727cc4b9fb93de904123083f4f9fe05af1f9b14a67218a3cb812eb1f9ce62",
        "runtime IOCP association",
    ),
    "runtime/netpoll.go": (
        "f7c606d3fa0a3b9499fd5f42b81918a98f0b99a6029fca2010cabc710fc9ea65",
        "poll descriptor allocation/failure/close lifecycle",
    ),
    "cmd/link/internal/loader/loader.go": (
        "0b6b271aee4951e7202e854795c008733f0f2a6f5726603c7067eda3a2413dfe",
        "existing unchecked-link policy, not ABI verification",
    ),
}

# The exact enumerated exception boundary of the direct-owned adoption.
QUALIFIED_SYMBOLS = [
    "//go:linkname goNetNewFD net.newFD",
    "//go:linkname goNetFDInit net.(*netFD).init",
    "//go:linkname goNetFDSetAddr net.(*netFD).setAddr",
    "//go:linkname goNetFDClose net.(*netFD).Close",
    "//go:linkname goNetNewTCPConn net.newTCPConn",
]

QUALIFIED_SIGNATURES = [
    "func goNetNewFD(sysfd syscall.Handle, family, sotype int, network string) (unsafe.Pointer, error)",
    "func goNetFDInit(fd unsafe.Pointer) error",
    "func goNetFDSetAddr(fd unsafe.Pointer, local, remote net.Addr)",
    "func goNetFDClose(fd unsafe.Pointer) error",
    "func goNetNewTCPConn(fd unsafe.Pointer, idle time.Duration, cfg net.KeepAliveConfig, preHook func(unsafe.Pointer), hook func(net.KeepAliveConfig)) *net.TCPConn",
]

# The superseded FileConn boundary, mirrored private layouts and pointer
# round-trips must not reappear in the adoption sources.
PROHIBITED_ADOPTION_TEXT = [
    "net.FileConn(",
    "os.NewFile(",
    "net.newWindowsFile",
    "net_newWindowsFile",
    "dupFileSocket",
    "unsafe.Sizeof(",
    "unsafe.Offsetof(",
    "uintptr(fd)",
    "unsafe.Pointer(uintptr",
    "type netFD struct",
    "type pollFD struct",
    "type tcpConn struct",
]

ADOPTION_FILES = [
    "common/dialer/attempt_windows.go",
    "common/dialer/attempt_windows_adoption_ctor.go",
    "common/dialer/attempt_windows_adoption_ctor_unsupported.go",
]


class QualificationError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def go_env(go, name):
    result = subprocess.run(
        [str(go), "env", name], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise QualificationError(
            f"`{go} env {name}` failed with exit {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def go_version(go):
    result = subprocess.run(
        [str(go), "version"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise QualificationError(
            f"`{go} version` failed with exit {result.returncode}: {result.stderr.strip()}"
        )
    fields = result.stdout.split()
    if len(fields) < 3 or fields[0] != "go":
        raise QualificationError(f"unexpected `go version` output: {result.stdout!r}")
    return fields[2], result.stdout.strip()


def qualify_adoption_sources(product_dir):
    adoption_text = {}
    for relative in ADOPTION_FILES:
        path = product_dir / relative
        if not path.is_file():
            raise QualificationError(f"adoption source is missing: {path}")
        text = path.read_text(encoding="utf-8")
        adoption_text[relative] = text
        for prohibited in PROHIBITED_ADOPTION_TEXT:
            if prohibited in text:
                raise QualificationError(
                    f"{relative} contains the superseded/prohibited boundary {prohibited!r}"
                )

    ctor = adoption_text["common/dialer/attempt_windows_adoption_ctor.go"]
    for directive in QUALIFIED_SYMBOLS:
        if ctor.count(directive) != 1:
            raise QualificationError(
                f"adoption constructor must declare {directive!r} exactly once"
            )
    for signature in QUALIFIED_SIGNATURES:
        if signature not in ctor:
            raise QualificationError(
                f"adoption constructor is missing the qualified signature {signature!r}"
            )

    package_dir = product_dir / "common" / "dialer"
    directives = []
    for path in sorted(package_dir.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("//go:linkname"):
                directives.append(line.strip())
    if directives != QUALIFIED_SYMBOLS:
        raise QualificationError(
            f"package go:linkname directives = {directives!r}, "
            f"want exactly {QUALIFIED_SYMBOLS!r}"
        )

    unsupported = adoption_text["common/dialer/attempt_windows_adoption_ctor_unsupported.go"]
    if "//go:build windows && (!go1.26 || go1.27)" not in unsupported:
        raise QualificationError(
            "the unqualified-toolchain file must refuse the build by convention"
        )
    if "newOwnedSocketConn" not in unsupported:
        raise QualificationError(
            "the unqualified-toolchain file must fail closed on the missing direct-owned bridge"
        )


def qualify(go, product_dir):
    go = pathlib.Path(go)
    if not go.is_file():
        raise QualificationError(f"Go executable not found: {go}")

    version, version_line = go_version(go)
    if version != EXPECTED_VERSION:
        raise QualificationError(
            f"toolchain version is {version!r} ({version_line}), "
            f"but the Windows adoption boundary is qualified only for {EXPECTED_VERSION!r}"
        )

    goroot = pathlib.Path(go_env(go, "GOROOT"))
    if not (goroot / "src" / "net" / "fd_windows.go").is_file():
        raise QualificationError(f"GOROOT {goroot} does not contain the Windows sources")

    fingerprints = {}
    for relative, (expected, purpose) in AUDITED_SOURCES.items():
        path = goroot / "src" / relative
        if not path.is_file():
            raise QualificationError(f"audited source is missing: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise QualificationError(
                f"audited source {relative} has SHA-256 {actual}, expected {expected} ({purpose})"
            )
        fingerprints[relative] = actual

    goos = go_env(go, "GOOS")
    goarch = go_env(go, "GOARCH")
    if (goos, goarch) != (EXPECTED_GOOS, EXPECTED_GOARCH):
        raise QualificationError(
            f"toolchain target is {goos}/{goarch}, expected {EXPECTED_GOOS}/{EXPECTED_GOARCH}"
        )

    product_dir = pathlib.Path(product_dir)
    ldflags_path = product_dir / "release" / "LDFLAGS"
    if not ldflags_path.is_file():
        raise QualificationError(f"release link flags are missing: {ldflags_path}")
    ldflags = ldflags_path.read_text(encoding="utf-8").strip()
    if REQUIRED_LDFLAG not in ldflags.split():
        raise QualificationError(
            f"{ldflags_path} does not contain {REQUIRED_LDFLAG}: the five enumerated "
            "standard-library symbols would be rejected by a checked link"
        )

    qualify_adoption_sources(product_dir)

    return {
        "toolchain": version_line,
        "version": version,
        "goos": goos,
        "goarch": goarch,
        "goroot": str(goroot),
        "audited_sources": fingerprints,
        "qualified_symbols": QUALIFIED_SYMBOLS,
        "ldflags": ldflags,
        "flags": [f"-ldflags={ldflags}"],
    }


def main(argv):
    parser = argparse.ArgumentParser(
        description="Qualify the cached Go toolchain for the Windows console build."
    )
    parser.add_argument("--go", required=True, help="path to the cached go executable")
    parser.add_argument(
        "--product-dir",
        default=str(pathlib.Path(__file__).resolve().parent.parent),
        help="sing-box checkout root (defaults to the parent of release/)",
    )
    args = parser.parse_args(argv)
    try:
        report = qualify(args.go, args.product_dir)
    except QualificationError as error:
        print(f"Windows adoption toolchain qualification FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    print("Windows adoption toolchain qualification PASSED", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
