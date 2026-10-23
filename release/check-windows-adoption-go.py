#!/usr/bin/env python3
"""Qualify a cached Go toolchain for the Windows console build.

The Windows socket-adoption path (accepted decision
`direct-desync/windows-adoption/v1.0`) references exactly one non-public Go
symbol, `net.newWindowsFile`, so the Windows console build must use the
unmodified, audited Go1.26.9 toolchain: its `FileConn` duplication propagates
duplication errors, and its socket-aware File constructor disposes of a Winsock
carrier with `closesocket`. The module's `go 1.25.5` directive is not a
toolchain qualification; a build constraint can only refuse other minor
versions, not select the audited patch release.

This helper performs that exact-version qualification without installing
anything and without running the product:

    python3 release/check-windows-adoption-go.py --go <cached-go-executable>

It verifies:
  * the toolchain reports exactly go1.26.9;
  * GOOS/GOARCH are windows/amd64;
  * the five audited standard-library sources under GOROOT have the pinned
    SHA-256 values (constructor, FileConn duplication, poll disposal, linker
    linkname restriction);
  * the project release link flags contain `-checklinkname=0`.

Exit 0 only when every check matches. Any mismatch is a failed build
qualification: there is no generic-File or plaintext fallback.
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

# Audited go1.26.9 standard-library sources. Paths are relative to GOROOT.
AUDITED_SOURCES = {
    "os/file_windows.go": (
        "c22ecd7dd18b10a3091f7c1d7deae868a64e7adcf046c8ca62d3666e73edfcc7",
        "socket-aware File constructor net.newWindowsFile (kindSock)",
    ),
    "net/file_windows.go": (
        "33005305d01549b938d1f6c08fa7b3ac0dd899f4575ebf9cf9522ec1cbac23e8",
        "dupFileSocket duplication error propagation",
    ),
    "net/file_posix.go": (
        "db3c6b88dad9f5ac472d2aebbac3e2ccfa18645718d99fde31a31967b8021bac",
        "fileConn/newFileFD ownership and setup-failure cleanup",
    ),
    "internal/poll/fd_windows.go": (
        "a6ed6ff45e39c6c49eb42c43bc07f2290315edcd63a2fb6e4028782ac3a8e950",
        "kindFileNet disposal through CloseFunc (closesocket)",
    ),
    "cmd/link/internal/loader/loader.go": (
        "0b6b271aee4951e7202e854795c008733f0f2a6f5726603c7067eda3a2413dfe",
        "linkname restriction of net.newWindowsFile to package net",
    ),
}


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
    if not (goroot / "src" / "os" / "file_windows.go").is_file():
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

    ldflags_path = pathlib.Path(product_dir) / "release" / "LDFLAGS"
    if not ldflags_path.is_file():
        raise QualificationError(f"release link flags are missing: {ldflags_path}")
    ldflags = ldflags_path.read_text(encoding="utf-8").strip()
    if REQUIRED_LDFLAG not in ldflags.split():
        raise QualificationError(
            f"{ldflags_path} does not contain {REQUIRED_LDFLAG}: the single "
            "enumerated socket constructor symbol would be rejected by a checked link"
        )

    return {
        "toolchain": version_line,
        "version": version,
        "goos": goos,
        "goarch": goarch,
        "goroot": str(goroot),
        "audited_sources": fingerprints,
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
