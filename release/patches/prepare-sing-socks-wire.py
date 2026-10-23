#!/usr/bin/env python3
"""Prepare the hash-locked SOCKS wire-contract dependency bundle.

The helper never writes to the Go module cache. It verifies the pinned
github.com/sagernet/sing module archive, reads it exactly once into a bounded
in-memory buffer, and derives the complete dependency source tree from the same
bytes whose SHA-256 it checked. Hashing one open and extracting from another
open of the same pathname (or of a rewritable inode) would let a post-check
replacement reach the prepared tree, so that is not done: extraction and the
whole-tree comparison consume only the verified buffer. The helper applies
release/patches/sing-socks-wire-contract.patch, verifies the whole resulting
membership and content against the archive plus patch manifest, and writes an
alternate go.mod that replaces only that module with the generated path. The
product go.mod, go.sum and the normal module cache are left untouched. An
expanded copy of the module in the module cache is never copied or trusted.

Usage:
    python3 prepare-sing-socks-wire.py --product-dir <sing-box checkout> \
        --output-dir <new directory>
"""

import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import zipfile

PATCH_NAME = "sing-socks-wire-contract.patch"
MANIFEST_NAME = "sing-socks-wire-contract.json"
ALT_MOD = "go.sing-socks-wire.mod"
ALT_SUM = "go.sing-socks-wire.sum"
MODULE_PATH = "github.com/sagernet/sing"
MODULE_VERSION = "v0.9.7-0.20260929150544-0ad23b637bd4"

# Bounds for the verified archive. The pinned module is a small Go source
# archive; these limits reject an oversized or hostile replacement archive
# without needing a signature system. The archive is read once into memory, so
# the raw archive bytes have their own hard bound as well.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024


class PreparationError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(helper_dir):
    manifest_path = os.path.join(helper_dir, MANIFEST_NAME)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest["module"]["path"] != MODULE_PATH or manifest["module"]["version"] != MODULE_VERSION:
        raise PreparationError("manifest does not describe the pinned module")
    return manifest_path, manifest


def read_archive_bytes(zip_path):
    """Read the whole archive once into memory under a hard size bound."""
    chunks = []
    total = 0
    try:
        with open(zip_path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise PreparationError("module archive is too large")
                chunks.append(chunk)
    except OSError as error:
        raise PreparationError("module archive is not readable: " + str(error))
    return b"".join(chunks)


def module_archive(manifest, module_cache):
    """Return the verified identity and immutable bytes of the pinned archive.

    The pinned SHA-256 is checked on exactly the buffer that is returned, and
    every later step consumes only that buffer. Replacing the cache pathname,
    or rewriting the same inode, after this function returns therefore cannot
    change the bytes used to build and verify the prepared tree.
    """
    zip_path = os.path.join(
        module_cache, "cache", "download", manifest["module"]["path"], "@v",
        manifest["module"]["version"] + ".zip",
    )
    if not os.path.isfile(zip_path):
        raise PreparationError("pinned module archive is not present in the module cache: " + zip_path)
    data = read_archive_bytes(zip_path)
    actual_zip = hashlib.sha256(data).hexdigest()
    if actual_zip != manifest["module"]["cache_zip_sha256"]:
        raise PreparationError("module archive hash mismatch: " + actual_zip)
    return actual_zip, data


def read_archive(manifest, archive_bytes):
    """Return {module-relative path: bytes} taken only from the verified archive bytes."""
    prefix = manifest["module"]["path"] + "@" + manifest["module"]["version"] + "/"
    entries = {}
    total = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as error:
        raise PreparationError("module archive is not readable: " + str(error))
    with archive:
        for info in archive.infolist():
            name = info.filename
            if not name.startswith(prefix):
                raise PreparationError("archive entry outside the pinned module: " + name)
            relative = name[len(prefix):]
            if not relative:
                continue
            if relative.startswith("/") or "\\" in relative:
                raise PreparationError("unsafe archive entry path: " + relative)
            if ".." in pathlib.PurePosixPath(relative).parts:
                raise PreparationError("unsafe archive entry path: " + relative)
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                raise PreparationError("archive entry is a symbolic link: " + relative)
            if info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                raise PreparationError("archive entry is too large: " + relative)
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise PreparationError("module archive is too large")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise PreparationError("archive entry is truncated: " + relative)
            entries[relative] = data
    if not entries:
        raise PreparationError("module archive contains no source files")
    return entries


def write_module(entries, module_dir):
    """Write the verified archive bytes; nothing else is ever copied in."""
    os.makedirs(module_dir, exist_ok=False)
    for relative, data in entries.items():
        path = os.path.join(module_dir, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    for root, directories, files in os.walk(module_dir):
        os.chmod(root, 0o755)
        for name in files:
            os.chmod(os.path.join(root, name), 0o644)


def verify_files(root, manifest, use_patched):
    key = "patched_sha256" if use_patched else "base_sha256"
    for entry in manifest["files"]:
        expected = entry.get(key)
        if expected is None:
            continue
        path = os.path.join(root, entry["path"])
        if not os.path.isfile(path):
            raise PreparationError("missing file: " + entry["path"])
        actual = sha256_file(path)
        if actual != expected:
            raise PreparationError("hash mismatch for %s: %s" % (entry["path"], actual))


def expected_tree(entries, manifest):
    """Whole expected tree: verified archive bytes with the approved patch applied."""
    expected = {path: hashlib.sha256(data).hexdigest() for path, data in entries.items()}
    for entry in manifest["files"]:
        patched = entry.get("patched_sha256")
        if patched is not None:
            expected[entry["path"]] = patched
    return expected


def scan_tree(root):
    actual = {}
    for current, directories, files in os.walk(root):
        for name in files:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            actual[relative] = sha256_file(path)
    return actual


def tree_digest(tree):
    digest = hashlib.sha256()
    for path in sorted(tree):
        digest.update(path.encode("utf-8") + b"\0" + tree[path].encode("ascii") + b"\n")
    return digest.hexdigest()


def verify_tree(root, entries, manifest):
    """Reject anything that is not the authenticated archive plus approved patch."""
    expected = expected_tree(entries, manifest)
    actual = scan_tree(root)
    if actual == expected:
        return actual
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(actual) & set(expected) if actual[path] != expected[path])
    raise PreparationError(
        "prepared source does not match the verified archive plus approved patch:"
        " missing=%s unexpected=%s changed=%s" % (missing[:5], unexpected[:5], changed[:5])
    )


def apply_patch(module_dir, patch_path):
    if shutil.which("git"):
        command = ["git", "apply", "-p1", patch_path]
    else:
        command = ["patch", "-p1", "--forward", "-i", patch_path]
    result = subprocess.run(command, cwd=module_dir, capture_output=True, text=True)
    if result.returncode != 0:
        raise PreparationError("patch did not apply: " + (result.stderr or result.stdout).strip())


def write_alternate_module(product_dir, output_dir, module_dir):
    product_mod = os.path.join(product_dir, "go.mod")
    product_sum = os.path.join(product_dir, "go.sum")
    if not os.path.isfile(product_mod):
        raise PreparationError("product go.mod not found: " + product_mod)
    with open(product_mod, "r", encoding="utf-8") as handle:
        content = handle.read()
    if "replace " + MODULE_PATH + " " in content or "replace " + MODULE_PATH + " =>" in content:
        raise PreparationError("product go.mod already replaces " + MODULE_PATH)
    content = content.rstrip("\n") + "\n\nreplace " + MODULE_PATH + " => " + os.path.abspath(module_dir) + "\n"
    with open(os.path.join(output_dir, ALT_MOD), "w", encoding="utf-8") as handle:
        handle.write(content)
    if os.path.isfile(product_sum):
        shutil.copyfile(product_sum, os.path.join(output_dir, ALT_SUM))


def prepare(product_dir, output_dir, module_cache, helper_dir, force):
    manifest_path, manifest = load_manifest(helper_dir)
    patch_path = os.path.join(helper_dir, PATCH_NAME)
    if not os.path.isfile(patch_path):
        raise PreparationError("patch file not found: " + patch_path)
    actual_patch = sha256_file(patch_path)
    if actual_patch != manifest["patch"]["sha256"]:
        raise PreparationError("patch hash mismatch: " + actual_patch)
    if os.path.abspath(output_dir) == os.path.abspath(product_dir):
        raise PreparationError("output directory must differ from the product directory")
    if os.path.exists(output_dir) and os.listdir(output_dir):
        if not force:
            raise PreparationError("output directory is not empty: " + output_dir)
        raise PreparationError("refusing to overwrite an existing output directory even with --force; choose a new directory")
    archive_sha256, archive_bytes = module_archive(manifest, module_cache)
    entries = read_archive(manifest, archive_bytes)
    os.makedirs(output_dir, exist_ok=True)
    module_dir = os.path.join(output_dir, "sing-socks-wire")
    write_module(entries, module_dir)
    verify_files(module_dir, manifest, use_patched=False)
    apply_patch(module_dir, patch_path)
    verify_files(module_dir, manifest, use_patched=True)
    tree = verify_tree(module_dir, entries, manifest)
    write_alternate_module(product_dir, output_dir, module_dir)
    result = {
        "module": manifest["module"],
        "patch_sha256": actual_patch,
        "manifest_sha256": sha256_file(manifest_path),
        "module_dir": os.path.abspath(module_dir),
        "alternate_modfile": os.path.abspath(os.path.join(output_dir, ALT_MOD)),
        "alternate_sumfile": os.path.abspath(os.path.join(output_dir, ALT_SUM)),
        "source_archive_sha256": archive_sha256,
        "tree_sha256": tree_digest(tree),
        "file_count": len(tree),
        "go_version": manifest["toolchain"]["required_go"],
    }
    with open(os.path.join(output_dir, "sing-socks-wire-manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-dir", required=True, help="sing-box checkout containing go.mod/go.sum")
    parser.add_argument("--output-dir", required=True, help="explicit output directory for the prepared dependency")
    parser.add_argument("--module-cache", default=os.environ.get("GOMODCACHE") or os.path.join(os.path.expanduser("~"), "go", "pkg", "mod"))
    parser.add_argument("--force", action="store_true", help="reserved; existing outputs are never overwritten")
    arguments = parser.parse_args(argv)
    helper_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        result = prepare(
            os.path.abspath(arguments.product_dir),
            os.path.abspath(arguments.output_dir),
            os.path.abspath(arguments.module_cache),
            helper_dir,
            arguments.force,
        )
    except PreparationError as error:
        print("prepare-sing-socks-wire: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
