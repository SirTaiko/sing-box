#!/usr/bin/env python3
"""Validation and failure-mode tests for prepare-sing-socks-wire.py."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

# Never leave a __pycache__ directory inside the product checkout.
sys.dont_write_bytecode = True

HELPER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prepare-sing-socks-wire.py")
PRODUCT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE_PATH = "github.com/sagernet/sing"
MODULE_VERSION = "v0.9.7-0.20260929150544-0ad23b637bd4"


def load_helper():
    spec = importlib.util.spec_from_file_location("prepare_sing_socks_wire", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def module_cache_root():
    return os.environ.get("GOMODCACHE") or os.path.join(os.path.expanduser("~"), "go", "pkg", "mod")


def pinned_zip_path(cache_root):
    return os.path.join(cache_root, "cache", "download", MODULE_PATH, "@v", MODULE_VERSION + ".zip")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hashes(root):
    result = {}
    for current, directories, files in os.walk(root):
        for name in files:
            path = os.path.join(current, name)
            result[os.path.relpath(path, root).replace(os.sep, "/")] = sha256_file(path)
    return result


MARKER_RELATIVE = "common/security_archive_marker.go"
MARKER_SOURCE = 'package common\n\nconst SecurityArchiveMarker = "unverified-after-hash"\n'


def archive_bytes_of(path):
    with open(path, "rb") as handle:
        return handle.read()


def malicious_archive_bytes(pinned_bytes):
    """Return a well-formed copy of the pinned archive plus one extra Go file."""
    prefix = MODULE_PATH + "@" + MODULE_VERSION + "/"
    target = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(pinned_bytes)) as original:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as replacement:
            for info in original.infolist():
                replacement.writestr(info, original.read(info))
            # Fixed timestamp so the control fixture is byte-for-byte reproducible.
            marker = zipfile.ZipInfo(prefix + MARKER_RELATIVE, date_time=(1980, 1, 1, 0, 0, 0))
            marker.compress_type = zipfile.ZIP_DEFLATED
            marker.external_attr = 0o644 << 16
            replacement.writestr(marker, MARKER_SOURCE)
    return target.getvalue()


def extraction_call_line():
    """Line number of the extraction call inside prepare() in the actual helper."""
    with open(HELPER_PATH, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if line.strip().startswith("entries = read_archive("):
                return number
    raise AssertionError("helper does not extract the verified archive in prepare()")


class PrepareHelperTest(unittest.TestCase):
    def setUp(self):
        self.helper = load_helper()
        self.tempdir = tempfile.mkdtemp(prefix="socks-wire-test-")

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def copy_helper(self):
        helper_dir = os.path.join(self.tempdir, "helper")
        os.makedirs(helper_dir, exist_ok=True)
        shutil.copyfile(os.path.join(os.path.dirname(HELPER_PATH), "sing-socks-wire-contract.json"),
                        os.path.join(helper_dir, "sing-socks-wire-contract.json"))
        shutil.copyfile(os.path.join(os.path.dirname(HELPER_PATH), "sing-socks-wire-contract.patch"),
                        os.path.join(helper_dir, "sing-socks-wire-contract.patch"))
        return helper_dir

    def test_patch_hash_mismatch_is_rejected(self):
        helper_dir = os.path.join(self.tempdir, "helper")
        os.makedirs(helper_dir)
        shutil.copyfile(os.path.join(os.path.dirname(HELPER_PATH), "sing-socks-wire-contract.json"),
                        os.path.join(helper_dir, "sing-socks-wire-contract.json"))
        with open(os.path.join(helper_dir, "sing-socks-wire-contract.patch"), "w", encoding="utf-8") as handle:
            handle.write("not the pinned patch\n")
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.prepare(PRODUCT_DIR, os.path.join(self.tempdir, "out"), self.tempdir, helper_dir, False)
        self.assertIn("patch hash mismatch", str(raised.exception))

    def test_non_empty_output_directory_is_rejected(self):
        output_dir = os.path.join(self.tempdir, "out")
        os.makedirs(output_dir)
        with open(os.path.join(output_dir, "keep.txt"), "w", encoding="utf-8") as handle:
            handle.write("existing\n")
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.prepare(PRODUCT_DIR, output_dir, self.tempdir, os.path.dirname(HELPER_PATH), False)
        self.assertIn("not empty", str(raised.exception))

    def test_output_directory_must_differ_from_product(self):
        with self.assertRaises(self.helper.PreparationError):
            self.helper.prepare(self.tempdir, self.tempdir, self.tempdir, os.path.dirname(HELPER_PATH), False)

    def test_missing_module_archive_is_rejected(self):
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.prepare(PRODUCT_DIR, os.path.join(self.tempdir, "out"), self.tempdir,
                                os.path.dirname(HELPER_PATH), False)
        self.assertIn("not present in the module cache", str(raised.exception))

    def test_manifest_describes_pinned_module(self):
        manifest_path, manifest = self.helper.load_manifest(os.path.dirname(HELPER_PATH))
        self.assertTrue(os.path.isfile(manifest_path))
        self.assertEqual(manifest["module"]["path"], MODULE_PATH)
        self.assertEqual(manifest["module"]["version"], MODULE_VERSION)
        production = [entry for entry in manifest["files"] if entry["role"] == "production"]
        self.assertEqual([entry["path"] for entry in production],
                         ["common/bufio/cache.go", "protocol/socks/handshake.go", "protocol/socks/lazy.go"])

    def test_pinned_module_archive_matches_manifest(self):
        _, manifest = self.helper.load_manifest(os.path.dirname(HELPER_PATH))
        archive = pinned_zip_path(module_cache_root())
        self.assertTrue(os.path.isfile(archive), "pinned module archive is required for the bundle tests: " + archive)
        self.assertEqual(sha256_file(archive), manifest["module"]["cache_zip_sha256"])

    def test_module_archive_hash_mismatch_is_rejected(self):
        private_cache = os.path.join(self.tempdir, "cache")
        archive = pinned_zip_path(private_cache)
        os.makedirs(os.path.dirname(archive), exist_ok=True)
        shutil.copyfile(pinned_zip_path(module_cache_root()), archive)
        with open(archive, "r+b") as handle:
            handle.seek(2048)
            original = handle.read(1)
            handle.seek(2048)
            handle.write(bytes([original[0] ^ 0xFF]))
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.prepare(PRODUCT_DIR, os.path.join(self.tempdir, "out"), private_cache,
                                os.path.dirname(HELPER_PATH), False)
        self.assertIn("module archive hash mismatch", str(raised.exception))

    def test_tampered_expanded_cache_is_not_copied(self):
        private_cache = os.path.join(self.tempdir, "cache")
        archive = pinned_zip_path(private_cache)
        os.makedirs(os.path.dirname(archive), exist_ok=True)
        shutil.copyfile(pinned_zip_path(module_cache_root()), archive)
        expanded = os.path.join(private_cache, MODULE_PATH.replace("/", os.sep) + "@" + MODULE_VERSION)
        os.makedirs(os.path.join(expanded, "common"))
        os.makedirs(os.path.join(expanded, "protocol", "socks"))
        with open(os.path.join(expanded, "common", "security_cache_marker.go"), "w", encoding="utf-8") as handle:
            handle.write('package common\n\nconst SecurityCacheMarker = "not-in-pinned-archive"\n')
        with open(os.path.join(expanded, "protocol", "socks", "lazy.go"), "w", encoding="utf-8") as handle:
            handle.write("package socks\n\n// poisoned expanded module cache copy\n")
        output_dir = os.path.join(self.tempdir, "out")
        result = self.helper.prepare(PRODUCT_DIR, output_dir, private_cache, os.path.dirname(HELPER_PATH), False)
        module_dir = os.path.join(output_dir, "sing-socks-wire")
        prepared = tree_hashes(module_dir)
        _, manifest = self.helper.load_manifest(os.path.dirname(HELPER_PATH))
        self.assertNotIn("common/security_cache_marker.go", prepared)
        self.assertFalse(os.path.exists(os.path.join(module_dir, "common", "security_cache_marker.go")))
        lazily = [entry for entry in manifest["files"] if entry["path"] == "protocol/socks/lazy.go"][0]
        self.assertEqual(prepared["protocol/socks/lazy.go"], lazily["patched_sha256"])
        with zipfile.ZipFile(archive) as source:
            prefix = MODULE_PATH + "@" + MODULE_VERSION + "/"
            expected = {}
            for info in source.infolist():
                relative = info.filename[len(prefix):]
                if not relative or info.is_dir():
                    continue
                expected[relative] = hashlib.sha256(source.read(info)).hexdigest()
        for entry in manifest["files"]:
            expected[entry["path"]] = entry["patched_sha256"]
        self.assertEqual(prepared, expected)
        self.assertEqual(result["file_count"], len(expected))
        self.assertEqual(result["tree_sha256"], self.helper.tree_digest(expected))

    def pinned_cache(self):
        private_cache = os.path.join(self.tempdir, "cache")
        archive = pinned_zip_path(private_cache)
        os.makedirs(os.path.dirname(archive), exist_ok=True)
        shutil.copyfile(pinned_zip_path(module_cache_root()), archive)
        return private_cache, archive

    def replacement_archive(self):
        malicious = malicious_archive_bytes(archive_bytes_of(pinned_zip_path(module_cache_root())))
        path = os.path.join(self.tempdir, "replacement.zip")
        with open(path, "wb") as handle:
            handle.write(malicious)
        return path, malicious

    def expected_prepared_tree(self):
        _, manifest = self.helper.load_manifest(os.path.dirname(HELPER_PATH))
        prefix = MODULE_PATH + "@" + MODULE_VERSION + "/"
        expected = {}
        with zipfile.ZipFile(pinned_zip_path(module_cache_root())) as archive:
            for info in archive.infolist():
                relative = info.filename[len(prefix):]
                if not relative or info.is_dir():
                    continue
                expected[relative] = hashlib.sha256(archive.read(info)).hexdigest()
        for entry in manifest["files"]:
            expected[entry["path"]] = entry["patched_sha256"]
        return expected

    @staticmethod
    def replace_pathname(archive, replacement):
        event = {
            "mode": "pathname-replacement",
            "inode_before": os.stat(archive).st_ino,
            "archive_sha256_before": sha256_file(archive),
        }
        os.replace(replacement, archive)
        event["inode_after"] = os.stat(archive).st_ino
        event["archive_sha256_after"] = sha256_file(archive)
        return event

    @staticmethod
    def rewrite_same_inode(archive, replacement):
        event = {
            "mode": "same-inode-rewrite",
            "inode_before": os.stat(archive).st_ino,
            "archive_sha256_before": sha256_file(archive),
        }
        with open(replacement, "rb") as handle:
            payload = handle.read()
        with open(archive, "r+b") as handle:
            handle.seek(0)
            handle.write(payload)
            handle.truncate()
        event["inode_after"] = os.stat(archive).st_ino
        event["archive_sha256_after"] = sha256_file(archive)
        return event

    def prepare_after_validation(self, mutate):
        """Run the actual helper, mutating the cached archive after its hash check.

        The trace fires on the extraction call inside prepare(); by then the
        helper has already returned from the archive hash validation. The
        mutation therefore happens strictly after the pinned SHA-256 passed.
        """
        private_cache, archive = self.pinned_cache()
        replacement, malicious = self.replacement_archive()
        output_dir = os.path.join(self.tempdir, "out")
        hook_line = extraction_call_line()
        events = []

        def tracer(frame, event, argument):
            if event == "line" and frame.f_code.co_filename == HELPER_PATH and frame.f_lineno == hook_line:
                events.append(mutate(archive, replacement))
            return tracer

        previous_trace = sys.gettrace()
        sys.settrace(tracer)
        try:
            result = self.helper.prepare(PRODUCT_DIR, output_dir, private_cache,
                                         os.path.dirname(HELPER_PATH), False)
        finally:
            sys.settrace(previous_trace)
        return result, output_dir, archive, malicious, events

    def assert_only_verified_bytes_consumed(self, result, output_dir, archive, malicious, events, mode):
        _, manifest = self.helper.load_manifest(os.path.dirname(HELPER_PATH))
        self.assertEqual(len(events), 1, "post-validation mutation was not exercised exactly once")
        event = events[0]
        self.assertEqual(event["mode"], mode)
        self.assertEqual(event["archive_sha256_before"], manifest["module"]["cache_zip_sha256"])
        self.assertEqual(sha256_file(archive), hashlib.sha256(malicious).hexdigest(),
                         "control fixture did not replace the cached archive")
        self.assertEqual(result["source_archive_sha256"], manifest["module"]["cache_zip_sha256"])
        expected = self.expected_prepared_tree()
        prepared = tree_hashes(os.path.join(output_dir, "sing-socks-wire"))
        self.assertFalse(MARKER_RELATIVE in prepared,
                         "unverified post-validation archive bytes were consumed: " + MARKER_RELATIVE)
        if prepared != expected:
            missing = sorted(set(expected) - set(prepared))[:8]
            unexpected = sorted(set(prepared) - set(expected))[:8]
            changed = sorted(path for path in set(prepared) & set(expected) if prepared[path] != expected[path])[:8]
            self.fail("prepared tree differs from archive+patch: missing=%s unexpected=%s changed=%s"
                      % (missing, unexpected, changed))
        self.assertEqual(result["file_count"], len(expected))
        self.assertEqual(result["tree_sha256"], self.helper.tree_digest(expected))
        prefix = MODULE_PATH + "@" + MODULE_VERSION + "/"
        with zipfile.ZipFile(io.BytesIO(malicious)) as probe:
            self.assertIn(prefix + MARKER_RELATIVE, probe.namelist())

    def test_post_validation_pathname_replacement_consumes_verified_bytes(self):
        result, output_dir, archive, malicious, events = self.prepare_after_validation(self.replace_pathname)
        self.assertNotEqual(events[0]["inode_before"], events[0]["inode_after"])
        self.assert_only_verified_bytes_consumed(result, output_dir, archive, malicious, events,
                                                 "pathname-replacement")

    def test_post_validation_same_inode_rewrite_consumes_verified_bytes(self):
        result, output_dir, archive, malicious, events = self.prepare_after_validation(self.rewrite_same_inode)
        self.assertEqual(events[0]["inode_before"], events[0]["inode_after"])
        self.assert_only_verified_bytes_consumed(result, output_dir, archive, malicious, events,
                                                 "same-inode-rewrite")

    def test_archive_replacement_before_validation_is_rejected(self):
        private_cache, archive = self.pinned_cache()
        _, malicious = self.replacement_archive()
        with open(archive, "wb") as handle:
            handle.write(malicious)
        output_dir = os.path.join(self.tempdir, "out")
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.prepare(PRODUCT_DIR, output_dir, private_cache,
                                os.path.dirname(HELPER_PATH), False)
        self.assertIn("module archive hash mismatch", str(raised.exception))
        self.assertFalse(os.path.exists(os.path.join(output_dir, "sing-socks-wire")))

    def test_archive_entry_path_escape_is_rejected(self):
        crafted = os.path.join(self.tempdir, "crafted.zip")
        prefix = MODULE_PATH + "@" + MODULE_VERSION + "/"
        with zipfile.ZipFile(crafted, "w") as archive:
            archive.writestr(prefix + "safe.go", "package safe\n")
            archive.writestr(prefix + "../escaped.go", "package escaped\n")
        manifest = {"module": {"path": MODULE_PATH, "version": MODULE_VERSION}}
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.read_archive(manifest, archive_bytes_of(crafted))
        self.assertIn("unsafe archive entry path", str(raised.exception))

    def test_archive_entry_outside_module_is_rejected(self):
        crafted = os.path.join(self.tempdir, "crafted.zip")
        with zipfile.ZipFile(crafted, "w") as archive:
            archive.writestr("other/module/file.go", "package other\n")
        manifest = {"module": {"path": MODULE_PATH, "version": MODULE_VERSION}}
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.read_archive(manifest, archive_bytes_of(crafted))
        self.assertIn("outside the pinned module", str(raised.exception))

    def test_whole_tree_mismatch_is_rejected(self):
        root = os.path.join(self.tempdir, "tree")
        os.makedirs(root)
        with open(os.path.join(root, "file.go"), "w", encoding="utf-8") as handle:
            handle.write("package tree\n")
        entries = {"file.go": b"package tree\n"}
        manifest = {"files": []}
        self.helper.verify_tree(root, entries, manifest)
        with open(os.path.join(root, "extra.go"), "w", encoding="utf-8") as handle:
            handle.write("package tree\n\nconst Extra = true\n")
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.verify_tree(root, entries, manifest)
        self.assertIn("unexpected=", str(raised.exception))
        os.remove(os.path.join(root, "extra.go"))
        with open(os.path.join(root, "file.go"), "w", encoding="utf-8") as handle:
            handle.write("package tree\n\nconst Changed = true\n")
        with self.assertRaises(self.helper.PreparationError) as raised:
            self.helper.verify_tree(root, entries, manifest)
        self.assertIn("changed=", str(raised.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
