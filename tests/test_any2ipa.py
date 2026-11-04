import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from any2ipa.archive import Limits, extract_ipa, inspect_ipa, pack_ipa, portable_parts
from any2ipa.cli import main
from any2ipa.errors import Any2IPAError
from any2ipa.signing import sign_ipa


def fixture(path, extras=(), binary=False):
    info = {"CFBundleIdentifier": "org.example.demo", "CFBundleExecutable": "Demo",
            "CFBundleName": "Demo", "CFBundleVersion": "1"}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML))
        zf.writestr("Payload/Demo.app/Demo", b"TEST-FIXTURE-NOT-A-RUNNABLE-IOS-APP")
        zf.writestr("Payload/Demo.app/resource.txt", b"hello")
        for name, data in extras:
            zf.writestr(name, data)
    # ZipInfo normalizes backslashes on Windows while writing; mutate raw local
    # and central names to construct the actual hostile on-disk ZIP instead.
    for name, _ in extras:
        if "\\" in name:
            path.write_bytes(path.read_bytes().replace(name.replace("\\", "/").encode(), name.encode()))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ipa = self.root / "input.ipa"
        fixture(self.ipa)

    def test_inspect_xml_and_binary(self):
        for binary in (False, True):
            fixture(self.ipa, binary=binary)
            data = inspect_ipa(self.ipa)
            self.assertEqual(data["bundle_id"], "org.example.demo")
            self.assertFalse(data["signature_verified"])
            self.assertEqual(data["entries"], 3)

    def test_roundtrip_and_content(self):
        extract_ipa(self.ipa, self.root / "tree")
        result = pack_ipa(self.root / "tree", self.root / "output.ipa")
        self.assertEqual(result["bundle_id"], "org.example.demo")
        with zipfile.ZipFile(self.ipa) as a, zipfile.ZipFile(self.root / "output.ipa") as b:
            for name in a.namelist():
                self.assertEqual(a.read(name), b.read(name))
            self.assertTrue((b.getinfo("Payload/Demo.app/Demo").external_attr >> 16) & 0o111)

    def test_pack_standalone_app(self):
        extract_ipa(self.ipa, self.root / "tree")
        pack_ipa(self.root / "tree/Payload/Demo.app", self.root / "app.ipa")
        self.assertEqual(inspect_ipa(self.root / "app.ipa")["app_path"], "Payload/Demo.app")

    def test_reproducible_pack(self):
        extract_ipa(self.ipa, self.root / "tree")
        pack_ipa(self.root / "tree", self.root / "a.ipa")
        pack_ipa(self.root / "tree", self.root / "b.ipa")
        self.assertEqual((self.root / "a.ipa").read_bytes(), (self.root / "b.ipa").read_bytes())

    def test_unsafe_paths(self):
        for name in ("../escape", "/absolute", "C:/evil", "a\\b", "a//b", "a/./b",
                     "a/../b", "a.", "a ", "NUL.txt", "CON", "COM1", "a:b",
                     "a\x00b", "a\x1bb", "a?b", "a/" * 65 + "b"):
            with self.subTest(name=name), self.assertRaises(Any2IPAError):
                portable_parts(name)

    def test_archive_attacks(self):
        attacks = [
            [("../escape", b"bad")], [("C:/escape", b"bad")],
            [("a\\b", b"bad")], [("file", b"1"), ("file", b"2")],
            [("A/file", b"1"), ("a/other", b"2")],
            [("x", b"1"), ("x/file", b"2")],
            [("caf\u00e9/x", b"1"), ("cafe\u0301/y", b"2")],
            [("Payload/Other.app/Info.plist", b"bad")],
        ]
        for extras in attacks:
            with self.subTest(extras=extras):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    fixture(self.ipa, extras)
                with self.assertRaises(Any2IPAError):
                    extract_ipa(self.ipa, self.root / "out")
                self.assertFalse((self.root / "out").exists())
                self.assertFalse((self.root / "escape").exists())

    def test_archive_symlink_special_and_reparse(self):
        for mode, attr in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFIFO | 0o600, 0), (stat.S_IFREG | 0o644, 0x400)):
            fixture(self.ipa)
            with zipfile.ZipFile(self.ipa, "a") as zf:
                entry = zipfile.ZipInfo("Payload/Demo.app/link")
                entry.create_system = 3
                entry.external_attr = (mode << 16) | attr
                zf.writestr(entry, b"/elsewhere")
            with self.assertRaises(Any2IPAError):
                inspect_ipa(self.ipa)

    def test_crc_failure_and_cleanup(self):
        raw = self.ipa.read_bytes().replace(b"hello", b"jello", 1)
        self.ipa.write_bytes(raw)
        with self.assertRaises(Any2IPAError):
            extract_ipa(self.ipa, self.root / "out")
        self.assertFalse((self.root / "out").exists())
        self.assertEqual(list(self.root.glob(".any2ipa-*")), [])

    def test_truncation(self):
        self.ipa.write_bytes(self.ipa.read_bytes()[:-15])
        with self.assertRaises(Any2IPAError):
            inspect_ipa(self.ipa)

    def test_central_directory_limit_before_zipfile(self):
        raw = bytearray(self.ipa.read_bytes())
        pos = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<L", raw, pos + 12, 40 * 1024**2)
        self.ipa.write_bytes(raw)
        with self.assertRaises(Any2IPAError):
            inspect_ipa(self.ipa)

    def test_encrypted_and_unsupported_compression(self):
        for compression in (None, zipfile.ZIP_BZIP2):
            fixture(self.ipa)
            if compression is None:
                raw = bytearray(self.ipa.read_bytes())
                pos = raw.find(b"PK\x01\x02")
                raw[pos + 8] |= 1
                self.ipa.write_bytes(raw)
            else:
                with zipfile.ZipFile(self.ipa, "a", compression=compression) as zf:
                    zf.writestr("bzip", b"hello")
            with self.assertRaises(Any2IPAError):
                inspect_ipa(self.ipa)

    def test_limits(self):
        for limits in (Limits(max_entries=2), Limits(max_file_bytes=10),
                       Limits(max_total_bytes=10), Limits(max_archive_bytes=10)):
            with self.subTest(limits=limits), self.assertRaises(Any2IPAError):
                inspect_ipa(self.ipa, limits)
        fixture(self.ipa)
        with zipfile.ZipFile(self.ipa, "a", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros", b"0" * 100000)
        with self.assertRaises(Any2IPAError):
            inspect_ipa(self.ipa, Limits(max_ratio=10))
        for ratio in (float("inf"), float("nan"), 0):
            with self.assertRaises(Any2IPAError):
                Limits(max_ratio=ratio)

    def test_invalid_layout_and_plist(self):
        for contents in ({"Info.plist": b"bad"}, {"Payload/Demo.app/Info.plist": b"bad"},
                         {"Payload/Demo.app/Info.plist": plistlib.dumps({"CFBundleIdentifier": "a", "CFBundleExecutable": "../x"})}):
            with zipfile.ZipFile(self.ipa, "w") as zf:
                for name, value in contents.items():
                    zf.writestr(name, value)
            with self.assertRaises(Any2IPAError):
                inspect_ipa(self.ipa)

    def test_no_overwrite(self):
        existing = self.root / "existing"
        existing.mkdir()
        (existing / "keep").write_text("keep")
        with self.assertRaises(Any2IPAError):
            extract_ipa(self.ipa, existing)
        extract_ipa(self.ipa, self.root / "tree")
        with self.assertRaises(Any2IPAError):
            pack_ipa(self.root / "tree", self.ipa)
        self.assertEqual((existing / "keep").read_text(), "keep")

    def test_output_inside_source(self):
        extract_ipa(self.ipa, self.root / "tree")
        with self.assertRaises(Any2IPAError):
            pack_ipa(self.root / "tree", self.root / "tree/out.ipa")

    def test_source_symlink(self):
        extract_ipa(self.ipa, self.root / "tree")
        try:
            (self.root / "tree/link").symlink_to(self.ipa)
        except OSError:
            self.skipTest("Host does not allow symlink creation")
        with self.assertRaises(Any2IPAError):
            pack_ipa(self.root / "tree", self.root / "out.ipa")

    def test_cli_subprocess(self):
        run = subprocess.run([sys.executable, "-m", "any2ipa", "inspect", str(self.ipa), "--json"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["bundle_id"], "org.example.demo")

    def test_cli_error_json(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["inspect", str(self.root / "missing"), "--json"]), 1)
        self.assertIn("error", json.loads(err.getvalue()))


class SigningTests(unittest.TestCase):
    def setUp(self):
        ArchiveTests.setUp(self)
        self.key = self.root / "identity.p12"
        self.profile = self.root / "app.mobileprovision"
        self.key.write_bytes(b"DUMMY-NOT-A-CERTIFICATE")
        self.profile.write_bytes(b"DUMMY-NOT-A-PROFILE")

    def sign(self, **kwargs):
        return sign_ipa(self.ipa, self.root / "signed.ipa", key=self.key,
                        profiles=[self.profile], password="secret ; & value", **kwargs)

    def test_missing_signer(self):
        with patch("any2ipa.signing.find_zsign", return_value=None), self.assertRaises(Any2IPAError):
            self.sign()

    def test_signer_failure_timeout_missing_output(self):
        for effect in (subprocess.CompletedProcess([], 5), subprocess.TimeoutExpired([], 1),
                       subprocess.CompletedProcess([], 0)):
            with self.subTest(effect=effect), patch("any2ipa.signing.find_zsign", return_value=sys.executable):
                with patch("any2ipa.signing.subprocess.run") as run:
                    if isinstance(effect, Exception):
                        run.side_effect = effect
                    else:
                        run.return_value = effect
                    with self.assertRaises(Any2IPAError) as caught:
                        self.sign()
                    self.assertNotIn("secret", str(caught.exception))
                    self.assertFalse((self.root / "signed.ipa").exists())

    def test_real_subprocess_with_controlled_signer_stub(self):
        stub = self.root / "stub.py"
        stub.write_text(
            "import sys,zipfile,shutil\n"
            "a=sys.argv[1:]\n"
            "assert a[a.index('-p')+1]=='secret ; & value'\n"
            "out=a[a.index('-o')+1]\n"
            "shutil.copyfile(a[-1],out)\n"
            "with zipfile.ZipFile(out,'a') as z:\n"
            " z.writestr('Payload/Demo.app/_CodeSignature/CodeResources',b'STUB')\n"
            " z.writestr('Payload/Demo.app/embedded.mobileprovision',b'STUB')\n", encoding="utf-8")
        real_run = subprocess.run

        def run_stub(command, **options):
            self.assertFalse(options["shell"])
            self.assertIn(".any2ipa-sign-", str(options["cwd"]))
            return real_run([sys.executable, str(stub)] + command[1:], **options)

        with patch("any2ipa.signing.find_zsign", return_value=sys.executable), patch("any2ipa.signing.subprocess.run", side_effect=run_stub):
            data = self.sign()
        self.assertEqual(data["signer_exit_code"], 0)
        self.assertFalse(data["signature_verified"])
        self.assertTrue(inspect_ipa(self.root / "signed.ipa")["embedded_profile_present"])

    def test_malicious_signer_output_is_rejected(self):
        def bad(command, **options):
            fixture(Path(command[command.index("-o") + 1]), [("../escape", b"bad")])
            return subprocess.CompletedProcess(command, 0)
        with patch("any2ipa.signing.find_zsign", return_value=sys.executable), patch("any2ipa.signing.subprocess.run", side_effect=bad):
            with self.assertRaises(Any2IPAError):
                self.sign()
        self.assertFalse((self.root / "signed.ipa").exists())


if __name__ == "__main__":
    unittest.main()
