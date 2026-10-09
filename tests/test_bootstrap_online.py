"""Exercise server-side downloads with fake HTTPS tools; no compiler or VPS."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="nx-bootstrap-test-"))
        self.stage = Path("/tmp/nx-sync-setup-" + uuid.uuid4().hex)
        self.stage.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.addCleanup(shutil.rmtree, self.stage)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.archive = self.root / "archive"
        self.archive_name = "nx-sync-server-linux-amd64.tar.gz"
        (self.tools / "uname").write_text("#!/bin/sh\nprintf 'x86_64\\n'\n")
        (self.tools / "curl").write_text('''#!/bin/sh
while test "$#" -gt 0; do
  case "$1" in --output) output=$2; shift 2;; *) url=$1; shift;; esac
done
printf '%s\\n' "$url" >> "$NX_BOOT_LOG"
case "$url" in */SHA256SUMS) cp "$NX_BOOT_FIXTURE/checksums" "$output";; *) cp "$NX_BOOT_FIXTURE/archive" "$output";; esac
''')
        for path in self.tools.iterdir():
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.tools)+":"+os.environ["PATH"],
                        NX_BOOT_FIXTURE=str(self.root), NX_BOOT_LOG=str(self.root / "requests"))

    def prepare_archive(self, duplicate=False, escape=False, oversized_metadata=False, linked_control=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name in ("nx-syncd", "nx-syncctl", "release.json"):
                payload = b"synthetic downloaded data"
                member = tarfile.TarInfo("linux-amd64/"+name)
                if oversized_metadata and name == "release.json":
                    payload = b"x"*65537
                if linked_control and name == "nx-syncctl":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/etc/passwd"
                    archive.addfile(member)
                    continue
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
                if duplicate and name == "nx-syncctl":
                    archive.addfile(member, io.BytesIO(payload))
            if escape:
                member = tarfile.TarInfo("linux-amd64/../../escape")
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.root / "checksums").write_text(digest+"  "+self.archive_name+"\n")

    def run_bootstrap(self, channel="stable"):
        return subprocess.run(["sh", str(ROOT / "scripts/bootstrap-online"), channel, str(self.stage)],
                              env=self.env, text=True, capture_output=True, timeout=10)

    def test_stable_only_downloads_latest_stable(self):
        self.prepare_archive()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["channel"], "stable")
        self.assertIn("/releases/latest/download/", (self.root / "requests").read_text())
        self.assertNotIn("/download/dev/", (self.root / "requests").read_text())

    def test_dev_requires_explicit_selection(self):
        self.prepare_archive()
        result = self.run_bootstrap("dev")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/releases/download/dev/", (self.root / "requests").read_text())

    def test_checksum_failure_prevents_extraction(self):
        self.prepare_archive()
        (self.root / "checksums").write_text("0"*64+"  "+self.archive_name+"\n")
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.stage / "nx-syncctl").exists())

    def test_duplicate_executable_is_rejected(self):
        self.prepare_archive(duplicate=True)
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.stage / "nx-syncctl").exists())

    def test_archive_paths_are_never_extracted_to_disk(self):
        self.prepare_archive(escape=True)
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.stage.iterdir()}, {"nx-syncd", "nx-syncctl", "release.json"})

    def test_unknown_channel_does_not_download(self):
        self.assertNotEqual(self.run_bootstrap("nightly").returncode, 0)
        self.assertFalse((self.root / "requests").exists())

    def test_oversized_metadata_is_rejected_and_intermediates_removed(self):
        self.prepare_archive(oversized_metadata=True)
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertLessEqual((self.stage / "release.json").stat().st_size, 65537)
        self.assertFalse(any(p.name.endswith(".download") for p in self.stage.iterdir()))

    def test_link_cannot_supply_a_required_executable(self):
        self.prepare_archive(linked_control=True)
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.stage / "nx-syncctl").is_symlink())


if __name__ == "__main__":
    unittest.main()
