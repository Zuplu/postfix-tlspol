# SPDX-License-Identifier: Apache-2.0

import base64
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock


SPEC = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
OLD_NOTES = "## What's Changed in v1.14.1 (2026-10-06)\n\n* fix: earlier release\n"
CLIFF = os.environ.get("GIT_CLIFF", "git-cliff")


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tlspol-release-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.name", "DragonWork")
        self.git("config", "user.email", "release@example.test")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "VERSION").write_text("1.14.1\n")
        (self.root / "CHANGELOG.md").write_text(OLD_NOTES)
        shutil.copyfile(release.ROOT / "cliff.toml", self.root / "cliff.toml")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "chore: initial release")
        self.git("tag", "v1.14.1")
        self.previous_offline = os.environ.get("GIT_CLIFF_OFFLINE")
        os.environ["GIT_CLIFF_OFFLINE"] = "true"
        self.addCleanup(self.restore_offline)

    def restore_offline(self):
        if self.previous_offline is None:
            os.environ.pop("GIT_CLIFF_OFFLINE", None)
        else:
            os.environ["GIT_CLIFF_OFFLINE"] = self.previous_offline

    def git(self, *args):
        return release.git(self.root, *args)

    def commit(self, message):
        self.git("commit", "--quiet", "--allow-empty", "-m", message)

    def plan(self, request="auto"):
        return release.prepare(self.root, request, CLIFF)

    def test_conventional_bumps(self):
        for message, expected in (
            ("fix(dns): retry a lookup", "1.14.2"),
            ("feat(cli): add diagnostics", "1.15.0"),
            ("feat(api)!: change the contract", "2.0.0"),
        ):
            with self.subTest(message=message):
                self.git("reset", "--hard", "v1.14.1")
                self.commit(message)
                self.commit("chore(release): update metadata")
                plan = self.plan()
                self.assertEqual(plan["version"], expected)
                self.assertIn("* " + message + " by @DragonWork", plan["notes"])
                self.assertNotIn("chore(release)", plan["notes"])
                self.assertIn(f"/compare/v1.14.1...v{expected}", plan["notes"])

    def test_manual_versions_and_prereleases(self):
        self.commit("fix: improve the server")
        for request, expected in (
            ("patch", "1.14.2"), ("minor", "1.15.0"), ("major", "2.0.0"),
            ("v2.1.0-rc.1", "2.1.0-rc.1"),
        ):
            with self.subTest(request=request):
                self.assertEqual(self.plan(request)["version"], expected)

    def test_invalid_versions_are_rejected_before_git_cliff(self):
        for version in ("--help", "1.2.03", "1.2.3-01", "1.2.3\nextra", "1.2.3+build", "1.2.3/other", "1.2.3-", "v1.2.3;true", "1.2.3\u0660"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "SemVer"):
                release.prepare(self.root, version, "/missing-cliff")

    def test_existing_or_older_versions_and_empty_releases_are_rejected(self):
        with self.assertRaises(ValueError):
            self.plan()
        self.commit("chore: routine housekeeping")
        with self.assertRaises(ValueError):
            self.plan("patch")
        self.commit("fix: improve the server")
        for version in ("1.14.1", "1.0.0", "1.14.1-rc.1"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.plan(version)

    def test_other_branch_tags_do_not_drive_bumps(self):
        self.git("checkout", "--quiet", "-b", "other")
        self.commit("feat!: experimental replacement")
        self.git("tag", "v9.0.0")
        self.git("checkout", "--quiet", "main")
        self.commit("fix: keep the main release line")
        self.assertEqual(self.plan()["version"], "1.14.2")

    def test_prepend_preserves_history_and_is_idempotent(self):
        notes = "## What's Changed in v1.14.2 (2026-10-09)\n\n* fix: new change\n"
        result = release.prepend(OLD_NOTES, notes, "v1.14.2")
        self.assertEqual(result, notes + "\n" + OLD_NOTES)
        self.assertEqual(release.prepend(result, notes, "v1.14.2"), result)
        with self.assertRaises(ValueError):
            release.prepend("unrelated content", notes, "v1.14.2")

    def test_apply_requires_matching_source_and_unchanged_files(self):
        self.commit("fix: new change")
        plan = self.plan()
        (self.root / "CHANGELOG.md").write_text("operator edit")
        with self.assertRaisesRegex(ValueError, "changed after"):
            release.apply(self.root, plan)
        self.assertEqual((self.root / "VERSION").read_text(), "1.14.1\n")
        (self.root / "CHANGELOG.md").write_text(OLD_NOTES)
        self.commit("fix: concurrent change")
        with self.assertRaisesRegex(ValueError, "another checkout"):
            release.apply(self.root, plan)

    def test_apply_is_repeatable_and_rejects_unexpected_paths(self):
        self.commit("fix: new change")
        plan = self.plan()
        release.apply(self.root, plan)
        release.apply(self.root, plan)
        self.assertEqual((self.root / "VERSION").read_text(), "1.14.2\n")
        self.assertTrue((self.root / "CHANGELOG.md").read_text().endswith(OLD_NOTES))
        plan["files"]["../outside"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "paths"):
            release.apply(self.root, plan)

    def test_apply_rejects_symlinks(self):
        self.commit("fix: new change")
        plan = self.plan()
        (self.root / "original").write_text("1.14.1\n")
        (self.root / "VERSION").unlink()
        (self.root / "VERSION").symlink_to("original")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            release.apply(self.root, plan)
        self.assertEqual((self.root / "original").read_text(), "1.14.1\n")

    def test_signed_commit_uses_expected_head_and_only_release_files(self):
        self.commit("fix: new change")
        plan = self.plan()
        api = Mock(return_value={"data": {"createCommitOnBranch": {"commit": {"oid": "a" * 40, "signature": {"isValid": True}}}}})
        api.side_effect = lambda method, path, *args: {"commit": {"sha": plan["source_commit"]}} if path == "branches/main" else api.return_value
        self.assertEqual(release.record(plan, api, "main"), "a" * 40)
        mutation = api.call_args.args[2]["variables"]["input"]
        self.assertEqual(mutation["expectedHeadOid"], plan["source_commit"])
        self.assertEqual(mutation["message"]["headline"], "chore(release): prepare v1.14.2")
        files = {item["path"]: base64.b64decode(item["contents"]).decode() for item in mutation["fileChanges"]["additions"]}
        self.assertEqual(files, plan["files"])
        api.return_value = {"errors": [{"message": "expectedHeadOid changed"}]}
        with self.assertRaisesRegex(ValueError, "advanced"):
            release.record(plan, api, "main")
        api.return_value = {"data": {"createCommitOnBranch": {"commit": {"oid": "a" * 40, "signature": {"isValid": False}}}}}
        with self.assertRaisesRegex(ValueError, "signature"):
            release.record(plan, api, "main")
        with self.assertRaisesRegex(ValueError, "main"):
            release.record(plan, api, "rust-port")

    def test_preparation_retry_reuses_only_the_identical_signed_commit(self):
        self.commit("fix: new change")
        plan = self.plan()
        head = "a" * 40
        recorded = {
            "parents": [{"sha": plan["source_commit"]}],
            "commit": {"message": "chore(release): prepare v1.14.2", "verification": {"verified": True}},
            "files": [{"filename": name} for name in release.FILES],
        }

        def api(method, path):
            self.assertEqual(method, "GET")
            if path == "branches/main":
                return {"commit": {"sha": head}}
            if path == "commits/" + head:
                return recorded
            name = path.split("/", 1)[1].split("?", 1)[0]
            return {"encoding": "base64", "content": base64.b64encode(plan["files"][name].encode()).decode()}

        self.assertEqual(release.record(plan, api, "main"), head)
        recorded["parents"] = [{"sha": "b" * 40}]
        with self.assertRaisesRegex(ValueError, "advanced"):
            release.record(plan, api, "main")

    def test_draft_and_publication_retries_preserve_the_tag(self):
        self.commit("fix: new change")
        plan = self.plan()
        plan["commit"] = "a" * 40
        state = {"tag": None, "release": None}
        calls = []

        def api(method, path, data=None, missing=False):
            calls.append((method, path))
            if path.startswith("git/ref/tags/"):
                return {"object": {"type": "commit", "sha": state["tag"]}} if state["tag"] else None
            if path == "git/refs":
                state["tag"] = data["sha"]
                return {}
            if path.startswith("releases/tags/"):
                return None
            if path.startswith("releases?"):
                return [copy.deepcopy(state["release"])] if state["release"] else []
            if path == "releases":
                state["release"] = {**data, "id": 42, "html_url": "https://example.test/release"}
            elif path == "releases/42":
                state["release"].update(data)
            else:
                self.fail(f"Unexpected API call: {method} {path}")
            return copy.deepcopy(state["release"])

        release.draft(plan, api)
        release.draft(plan, api)
        self.assertEqual(calls.count(("POST", "git/refs")), 1)
        self.assertEqual(calls.count(("POST", "releases")), 1)
        self.assertTrue(state["release"]["draft"])
        image = "sha256:" + "b" * 64
        release.publish(plan, api, image)
        release.publish(plan, api, image)
        self.assertEqual(calls.count(("PATCH", "releases/42")), 1)
        self.assertFalse(state["release"]["draft"])
        with self.assertRaisesRegex(ValueError, "different contents"):
            release.publish(plan, api, "sha256:" + "c" * 64)
        state["tag"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "different commit"):
            release.draft(plan, api)

    def test_prerelease_and_old_versions_cannot_replace_latest_docker_tags(self):
        self.commit("fix: new change")
        plan = self.plan("2.0.0-rc.1")
        release.apply(self.root, plan)
        metadata = release.docker_metadata(self.root, plan["version"])
        self.assertEqual(metadata["tags"], [release.IMAGE + ":v2.0.0-rc.1"])
        (self.root / "VERSION").write_text("1.14.1\n")
        self.assertIn(release.IMAGE + ":latest", release.docker_metadata(self.root, "1.14.1")["tags"])
        self.git("tag", "v1.15.0")
        self.assertEqual(release.docker_metadata(self.root, "1.14.1")["tags"], [release.IMAGE + ":v1.14.1"])
        with self.assertRaisesRegex(ValueError, "VERSION"):
            release.docker_metadata(self.root, "1.15.0")

    def test_platform_matrix_requires_every_target_including_riscv(self):
        manifest = {"manifests": [
            {"platform": {"os": "linux", "architecture": arch, "variant": variant}}
            for arch, variant in (
                ("amd64", None), ("arm", "v6"), ("arm", "v7"), ("arm64", "v8"),
                ("386", None), ("ppc64le", None), ("s390x", None),
            )
        ]}
        with self.assertRaisesRegex(ValueError, "required platform linux/riscv64"):
            release.docker_platforms(manifest)
        manifest["manifests"].append({"platform": {"os": "linux", "architecture": "riscv64"}})
        selected = release.docker_platforms(manifest)["include"]
        self.assertEqual(len(selected), 10)
        self.assertIn({"platform": "linux/riscv64"}, selected)
        manifest["manifests"].pop(0)
        with self.assertRaisesRegex(ValueError, "required platform"):
            release.docker_platforms(manifest)


if __name__ == "__main__":
    unittest.main()
