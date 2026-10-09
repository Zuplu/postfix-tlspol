#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare, apply, and publish a release from one immutable source revision."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Zuplu/postfix-tlspol"
IMAGE = "zuplu/postfix-tlspol"
FILES = ("VERSION", "CHANGELOG.md")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
)
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_key(version):
    match = SEMVER.fullmatch(version)
    require(match is not None and len(version) <= 120, "Choose auto, patch, minor, major, or an exact SemVer version")
    major, minor, patch, prerelease = match.groups()
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in (prerelease or "").split(".")
    )
    return int(major), int(minor), int(patch), prerelease is None, identifiers


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def version_tags(root, merged=False):
    args = ["tag", "--list", "v*"]
    if merged:
        args += ["--merged", "HEAD"]
    return [tag for tag in git(root, *args).splitlines() if SEMVER.fullmatch(tag[1:])]


def prepend(changelog, notes, tag):
    require(notes.startswith(f"## What's Changed in {tag} ("), "Release notes have the wrong version")
    require(not changelog or changelog.startswith("## What's Changed in "), "Unexpected changelog format")
    sections = re.split(r"\n(?=## What's Changed in )", changelog.strip())
    previous = [section.strip() for section in sections if section and not section.startswith(f"## What's Changed in {tag} (")]
    return "\n\n".join([notes.strip(), *previous]) + "\n"


def prepare(root, request, cliff="git-cliff"):
    version = request.removeprefix("v")
    if request not in ("auto", "patch", "minor", "major"):
        version_key(version)
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "Commit tracked changes before preparing a release")
    flags = [cliff, "--config", str(root / "cliff.toml"), "--unreleased", "--use-branch-tags", "--no-exec"]

    def run(*args):
        return subprocess.check_output([*flags, *args], cwd=root, text=True).strip()

    if request in ("auto", "patch", "minor", "major"):
        version = run("--bumped-version", "--bump", request).removeprefix("v")
    selected = version_key(version)
    tag = "v" + version
    require(not git(root, "tag", "--list", tag), f"Tag {tag} already exists; rerun the failed jobs of its original release workflow")
    current = (root / "VERSION").read_text().strip()
    baseline = [current, *(item[1:] for item in version_tags(root, merged=True))]
    require(all(selected > version_key(item) for item in baseline), "Release version must advance VERSION and all reachable release tags")
    notes = run("--tag", tag, "--strip", "all") + "\n"
    require(re.search(r"^\* ", notes, re.MULTILINE), "No changelog entries to release")
    old = {name: (root / name).read_text() for name in FILES}
    commit = git(root, "rev-parse", "HEAD")
    return {
        "version": version,
        "tag": tag,
        "source_commit": commit,
        "commit": commit,
        "notes": notes,
        "before": {name: digest(content) for name, content in old.items()},
        "files": {"VERSION": version + "\n", "CHANGELOG.md": prepend(old["CHANGELOG.md"], notes, tag)},
    }


def validate(plan):
    version_key(plan["version"])
    require(plan["tag"] == "v" + plan["version"], "Release tag/version mismatch")
    require(SHA.fullmatch(plan["source_commit"]) and SHA.fullmatch(plan["commit"]), "Invalid source revision")
    require(set(plan["files"]) == set(FILES) and set(plan["before"]) == set(FILES), "Unexpected prepared file paths")
    require(plan["files"]["VERSION"] == plan["version"] + "\n", "Prepared VERSION mismatch")
    require(plan["notes"].startswith(f"## What's Changed in {plan['tag']} ("), "Release notes/version mismatch")
    require(plan["files"]["CHANGELOG.md"].startswith(plan["notes"].strip() + "\n"), "Prepared changelog mismatch")


def apply(root, plan):
    validate(plan)
    require(git(root, "rev-parse", "HEAD") in (plan["source_commit"], plan["commit"]), "Prepared files belong to another checkout")
    for name in FILES:
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"Unsafe release file: {name}")
        current = path.read_text()
        require(current == plan["files"][name] or digest(current) == plan["before"][name], f"Release file changed after preparation: {name}")
    for name in FILES:
        (root / name).write_text(plan["files"][name])


class GitHub:
    def __init__(self):
        require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "Publication is restricted to " + REPOSITORY)
        self.token = os.environ.get("GH_TOKEN", "")
        require(self.token, "GH_TOKEN is required")

    def __call__(self, method, path, data=None, missing=False):
        route = "/graphql" if path == "graphql" else f"/repos/{REPOSITORY}/{path}"
        request = Request(
            "https://api.github.com" + route,
            data=json.dumps(data).encode() if data is not None else None,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError(f"GitHub {method} {path}: HTTP {error.code}") from None


def record(plan, api, branch):
    validate(plan)
    require(branch == "main", "Release preparation must run on main")
    head = api("GET", "branches/main")["commit"]["sha"]
    if head != plan["source_commit"]:
        commit = api("GET", "commits/" + head)
        require(
            [parent["sha"] for parent in commit["parents"]] == [plan["source_commit"]]
            and commit["commit"]["message"] == f"chore(release): prepare {plan['tag']}"
            and commit["commit"]["verification"]["verified"]
            and {file["filename"] for file in commit["files"]} == set(FILES),
            "Main advanced after checkout; refusing to overwrite it",
        )
        for name in FILES:
            content = api("GET", f"contents/{name}?ref={head}")
            require(content["encoding"] == "base64", "Unexpected release file encoding")
            require(base64.b64decode(content["content"]).decode() == plan["files"][name], "Existing preparation has different contents")
        return head
    response = api("POST", "graphql", {
        "query": "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid signature { isValid } } } }",
        "variables": {"input": {
            "branch": {"repositoryNameWithOwner": REPOSITORY, "branchName": branch},
            "expectedHeadOid": plan["source_commit"],
            "message": {"headline": f"chore(release): prepare {plan['tag']}"},
            "fileChanges": {"additions": [
                {"path": name, "contents": base64.b64encode(plan["files"][name].encode()).decode()}
                for name in FILES
            ]},
        }},
    })
    require(not response.get("errors"), "Could not record release preparation; main may have advanced")
    commit = response.get("data", {}).get("createCommitOnBranch", {}).get("commit", {})
    require(commit.get("signature", {}).get("isValid"), "Release preparation must have a valid GitHub signature")
    require(SHA.fullmatch(commit.get("oid", "")), "Invalid preparation commit")
    return commit["oid"]


def tag_commit(api, tag):
    ref = api("GET", f"git/ref/tags/{tag}", missing=True)
    if ref is None:
        return None
    obj = ref["object"]
    for _ in range(16):
        if obj["type"] == "commit":
            return obj["sha"]
        require(obj["type"] == "tag", "Release tag must resolve to a commit")
        obj = api("GET", "git/tags/" + obj["sha"])["object"]
    raise ValueError("Release tag nesting is too deep")


def find_release(api, tag):
    release = api("GET", "releases/tags/" + tag, missing=True)
    if release:
        return release
    for page in range(1, 101):
        releases = api("GET", f"releases?per_page=100&page={page}")
        for release in releases:
            if release["tag_name"] == tag:
                return release
        if len(releases) < 100:
            return None
    raise ValueError("Could not find the release within the bounded draft search")


def draft(plan, api):
    validate(plan)
    require(plan["commit"] != plan["source_commit"], "Record the signed release preparation before publication")
    commit = tag_commit(api, plan["tag"])
    require(commit is None or commit == plan["commit"], "Release tag points to a different commit")
    if commit is None:
        api("POST", "git/refs", {"ref": "refs/tags/" + plan["tag"], "sha": plan["commit"]})
    release = find_release(api, plan["tag"])
    if release is None:
        release = api("POST", "releases", {
            "tag_name": plan["tag"], "target_commitish": plan["commit"],
            "name": plan["tag"], "body": plan["notes"], "draft": True,
            "prerelease": "-" in plan["version"],
        })
    require(release["target_commitish"] == plan["commit"], "Release belongs to another commit")
    return release


def publish(plan, api, image_digest):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest), "Invalid Docker manifest digest")
    release = draft(plan, api)
    body = plan["notes"].rstrip() + f"\n\n**Docker image**: `{IMAGE}@{image_digest}`\n"
    if not release["draft"]:
        require(release["body"] == body, "Published release has different contents; refusing to replace it")
        return release
    return api("PATCH", f"releases/{release['id']}", {
        "body": body, "draft": False,
        "make_latest": "false" if "-" in plan["version"] else "legacy",
    })


def docker_metadata(root, version):
    version = version.removeprefix("v")
    key = version_key(version)
    require((root / "VERSION").read_text().strip() == version, "Docker version differs from prepared VERSION")
    stable = "-" not in version
    tags = [IMAGE + ":v" + version]
    newer = any(version_key(tag[1:]) > key for tag in version_tags(root) if "-" not in tag)
    if stable and not newer:
        major, minor = version.split(".")[:2]
        tags += [IMAGE + ":v" + major + "." + minor, IMAGE + ":v" + major, IMAGE + ":latest"]
    return {"version": version, "commit": git(root, "rev-parse", "HEAD"), "tags": tags}


def docker_platforms(manifest):
    available = set()
    for descriptor in manifest.get("manifests", []):
        platform = descriptor.get("platform", {})
        if platform.get("os") != "linux":
            continue
        architecture = platform.get("architecture")
        variant = platform.get("variant") if architecture == "arm" else None
        available.add("/".join(filter(None, ("linux", architecture, variant))))
    targets = [
        "linux/amd64", "linux/amd64/v2", "linux/amd64/v3",
        "linux/arm/v6", "linux/arm/v7", "linux/arm64", "linux/386",
        "linux/ppc64le", "linux/riscv64", "linux/s390x",
    ]
    selected = []
    for target in targets:
        base = "linux/amd64" if target.startswith("linux/amd64/") else target
        if target == "linux/riscv64" and base not in available:
            print("Pinned Go image has no linux/riscv64 build; omitting RISC-V", file=sys.stderr)
            continue
        require(base in available, "Pinned Go image is missing required platform " + target)
        selected.append({"platform": target})
    return {"include": selected}


def output(values):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as file:
            for name, value in values.items():
                file.write(f"{name}={value}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("version", nargs="?", default="auto")
    preparation.add_argument("--output", type=Path, required=True)
    preparation.add_argument("--record", action="store_true")
    for command in ("apply", "draft", "publish"):
        subparser = commands.add_parser(command)
        subparser.add_argument("plan", type=Path)
        if command == "publish":
            subparser.add_argument("--digest", required=True)
    metadata = commands.add_parser("docker-metadata")
    metadata.add_argument("version")
    commands.add_parser("docker-platforms")
    args = parser.parse_args()
    if args.command == "prepare":
        plan = prepare(ROOT, args.version, os.environ.get("GIT_CLIFF", "git-cliff"))
        if os.environ.get("GITHUB_SHA"):
            require(plan["source_commit"] == os.environ["GITHUB_SHA"], "Workflow source revision changed")
        if args.record:
            plan["commit"] = record(plan, GitHub(), os.environ.get("GITHUB_REF_NAME"))
        apply(ROOT, plan)
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "prepared-release.json").write_text(json.dumps(plan, indent=2) + "\n")
        (args.output / "release-notes.md").write_text(plan["notes"])
        output({key: plan[key] for key in ("version", "tag", "commit")})
        print("Prepared " + plan["tag"])
    elif args.command == "docker-metadata":
        print(json.dumps(docker_metadata(ROOT, args.version)))
    elif args.command == "docker-platforms":
        image = (ROOT / "deployments/Dockerfile").read_text().splitlines()[0].split()[1]
        require(re.fullmatch(r"golang:[0-9A-Za-z.-]+@sha256:[0-9a-f]{64}", image), "Expected a pinned official Go base image")
        manifest = json.loads(subprocess.check_output(["docker", "buildx", "imagetools", "inspect", "--raw", image], text=True))
        print(json.dumps(docker_platforms(manifest)))
    else:
        plan = json.loads(args.plan.read_text())
        validate(plan)
        if args.command == "apply":
            apply(ROOT, plan)
        elif args.command == "draft":
            print(draft(plan, GitHub())["html_url"])
        else:
            print(publish(plan, GitHub(), args.digest)["html_url"])


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
