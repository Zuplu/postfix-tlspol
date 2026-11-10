#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify locked inputs; discover releases only through the explicit update command."""

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import random
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
LOCKS = ROOT / "deployments/dependencies"
STABLE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def download(url, destination):
    """Atomic downloads, four attempts; never retry authentication or bad TLS."""
    require(url.startswith("https://"), "Downloads require HTTPS")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(4):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as file:
                temporary = Path(file.name)
                with urlopen(url, timeout=60) as response:
                    require(response.url.startswith("https://"), "Insecure download redirect")
                    shutil.copyfileobj(response, file)
                    length = response.headers.get("Content-Length")
                    if length is not None and file.tell() != int(length):
                        raise http.client.IncompleteRead(b"")
            temporary.replace(destination)
            return
        except HTTPError as error:
            if error.code not in (408, 429, 500, 502, 503, 504):
                raise
            failure = error
        except URLError as error:
            if isinstance(error.reason, ssl.SSLError):
                raise
            failure = error
        except (TimeoutError, ConnectionError, http.client.IncompleteRead) as error:
            failure = error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if attempt == 3:
            raise RuntimeError(f"Download failed after four attempts: {url}: {failure}")
        delay = 2 ** attempt + random.uniform(0, 1)
        print(f"Transient download failure: {url}: {failure}; retry in {delay:.1f}s", file=sys.stderr)
        time.sleep(delay)


def checksum(path, expected):
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Invalid SHA-256 input")
    with Path(path).open("rb") as file:
        actual = hashlib.file_digest(file, "sha256").hexdigest()
    require(actual == expected, f"SHA-256 mismatch: {path}; refusing to build")


def signature(archive, detached, key, fingerprint):
    require(re.fullmatch(r"[0-9A-F]{40}", fingerprint), "Invalid signing fingerprint")
    with tempfile.TemporaryDirectory(prefix="tlspol-gpg-") as directory:
        command = ["gpg", "--homedir", directory, "--batch", "--no-auto-key-retrieve"]
        listing = subprocess.check_output([*command, "--with-colons", "--show-keys", str(key)], text=True)
        primary = []
        previous = ""
        for line in listing.splitlines():
            fields = line.split(":")
            if fields[0] == "fpr" and previous == "pub":
                primary.append(fields[9])
            previous = fields[0]
        require(primary == [fingerprint], "Unrecognized signing key; review the vendored key and fingerprint")
        subprocess.run([*command, "--import", str(key)], check=True, capture_output=True)
        result = subprocess.run([*command, "--status-fd=1", "--verify", str(detached), str(archive)], text=True, capture_output=True)
        # VALIDSIG includes the primary fingerprint for a bound signing subkey.
        valid = [line.split()[-1] if len(line.split()) > 11 else line.split()[2]
                 for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        # KEYEXPIRED can describe unrelated historical subkeys. GOODSIG must
        # describe this signature; expired/revoked signers use other statuses.
        good = result.stdout.count("[GNUPG:] GOODSIG ") == 1
        bad = re.search(r"\[GNUPG:\] (?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|SIGEXPIRED)\b", result.stdout)
        require(result.returncode == 0 and good and not bad and valid == [fingerprint], f"OpenPGP verification failed: {archive}\n{result.stderr}")


def validate(component, lock):
    version = lock["version"]
    require(STABLE.fullmatch(version), f"{component}: expected an exact stable version")
    if component == "go":
        require(set(lock["archives"]) == {"amd64", "arm64"}, "Missing Go build-host archive")
        artifacts = lock["archives"]
        urls = {arch: f"https://dl.google.com/go/go{version}.linux-{arch}.tar.gz" for arch in artifacts}
    else:
        artifacts = {component: lock}
        prefix = "https://nlnetlabs.nl/downloads/unbound" if component == "unbound" else f"https://github.com/openssl/openssl/releases/download/openssl-{version}"
        urls = {component: f"{prefix}/{component}-{version}.tar.gz"}
    for name, artifact in artifacts.items():
        require(artifact["url"] == urls[name], f"{component}: unexpected source URL")
        require(re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]), f"{component}: invalid checksum")
    if component in ("go", "unbound"):
        require(re.fullmatch(r"[0-9A-F]{40}", lock["signer"]), f"Invalid {component} signing fingerprint")


def fetch(component, lock, output, arch="amd64"):
    validate(component, lock)
    if component == "go":
        require(arch in lock["archives"], f"Go build host linux/{arch} unsupported; use an AMD64 or ARM64 builder")
        artifact = lock["archives"][arch]
    else:
        artifact = lock
    # Keep unverified files separate, including when a caller supplies an existing output.
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tlspol-download-", dir=output.parent) as directory:
        archive = Path(directory) / "archive"
        download(artifact["url"], archive)
        checksum(archive, artifact["sha256"])
        if component in ("go", "unbound"):
            detached = Path(directory) / "signature.asc"
            download(artifact["url"] + ".asc", detached)
            key = "google.asc" if component == "go" else "nlnetlabs.asc"
            signature(archive, detached, LOCKS / key, lock["signer"])
        archive.replace(output)


def metadata(url):
    with tempfile.TemporaryDirectory(prefix="tlspol-metadata-") as directory:
        file = Path(directory) / "metadata"
        download(url, file)
        return file.read_text()


def upstream_checksum(url, filename):
    text = metadata(url).strip()
    match = re.fullmatch(r"([0-9a-f]{64})(?:\s+\*?" + re.escape(filename) + r")?", text)
    require(match, f"Unverifiable release checksum metadata: {url}")
    return match[1]


def discover(component, old):
    if component == "go":
        releases = json.loads(metadata("https://go.dev/dl/?mode=json"))
        releases = [item for item in releases if item.get("stable") and STABLE.fullmatch(item["version"].removeprefix("go"))]
        require(releases, "No stable official Go release metadata")
        newest = max(releases, key=lambda item: tuple(map(int, item["version"][2:].split("."))))
        version = newest["version"][2:]
        archives = {}
        for arch in ("amd64", "arm64"):
            filename = f"go{version}.linux-{arch}.tar.gz"
            matches = [f for f in newest["files"] if f["filename"] == filename and f["version"] == newest["version"] and f["kind"] == "archive"]
            require(len(matches) == 1, f"Missing or ambiguous Go archive: {filename}")
            archives[arch] = {"url": "https://dl.google.com/go/" + filename, "sha256": matches[0]["sha256"]}
        return {"version": version, "archives": archives, "signer": old["signer"]}
    if component == "unbound":
        page = metadata("https://nlnetlabs.nl/projects/unbound/download/")
        matches = re.findall(r"Unbound ([0-9]+\.[0-9]+\.[0-9]+) \(Current version\)", page)
        require(len(matches) == 1, "Unverifiable current Unbound release metadata")
        version = matches[0]
        url = f"https://nlnetlabs.nl/downloads/unbound/unbound-{version}.tar.gz"
    else:
        # Deliberately stay on the supported 3.5 LTS line.
        page = metadata("https://openssl-library.org/source/")
        versions = re.findall(r"openssl-(3\.5\.[0-9]+)\.tar\.gz", page)
        require(versions, "No supported OpenSSL 3.5 LTS release metadata")
        version = max(versions, key=lambda value: tuple(map(int, value.split("."))))
        url = f"https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz"
    result = {"version": version, "url": url, "sha256": upstream_checksum(url + ".sha256", url.rsplit("/", 1)[1])}
    if component == "unbound":
        result["signer"] = old["signer"]  # Key rotation always needs human review.
    return result


def dependency_pull_request(component):
    # Keep GitHub publication out of the Docker verification/import path.
    from release import GitHub, REPOSITORY, git, signed_commit
    import base64

    name = f"deployments/dependencies/{component}.json"
    before = git(ROOT, "show", "HEAD:" + name) + "\n"
    content = (ROOT / name).read_text()
    if content == before:
        print(f"{component} is current; no pull request needed")
        return
    lock = json.loads(content)
    validate(component, lock)
    # Called only by update, after verifying every changed archive in this process.
    api = GitHub()
    branch = "build/" + component + "-" + lock["version"]
    head = git(ROOT, "rev-parse", "HEAD")
    ref = api("GET", "git/ref/heads/" + branch, missing=True)
    if ref is None:
        api("POST", "git/refs", {"ref": "refs/heads/" + branch, "sha": head})
    else:
        head = ref["object"]["sha"]
    current = api("GET", f"contents/{name}?ref={head}")
    require(current["encoding"] == "base64", "Unexpected dependency file encoding")
    current_content = base64.b64decode(current["content"]).decode()
    require(current_content in (before, content), "Existing update branch has different dependency edits; review it manually")
    display = {"go": "Go", "unbound": "Unbound", "openssl": "OpenSSL"}[component]
    title = f"build(docker): update {display} to " + lock["version"]
    if current_content != content:
        head = signed_commit(api, branch, head, {name: content}, title)
    else:
        commit = api("GET", "commits/" + head)["commit"]
        require(commit.get("verification", {}).get("verified"), "Existing dependency update must have a valid GitHub signature")
    owner = REPOSITORY.split("/")[0]
    existing = api("GET", f"pulls?state=all&head={owner}:{branch}&base=main")
    if existing:
        print("Existing dependency pull request: " + existing[0]["html_url"])
        if existing[0]["state"] != "open":
            return
    else:
        pr = api("POST", "pulls", {
            "title": title, "head": branch, "base": "main",
            "body": f"Update the pinned {display} {lock['version']} input for the Docker build. Unbound and OpenSSL are bundled only in the Docker image; standalone archives contain the postfix-tlspol executable.\n\nRelease builds continue to use checked-in inputs. The archives passed their version-specific SHA-256 checks." + (f"\nOpenPGP signer: `{lock['signer']}`" if "signer" in lock else ""),
        })
        print("Opened dependency pull request: " + pr["html_url"])
    # GITHUB_TOKEN PRs do not emit pull_request workflow events. Explicitly
    # dispatch the existing non-publishing build on the PR commit instead.
    runs = api("GET", f"actions/workflows/build-docker.yaml/runs?branch={branch}&event=workflow_dispatch&per_page=100")
    if not any(run["head_sha"] == head for run in runs["workflow_runs"]):
        api("POST", "actions/workflows/build-docker.yaml/dispatches", {
            "ref": branch,
            "inputs": {"source_ref": branch, "tag": "v" + (ROOT / "VERSION").read_text().strip(), "publish": "false"},
        })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "check", "update", "sbom"))
    parser.add_argument("component", choices=("go", "unbound", "openssl", "all"))
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pull-request", action="store_true", help="Open signed dependency update PRs after verification")
    args = parser.parse_args()
    require(not args.pull_request or args.command == "update", "Pull requests require a verified update")
    if args.pull_request:
        from release import git
        require(not git(ROOT, "status", "--porcelain", "--untracked-files=no"), "Signed update PRs require a clean checkout")
    require(args.command != "fetch" or args.component != "all", "Fetch one component at a time")
    components = ("go", "unbound", "openssl") if args.component == "all" else (args.component,)
    changes = {}
    sbom_components = []
    for component in components:
        path = LOCKS / (component + ".json")
        lock = json.loads(path.read_text())
        validate(component, lock)
        if args.command == "sbom":
            artifacts = list(lock["archives"].values()) if component == "go" else [lock]
            sbom_components.append({
                "type": "application" if component != "openssl" else "library",
                "name": component, "version": lock["version"],
                "purl": f"pkg:generic/{component}@{lock['version']}",
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]} for item in artifacts],
                "externalReferences": [{"type": "distribution", "url": item["url"]} for item in artifacts],
                "properties": [{"name": "postfix-tlspol:role", "value": "build-toolchain" if component == "go" else "runtime"}],
            })
        if args.command == "fetch":
            require(args.output is not None, "fetch requires --output")
            fetch(component, lock, args.output, args.arch)
        elif args.command == "update":
            candidate = discover(component, lock)
            validate(component, candidate)
            require(tuple(map(int, candidate["version"].split("."))) >= tuple(map(int, lock["version"].split("."))), "Refusing an upstream version downgrade")
            require(candidate["version"] != lock["version"] or candidate == lock, f"{component}: published metadata for a locked release changed; review manually")
            if candidate != lock:
                with tempfile.TemporaryDirectory(prefix="tlspol-update-") as directory:
                    for arch in (candidate["archives"] if component == "go" else ("amd64",)):
                        fetch(component, candidate, Path(directory) / "archive", arch)
                changes[path] = json.dumps(candidate, indent=2) + "\n"
            print(f"{component}: {lock['version']} -> {candidate['version']}")
    # Do not leave partially updated input sets after a verification failure.
    for path, text in changes.items():
        path.write_text(text)
    if args.pull_request:
        for component in components:
            dependency_pull_request(component)
    if args.command == "sbom":
        require(args.output is not None, "sbom requires --output")
        args.output.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": sbom_components}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
