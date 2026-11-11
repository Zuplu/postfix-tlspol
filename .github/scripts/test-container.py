#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small offline smoke test; supply a locally loaded image for a compatible CPU."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=45)
    if check and result.returncode:
        raise RuntimeError(f"docker {' '.join(args)}: {result.stderr}")
    return result


def main(image):
    config = json.loads(docker("image", "inspect", image).stdout)[0]["Config"]
    assert config["User"] == "default"
    assert set(config["ExposedPorts"]) == {"8642/tcp"}
    assert config["Entrypoint"] == ["/entrypoint.sh"]
    with tempfile.TemporaryDirectory(prefix="tlspol-container-test-") as directory:
        Path(directory).chmod(0o755)  # The Docker daemon may run as a separate unprivileged user.
        # No public network: local SOA satisfies the existing readiness check.
        path = Path(directory) / "unbound.conf"
        text = (Path(__file__).resolve().parents[2] / "deployments/unbound.conf").read_text()
        text = text.replace("remote-control:", '''  local-zone: "." static
  local-data: ". 60 IN SOA ns.test. hostmaster.test. 1 60 60 60 60"
  local-data: "example.test. 60 IN MX 10 mail.example.test."
  local-data: "mail.example.test. 60 IN A 192.0.2.1"
remote-control:''')
        path.write_text(text)
        path.chmod(0o644)
        container = docker("run", "-d", "--network=none", "--read-only", "--cap-drop=ALL",
                           "-e", "TLSPOL_VERSION_CHECK=0",
                           "--security-opt=no-new-privileges", "--pids-limit=256",
                           "--tmpfs", "/data:uid=1000,gid=1000,mode=0700",
                           "--tmpfs", "/var/lib/unbound:uid=1000,gid=1000,mode=0700",
                           "--tmpfs", "/tmp:noexec,nosuid,nodev,size=16m",
                           "--mount", f"type=bind,source={path},target=/etc/unbound/unbound.conf,readonly",
                           "--health-interval=1s", "--health-start-period=1s", image).stdout.strip()
        try:
            for _ in range(30):
                state = json.loads(docker("inspect", container).stdout)[0]["State"]
                if state.get("Health", {}).get("Status") == "healthy":
                    break
                if not state["Running"]:
                    raise RuntimeError(docker("logs", container).stdout + docker("logs", container).stderr)
                time.sleep(1)
            else:
                raise RuntimeError("Container did not become healthy")
            docker("exec", container, "unbound-checkconf", "/etc/unbound/unbound.conf")
            modules = docker("exec", container, "unbound-checkconf", "-o", "module-config", "/etc/unbound/unbound.conf").stdout
            assert "validator iterator" in modules, modules
            docker("exec", container, "nslookup", "-type=MX", "example.test", "127.0.0.1:8053")
            query = docker("exec", container, "postfix-tlspol", "-config", "/etc/postfix-tlspol/config.yaml", "-query", "example.test").stdout
            assert "TEMP" not in query, query
            docker("exec", container, "sh", "-ec", "test -s /var/lib/unbound/trusted-key.key; test -w /var/lib/unbound/trusted-key.key; test -r /etc/ssl/certs/ca-certificates.crt; test ! -e /sbin/apk; test ! -e /usr/local/go; test ! -e /usr/include; test ! -e /sources; test ! -e /work")
            docker("stop", "--time=15", container)
            assert docker("inspect", "--format={{.State.ExitCode}}", container).stdout.strip() == "0"
            # The same supervisor must fail when either child exits unexpectedly.
            for process in ("unbound", "postfix-tlspol"):
                docker("start", container)
                for _ in range(30):
                    ready = docker("exec", container, "wget", "-q", "-T", "1", "-O", "/dev/null", "http://127.0.0.1:8642/metrics", check=False)
                    if ready.returncode == 0:
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError("Restart did not become ready")
                docker("exec", container, "/bin/busybox", "killall", "-TERM", process)
                code = docker("wait", container).stdout.strip()
                assert code != "0", f"Unexpected {process} exit was hidden"
        finally:
            docker("rm", "-f", container)
    print("Offline container checks passed: startup, health, DNSSEC configuration, DNS, application query, shutdown and child failures")


if __name__ == "__main__":
    main(sys.argv[1])
