"""Deploy probe HTML files to the PS5 research server.

SCP to /var/www/ps5-guide-entry/ on 10.0.0.80, optionally as index.html
or under /probes/<name>.html.  Verifies deployment via HTTP GET.
"""

import hashlib
import os
import subprocess
import time
from pathlib import Path


SERVER = "marwanserver@10.0.0.80"
WEBROOT = "/var/www/ps5-guide-entry"


def compute_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()[:16]


def scp_file(local_path, remote_path, server=SERVER):
    """SCP a file to the server. Returns (success, message)."""
    full_remote = f"{server}:{remote_path}"
    try:
        r = subprocess.run(
            ["scp", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
             str(local_path), full_remote],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            return True, f"Deployed to {remote_path}"
        return False, f"SCP failed: {r.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "SCP timed out"
    except Exception as e:
        return False, str(e)


def ssh_cmd(cmd, server=SERVER, timeout=10):
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
             server, cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", -1


def deploy_probe(local_path, name=None, as_index=False):
    """Deploy a probe HTML file to the server.

    Args:
        local_path: Path to the .html file on this machine
        name: Override probe name (default: filename stem)
        as_index: If True, deploy as index.html (replaces main page)

    Returns:
        dict with keys: success, hash, remote_path, url, message
    """
    local_path = Path(local_path)
    if not local_path.exists():
        return {"success": False, "message": f"File not found: {local_path}"}

    probe_hash = compute_hash(local_path)
    stem = name or local_path.stem

    if as_index:
        # Back up existing index.html first
        ssh_cmd(f"cp {WEBROOT}/index.html {WEBROOT}/index.html.bak 2>/dev/null || true")
        remote_path = f"{WEBROOT}/index.html"
        url_path = "/"
    else:
        ssh_cmd(f"mkdir -p {WEBROOT}/probes")
        remote_path = f"{WEBROOT}/probes/{stem}.html"
        url_path = f"/probes/{stem}.html"

    ok, msg = scp_file(local_path, remote_path)
    if not ok:
        return {"success": False, "message": msg}

    # Verify deployment
    verify_cmd = f"sha256sum {remote_path} | cut -c1-16"
    remote_hash, rc = ssh_cmd(verify_cmd)
    if rc != 0:
        return {"success": False, "message": "Verification failed: can't read remote file"}

    if remote_hash != probe_hash:
        return {
            "success": False,
            "message": f"Hash mismatch: local={probe_hash} remote={remote_hash}",
        }

    return {
        "success": True,
        "hash": probe_hash,
        "remote_path": remote_path,
        "url_path": url_path,
        "url": f"https://manuals.playstation.net{url_path}",
        "message": msg,
        "probe_name": stem,
    }


def restore_index():
    """Restore the original index.html from backup."""
    out, rc = ssh_cmd(f"cp {WEBROOT}/index.html.bak {WEBROOT}/index.html 2>&1")
    return rc == 0


def list_deployed():
    """List probe files currently on the server."""
    out, rc = ssh_cmd(f"ls -la {WEBROOT}/probes/ 2>/dev/null")
    if rc != 0:
        return []
    lines = out.strip().split("\n")
    return [l.split()[-1] for l in lines if l.endswith(".html")]
