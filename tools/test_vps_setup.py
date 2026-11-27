#!/usr/bin/env python3
"""Regression tests for the VPS setup script and nginx configuration."""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETUP = ROOT / "tools" / "vps_setup.sh"
NGINX = ROOT / "tools" / "vps_nginx.conf"

HEREDOC_RE = re.compile(
    r"sudo tee(?: -a)? /etc/nginx/sites-available/ps5research[^\n]*"
    r"<< 'NGINXEOF'\n(.*?)\nNGINXEOF",
    re.DOTALL,
)
FUNC_RE = re.compile(
    r"^is_(?:ipv4|public_ipv4)\(\) \{\n.*?^\}", re.MULTILINE | re.DOTALL)


def extracted_functions():
    functions = FUNC_RE.findall(SETUP.read_text(encoding="utf-8"))
    if not functions:
        raise AssertionError("missing IP validation functions")
    return "\n".join(functions)


def generated_nginx_config():
    return "\n".join(HEREDOC_RE.findall(SETUP.read_text(encoding="utf-8")))


def ipv4_accepted(value):
    result = subprocess.run(
        ["bash", "-c", extracted_functions() + '\nis_ipv4 "$1"', "test", value],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(result.stderr)
    return result.returncode == 0


def public_ipv4_accepted(value):
    if "is_public_ipv4()" not in extracted_functions():
        raise AssertionError("missing is_public_ipv4 function")
    result = subprocess.run(
        ["bash", "-c", extracted_functions() + '\nis_public_ipv4 "$1"', "test", value],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(result.stderr)
    return result.returncode == 0


def bash_probe_sane():
    """Some Windows bash launchers (the WindowsApps WSL shim) pre-expand the
    `-c` script against an empty outer context, so positional arguments never
    reach the script. Probe before trusting the local bash with the octet
    validator; the loopback suites run it for real on Linux runners."""
    try:
        result = subprocess.run(
            ["bash", "-c", 'printf "%s" "$1"', "probe", "CANARY"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout == "CANARY"


HAS_SANE_BASH = bash_probe_sane()


class VpsConfigTests(unittest.TestCase):
    def test_generated_config_routes_tester_hub_stage_scripts(self):
        config = generated_nginx_config()
        self.assertIn("location /probes/ {", config)
        self.assertIn("try_files $uri =404;", config)

    def test_checked_in_config_bootstraps_with_snakeoil_certs(self):
        config = NGINX.read_text(encoding="utf-8")
        self.assertIn(
            "ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;", config)
        self.assertIn(
            "ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;", config)
        self.assertNotIn(
            "ssl_certificate /etc/letsencrypt/live/ps5research/fullchain.pem;",
            config)

    def test_acme_exemption_matches_normalized_uri(self):
        configs = (generated_nginx_config(), NGINX.read_text(encoding="utf-8"))
        for config in configs:
            self.assertIn(
                r"if ($uri ~ ^/\.well-known/acme-challenge/)", config)
            self.assertNotIn(
                r"if ($request_uri ~ ^/\.well-known/acme-challenge/)", config)

    @unittest.skipUnless(HAS_SANE_BASH, "bash unavailable or -c positionals broken (e.g. WindowsApps WSL launcher)")
    def test_ipv4_validator_rejects_out_of_range_octets(self):
        for value in ("0.0.0.0", "255.255.255.255", "192.168.1.1", "8.8.8.8"):
            with self.subTest(value=value):
                self.assertTrue(ipv4_accepted(value))
        for value in ("", "256.1.1.1", "999.999.999.999", "1.2.3",
                      "1.2.3.4.5", "1..2.3", "-1.2.3.4", "1.2.3.a",
                      "1.2.3.4.", "1.2.3.4\n", "1.2.3.4\n5.6.7.8",
                      "1.2.3.4\naddress=/manuals.playstation.net/6.6.6.6",
                      "1.2.3.4\r\n5.6.7.8", "1.2.3.4\t"):
            with self.subTest(value=value):
                self.assertFalse(ipv4_accepted(value))

    @unittest.skipUnless(HAS_SANE_BASH, "bash unavailable or -c positionals broken (e.g. WindowsApps WSL launcher)")
    def test_public_ipv4_validator_rejects_non_global_addresses(self):
        for value in ("8.8.8.8", "1.1.1.1"):
            with self.subTest(value=value):
                self.assertTrue(public_ipv4_accepted(value))
        for value in ("0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1",
                      "169.254.1.1", "172.16.0.1", "192.168.1.1",
                      "198.18.0.1", "224.0.0.1", "255.255.255.255"):
            with self.subTest(value=value):
                self.assertFalse(public_ipv4_accepted(value))

    def test_setup_installs_fresh_host_prerequisites(self):
        script = SETUP.read_text(encoding="utf-8")
        install = script[script.index("sudo apt install"):].split("\n\n", 1)[0]
        for package in ("curl", "ssl-cert", "iptables", "netfilter-persistent"):
            self.assertIn(package, install)

    def test_setup_validates_home_ip_before_system_mutation(self):
        script = SETUP.read_text(encoding="utf-8")
        self.assertIn('HOME_IP="${1:-}"', script)
        self.assertNotIn("REPLACE_ME", script)
        self.assertLess(script.index('is_ipv4 "$HOME_IP"'),
                        script.index("sudo apt update"))

    def test_setup_checks_bootstrap_cert_before_dns_mutation(self):
        script = SETUP.read_text(encoding="utf-8")
        self.assertIn("ssl-cert-snakeoil.pem", script)
        self.assertIn("ssl-cert-snakeoil.key", script)
        self.assertLess(script.index("ssl-cert-snakeoil.key"),
                        script.index("systemctl stop systemd-resolved"))

    def test_public_ip_lookup_supports_manual_override(self):
        script = SETUP.read_text(encoding="utf-8")
        self.assertIn('VPS_IP="${VPS_IP:-', script)


if __name__ == "__main__":
    unittest.main()
