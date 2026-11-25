#!/usr/bin/env python3
"""Regression tests for the VPS setup script and nginx configuration."""

import re
import shutil
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
IPV4_FUNC_RE = re.compile(r"^is_ipv4\(\) \{\n.*?^\}", re.MULTILINE | re.DOTALL)


def generated_nginx_config():
    return "\n".join(HEREDOC_RE.findall(SETUP.read_text(encoding="utf-8")))


def ipv4_accepted(value):
    match = IPV4_FUNC_RE.search(SETUP.read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError("missing is_ipv4 function")
    result = subprocess.run(
        ["bash", "-c", match.group(0) + '\nis_ipv4 "$1"', "test", value],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(result.stderr)
    return result.returncode == 0


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

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_ipv4_validator_rejects_out_of_range_octets(self):
        for value in ("0.0.0.0", "255.255.255.255", "192.168.1.1", "8.8.8.8"):
            with self.subTest(value=value):
                self.assertTrue(ipv4_accepted(value))
        for value in ("", "256.1.1.1", "999.999.999.999", "1.2.3",
                      "1.2.3.4.5", "1..2.3", "-1.2.3.4", "1.2.3.a"):
            with self.subTest(value=value):
                self.assertFalse(ipv4_accepted(value))


if __name__ == "__main__":
    unittest.main()
