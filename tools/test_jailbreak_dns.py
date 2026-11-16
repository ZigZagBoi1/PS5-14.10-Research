#!/usr/bin/env python3
"""Offline protocol tests for the jailbreak host's DNS responder."""

import importlib.util
import socket
import struct
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent / "jailbreak-host" / "server.py"
SPEC = importlib.util.spec_from_file_location("jailbreak_host_server", SERVER)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def _question(qclass=1, qtype=1):
    name = b"".join(
        bytes([len(label)]) + label
        for label in b"manuals.playstation.net".split(b".")
    ) + b"\x00"
    return name + struct.pack("!HH", qtype, qclass)


def _query(qclass=1, qtype=1, qdcount=1, extra=b""):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, qdcount, 0, 0, 0)
    return header + _question(qclass, qtype) + extra


class JailbreakDnsTests(unittest.TestCase):
    def test_redirects_an_in_a_query(self):
        response = server.build_dns_response(_query(), "127.0.0.1")
        self.assertIsNotNone(response)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
        self.assertEqual(response[-4:], socket.inet_aton("127.0.0.1"))

    def test_does_not_answer_a_non_in_class_a_query(self):
        self.assertIsNone(server.build_dns_response(_query(qclass=3), "127.0.0.1"))

    def test_does_not_answer_a_multi_question_query(self):
        packet = _query(qdcount=2, extra=_question())
        self.assertIsNone(server.build_dns_response(packet, "127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
