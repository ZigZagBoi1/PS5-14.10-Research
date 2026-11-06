#!/usr/bin/env python3
"""Protocol tests for the browser runner's DNS spoofer."""

import socket
import struct
import unittest
from unittest import mock

from tools.browser_runner import dns_spoof


def _query(qtype=1, qclass=1):
    labels = b''.join(
        bytes([len(label)]) + label
        for label in b'manuals.playstation.net'.split(b'.')
    )
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    return header + labels + b'\x00' + struct.pack('!HH', qtype, qclass)


class DNSSpoofTests(unittest.TestCase):
    def setUp(self):
        self.handler = dns_spoof.DNSHandler.__new__(dns_spoof.DNSHandler)
        self.handler.client_address = ('192.0.2.10', 12345)
        dns_spoof.DNSHandler.spoof_ip = '127.0.0.1'
        dns_spoof.DNSHandler.upstream = '192.0.2.1'

    def test_spoofs_in_a_query(self):
        response = self.handler._process(_query(qtype=1, qclass=1))
        self.assertIsNotNone(response)
        self.assertEqual(struct.unpack('!H', response[6:8])[0], 1)
        self.assertEqual(response[-4:], socket.inet_aton('127.0.0.1'))

    def test_does_not_spoof_non_internet_class(self):
        with mock.patch('tools.browser_runner.dns_spoof.socket.socket') as sock:
            sock.return_value.recvfrom.return_value = (b'UPSTREAM', None)
            response = self.handler._process(_query(qtype=1, qclass=3))
        self.assertEqual(response, b'UPSTREAM')

    def test_does_not_spoof_non_a_query(self):
        with mock.patch('tools.browser_runner.dns_spoof.socket.socket') as sock:
            sock.return_value.recvfrom.return_value = (b'UPSTREAM', None)
            response = self.handler._process(_query(qtype=28, qclass=1))
        self.assertEqual(response, b'UPSTREAM')


if __name__ == '__main__':
    unittest.main()
