"""Offline test for durable range receipts and a resumed LAN session."""

import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest


spec = importlib.util.spec_from_file_location("pup_bridge", Path(__file__).with_name("pup_bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class ResumeProtocolTest(unittest.TestCase):
    def test_receipt_survives_new_session_and_detects_corruption(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            source = out / "source"
            source.write_bytes(b"test source")

            def session(resume, commands):
                client, server = socket.socketpair()
                results = []

                def receiver():
                    try:
                        results.append(bridge.serve(server, source, out, resume))
                    finally:
                        server.close()

                worker = threading.Thread(target=receiver)
                worker.start()
                try:
                    def request(op, entry=0, offset=0, data=b"", length=None):
                        count = len(data) if length is None else length
                        client.sendall(bridge.HEADER.pack(b"P14R", ord(op), entry, 0,
                                                          offset, count) + data)
                        return client.recv(4)

                    self.assertEqual(request("B", 1), b"OLD!" if resume else b"OKAY")
                    commands(request)
                    self.assertEqual(request("F", offset=1), b"OKAY")
                finally:
                    client.close()
                    worker.join(5)
                self.assertEqual(results, [True])

            def first(request):
                self.assertEqual(request("W", 1, 12, b"data"), b"OKAY")
                self.assertEqual(request("Q", 1, 12, length=4), b"HAVE")

            def second(request):
                self.assertEqual(request("Q", 1, 12, length=4), b"HAVE")
                self.assertEqual(request("Q", 1, 11, length=4), b"MISS")

            session(False, first)
            session(True, second)
            with (out / "PS5_1410_PS5UPDATE1.PUP.dec").open("r+b") as output:
                output.seek(12)
                output.write(b"bad!")

            session(True, lambda request: self.assertEqual(
                request("Q", 1, 12, length=4), b"MISS"))


if __name__ == "__main__":
    unittest.main()
