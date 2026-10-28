"""Adversarial WebSocket payloads shared by tools/ws_fuzz_server.py (8443) and
tools/webkit_server.py (the /ws route on the trusted 443 listener)."""

import struct
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# --- payload builders -------------------------------------------------------

def deflate_raw(data):
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def frame(opcode, payload, fin=True, rsv1=False, rsv2=False, rsv3=False, length=None):
    b0 = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | (0x20 if rsv2 else 0) | (0x10 if rsv3 else 0) | (opcode & 0xF)
    n = len(payload) if length is None else length
    if n < 126:
        head = bytes([b0, n])
    elif n < 65536:
        head = bytes([b0, 126]) + struct.pack(">H", n)
    else:
        head = bytes([b0, 127]) + struct.pack(">Q", n)
    return head + payload


def case_list():
    """(name, bytes to send, note)."""
    cases = []

    # 1. plain text / control frames, well formed (control)
    cases.append(("text-hello", frame(0x1, b"hello"), "control"))

    # 2. deflate negotiation: valid compressed message
    body = b"A" * 4096
    cases.append(("deflate-valid", frame(0x1, deflate_raw(body), rsv1=True), "valid permessage-deflate"))

    # 3. deflate with BFINAL=1 (should be BFINAL=0 with the 00 00 ff ff tail)
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    fixed = c.compress(b"B" * 1024) + c.flush(zlib.Z_FINISH)
    cases.append(("deflate-bfinal", frame(0x1, fixed + b"\x00\x00\xff\xff", rsv1=True), "BFINAL set"))

    # 4. stored block with an overlong LEN (claims 0xFFFF, provides 8 bytes)
    cases.append(("deflate-short-len", frame(0x1, b"\x00\xff\xff\x00\x00" + b"C" * 8, rsv1=True), "stored block LEN lies"))

    # 5. dynamic Huffman with code-length repeat overflow
    cases.append(("deflate-huff-overflow", frame(0x1, bytes([0x05, 0xC0, 0x81, 0x00]) + b"\x00" * 16, rsv1=True), "truncated dynamic huffman"))

    # 6. distance pointing before the output start
    cases.append(("deflate-bad-distance", frame(0x1, b"\x63\x00\x02\x00", rsv1=True), "distance before start"))

    # 7. deflate bomb: tiny frame, huge expansion
    bomb = deflate_raw(b"\x00" * (1 << 24))
    cases.append(("deflate-bomb-16m", frame(0x1, bomb, rsv1=True), "16 MiB expansion"))

    # 8. deflate on a control frame (invalid per RFC)
    cases.append(("deflate-on-ping", frame(0x9, deflate_raw(b"x"), rsv1=True), "rsv1 on control"))

    # 9. fragmented message with a control frame in the middle (legal) and then a
    #    continuation that never finishes
    cases.append(("frag-never-end", frame(0x1, b"part", fin=False) + frame(0x9, b"p"), "unterminated fragment"))

    # 10. continuation without a start
    cases.append(("cont-without-start", frame(0x0, b"orphan"), "continuation first"))

    # 11. new data frame while a fragment is open
    cases.append(("interleaved-data", frame(0x1, b"a", fin=False) + frame(0x1, b"b"), "data during fragment"))

    # 12. length header says 127 (8-byte length) but only 4 bytes follow
    cases.append(("len127-short", bytes([0x81, 127]) + struct.pack(">Q", 16) + b"abcd", "8-byte length lies"))

    # 13. length 126 (2-byte) with the high bit set (negative-ish)
    cases.append(("len126-hi", bytes([0x81, 126]) + struct.pack(">H", 0xFFFF) + b"abcd", "2-byte length lies"))

    # 14. masked frame from the server (clients must not mask, servers must not)
    mask = b"\x01\x02\x03\x04"
    payload = bytes(b ^ mask[i & 3] for i, b in enumerate(b"masked-server"))
    cases.append(("server-masked", bytes([0x81, 0x80 | len(payload)]) + mask + payload, "server frame masked"))

    # 15. huge declared text frame, then close
    cases.append(("declare-4g", bytes([0x81, 127]) + struct.pack(">Q", 0xFFFFFFFF) + b"head", "4 GiB declared"))

    # 16. close frame with a 1-byte payload (invalid: must be 0 or >=2)
    cases.append(("close-1byte", frame(0x8, b"\x03"), "close payload 1 byte"))

    # 17. close frame with an invalid UTF-8 reason
    cases.append(("close-bad-utf8", frame(0x8, struct.pack(">H", 1000) + b"\xff\xfe"), "close reason invalid utf8"))

    # 18. text frame with invalid UTF-8
    cases.append(("text-bad-utf8", frame(0x1, b"\xc3\x28\xa0\xa1\xe2\x28\xa1"), "invalid utf8 text"))

    # 19. many tiny frames in one write (pipelining)
    cases.append(("many-tiny", b"".join(frame(0x1, b"x") for _ in range(512)), "512 frames"))

    # 20. ping flood without pong reads
    cases.append(("ping-flood", b"".join(frame(0x9, b"p" * 125) for _ in range(1024)), "1024 pings"))

    return cases
