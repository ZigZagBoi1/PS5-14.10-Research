# ioctl Command-Code Catalog — 13.60 Kernel Text Capture

> **Date:** 2026-10-21
> **Source:** `docs/dumps_13.60/kernel_text.bin` (15,132,096 bytes, kernel base
> `0xffffffff8a9c0000`, 13.60-labeled, acquisition authenticity unresolved).
> 13.60 codes are candidates for 14.10 only; codes may have changed.

## Why

PR #74 opened 34 `/dev` nodes from the game process and `ioctl(fd, 0)` returned
-1 on all 34 without killing the process: the ioctl path reaches the drivers,
but no real command code was ever tried. The 13.60 kernel text contains the
driver ioctl dispatchers as compare chains on the command register. Extracting
their constants gives the first real command-code list to try on 14.10.

## Method

1. Scan all `cmp r32, imm32` / `cmp eax, imm32` instruction bytes in the text
   capture (`tools/extract_ioctl_catalog.py`, regex superset).
2. Keep constants shaped like FreeBSD `_IOC` encodings:
   direction bits 31-30 in {OUT, IN, INOUT} or size 0, group char 0x20-0x7E,
   ordinal <= 0x50, size <= 0x400 and 4-byte aligned.
3. Disassemble the clusters with capstone and keep only clusters that decode
   as real dispatchers (binary-search or chain compares of the command
   register: `cmp r15/rsi, imm32; je handler`).

## Verified dispatchers (capstone-confirmed)

| Cluster RVA (range) | Groups | Sample codes |
|---|---|---|
| 0x28943d | S, P | 0x40845301, 0x40845303, 0xc0845301, 0xc0845302, 0xc0a84b00 |
| 0x54639d | A, f | 0x40084105/06/08, 0x400c4109/0a, 0x80044103/0c/0e/0f, 0x80084107/08/09 |
| 0x62e94a | t, f | 0x40047419/1a, 0x402c7412/13, 0x80047410, 0x802c7414/16 |
| 0x7974bb | t | 0x40047400-03, 0x40047440-42, 0x40407445, 0x80047401/02/04 |
| 0xa48139 | D, 1 | 0x40144401, 0x40184402, 0x4030440a/0b, 0xc00c440d/0e, 0xc0104410-14 |
| 0xaa47e5 | H | 0x80044808 (+ VOID 0x48xx ordinals 8/81/83/103-109/125/126) |
| 0xbb1a32 | U | 0x40205505, 0x80045501/02/06, 0xc0185501, 0xc1785504 |
| 0xc32493 | A, B | 0x4008411f/20, 0x4008421f/20, 0x4014421b/1c, 0x40184114/15, 0x40204117, 0x8008410e |
| 0x5266b0 | O | VOID 0x4f00/0x4f01 |

Example dispatcher (rva 0x7974ba, group `t`, binary search over the command):

```
cmp rsi, 0x40047441
jle ...
mov eax, 0x80047401
cmp rsi, rax
jle ...
mov eax, 0x80047402
cmp rsi, rax
je handler
```

## Probe

`probes/phase17_new_vectors/271a_ioctl_catalog_matrix.lua` tries 57 curated
codes on 10 openable nodes (`gc dce gic ajmi ajm camera notification0 usbctl
hid bt`), records every return != -1, and closes each fd. Buffer is zeroed
0x800 bytes (largest catalog copy size is 0x404). CRASH_CLASS: MODERATE.

## Limits

- The capture is 13.60-labeled and its authenticity is unresolved; 14.10
  dispatchers may use different codes entirely.
- The mapping dispatcher -> `/dev` node name is unknown (no rodata/name
  pointers in the captured ranges); the probe infers it from which fd accepts
  which code.
- The regex tool output is a superset with false positives; only the
  capstone-verified table above was used to build the probe.
