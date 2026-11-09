# 13.60 UMTX code extraction — 2026-10-21

The retained 13.60 `kernel_text.bin` already spans RVA `0x0`–`0xe6e5c0`. Its 924-entry failmap contains no failed chunks. The syscall table records slot 454 (`_umtx_op`) at RVA `0x265600`; this entry jumps to the operation dispatcher at RVA `0x37ec40`. A new live 13.60 collection was unnecessary for this code path.

The private extraction in `artifacts/private_1360_umtx_454/` contains the syscall stubs (RVA `0x265600`–`0x2656e0`), dispatch and nearby handlers (RVA `0x37e000`–`0x38c000`), and SHA-256/failed-chunk metadata. The wider range includes the shared mutex lock routine at `0x383ff0` (called by op 5) and shared unlock routine at `0x385fb0` (tail-called by op 6). These are copies of saved 13.60 bytes, not fresh console output. Functions called outside the selected ranges remain in the complete `kernel_text.bin` and can be followed there.

| UMTX operation | 13.60 stub RVA | Handler RVA | 14.10 evidence |
| --- | --- | --- | --- |
| 5, mutex lock | `0x265628` | `0x37fc90` | Uncontended PI-flag lock returned 0 on 2026-10-21. |
| 6, mutex unlock | `0x265630` | `0x37fd70` | Uncontended PI-flag unlock returned 0 on 2026-10-21. |
| 18 | `0x265690` | `0x381af0` | Not established by the PI baseline. |
| 19 | `0x265698` | `0x381e70` | Not established by the PI baseline. |
| 20 | `0x2656a0` | `0x382280` | Not established by the PI baseline. |
| 25, SHM | `0x2656c8` | `0x3835b0` | Tested 14.10 calls returned -1. |
| 26, robust lists | `0x2656d0` | `0x3837f0` | Tested 14.10 calls returned -1. |

This dispatch map is verified against 13.60 bytes only. The 14.10 PI baseline proves ordinary lock/unlock reachability, not a pointer leak, UAF, or kernel read/write. A 14.10 kernel image or independently observed 14.10 behavior is required before treating these RVAs or implementation details as current firmware facts.

The user's AJM/A53 summary describes probe 275a, but that probe and its raw capture are not present in this checkout as of this note. Treat its 107 rejected ioctl calls as a reported result until the capture is added. The saved `58a` msync capture ends at `BEFORE msync(MS_SYNC)` with no return or canary; it does not establish `MS_INVALIDATE` reachability and repeating it unchanged would repeat a process termination boundary.

## Jump-table gap and live collection attempt

The shared lock routine at RVA `0x383ff0` reads mutex flags and uses bits 2–3 as an index into a four-entry relative jump table at RVA `0x14c0728`. Flag `0x04` selects index 1. That table lies beyond the saved 13.60 `kernel_data.bin` range (`0x1000000`–`0x1400000`), so its four values cannot be recovered from the retained dump. The table is needed to identify the precise PI branch without guessing from nearby code.

`tools/v1360-dumper/umtx_jump_table.c` is a bounded read-only collector: it obtains the SDK's current text base, checks the saved text signature at base+`0x10`, and only then requests 16 bytes at base+`0x14c0728`. It reports status and bytes to `tools/v1360-dumper/receive_umtx_table.py`. The ELF compiled successfully and 110,824 bytes were sent once to the 13.60 loader at `10.0.0.30:9021` on 2026-10-21. The receiver timed out without a connection. A subsequent TCP check found port 9021 unreachable, and one ICMP ping timed out. This is **not a successful table read**; no firmware version, current kernel base, or table bytes were observed. Do not automatically resend the same ELF. Check console and loader state first, then investigate callback/firewall or payload execution failure.
