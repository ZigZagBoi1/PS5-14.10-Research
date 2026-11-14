# libkernel is execute-only on 14.10, eboot is readable, and eboot has ymm0 stores

Measured 2026-11-04 (sixth boot) with probes 1183a, 1183b, 1184a, 1185a, 1186a, 1187a.

## The finding

The loader resolves itself with `sceKernelGetModuleInfoFromAddr` and takes `libkernel_base` from
`mod_info+0x160` (`.local/loader_payload/syscall.lua:36-52`). On PS5 it never reads libkernel text -
`syscall.syscall_address = *libc_gettimeofday_import + 7` is only ever `call`ed (`syscall.lua:26-28`).
Probe 1183b shows why that matters:

    [I] libc gettimeofday import slot = 0x00000001E207F9A8
    [I] *slot (libkernel text ptr)  = 0x00000008083B4B50
    [I] syscall.syscall_address     = 0x00000008083B4B57
    [I] libkernel_base (derived)    = 0x00000008083B4000
    [I] sa - b0                     = 0x0000000000000B57

`sa` is **inside the first page** of `libkernel_base`, at `+0xB57`. The loader executes that page for
every syscall it ever makes. Reading four bytes at `sa-8` killed the process before the byte dump could
print, and 1183a died the same way on page 0 *and* page 1 of `libkernel_base`.

Same page, executable, not readable. On x86-64 that is not a page-table property - there is no
read-disable bit - so libkernel text is mapped **execute-only through protection keys (PKU/PKRU)**, the
only mechanism Zen2 offers for it. Whether it is PKU or a Sony-specific trick, the operational
consequence is what matters:

* **libkernel text can never be read from userland.** Not for gadgets, not for the syscall table, not
  for a byte leak. 1173a's approach works on libc only.
* It retroactively explains 1182a and both 1183a runs, which "died for no reason" while scanning
  `libkernel_base`.

## eboot is readable, and it is full of AVX

`eboot_base` comes from `luaB_auxwrap - eboot_addrofs.luaB_auxwrap` (`.local/loader_payload/lua.lua:269`)
and the module reads normally. 1184a walked it with 1 MB `read_buffer` chunks and a byte-level VEX
motif scan:

| chunk | address | candidate `ymm0` stores | `vzeroupper` |
|---|---|---|---|
| 00 | `0x46EF4000` | 704 | 0 |
| 01 | `0x46FF4000` | 840 | 0 |
| 02 | `0x470F4000` | 426 | 0 |
| 03 | `0x471F4000` | 28 | 0 |
| 04 | - | read faulted, process died | |

Zero `vzeroupper` in the first 4 MB. The counts are inflated by `0xC5` bytes that are not prefixes, so
1185a/1186a replaced counting with disassembly.

## The dump-and-disassemble method

1186a dumps 1 MB of eboot as hex, 0x10000 per chunk with a `[D nn] off=...` header per chunk, and the
driver reassembles it into `.local/dumps/eboot_chunk0.bin` (1,048,576 bytes, all 16 chunks complete).
Note the marker must be exactly `=== DONE ===`; `=== 1186a DONE ===` makes `send_probe.py` report a
death that did not happen.

capstone 5.0.7 linear sweep with `skipdata=True` (without it `disasm` stops at the first invalid byte
and returns zero instructions) over that 1 MB gives 289,483 instructions and exactly two gadgets that
store a ymm and reach `ret` without touching memory in between:

    0F7CB7  vmovups ymmword ptr [rsi], ymm0 ; ret
            bytes: c5 fc 11 06 c3   (preceded by 31 c0 / c5 fc 11 4e 18 / ... at 0xF7CB0)
    0D4144  vmovups ymmword ptr [r10], ymm0 ; mov eax, 6 ; ret
            bytes: c4 c1 7c 11 02 b8 06 00 00 00 c3

The `[rsi]` one is the useful shape: `native.fcall_with_rax(fn, rax, rdi, rsi, ...)` gives us rsi
directly (`.local/loader_payload/native.lua:209-222`, argument order verified against the chain builder
`native.gen_fcall_chain` at `:30-54` - rdi is stack slot 5, rsi slot 6, rax slot 4).

## What is still open

1187a called `eboot+0xF7CB7` with `rsi` = a 0x100 buffer filled with `0xC0`, before and after real
syscalls, and **the buffer never changed** - no ymm0 content, no fault, no death. Two readings, not yet
separated:

* the fcall really did not reach the gadget (an error swallowed by the `pcall` in the probe - 1187a
  printed no status), or
* rsi was clobbered on the way in (the chain sets r9, r8, rcx, rdx, rsi, rdi, then rax, so a clobbering
  `push_set_*` would have to be in `push_set_rax_from_memory`).

1188a is written and waiting for a live loader: a memcpy positive control through the exact same path
(dst = buffer, src = eboot, n = 16, must produce `2f 6c 69 62 65 78 65 63` = `/libexec`), then the
gadget with every pcall status printed, then the neighbouring `0xF7CB4` (`[rsi+0x18]`) as a second
address probe.

Until that positive control passes, the ymm0 question is unanswered, not refuted.

## Method notes worth keeping

* A YMM store gadget is worthless without a controlled base register: check the base register against
  what `fcall_with_rax` can set (rax, rdi, rsi, rdx, rcx, r8, r9) before believing a hit.
* Linear sweep from offset 0 of a real module yields plenty of instructions whose "addresses" are not
  code - always confirm the exact entry bytes of a gadget before calling it.
* `memory.read_buffer` of a whole megabyte is fine and fast; the scan cost is in Lua, not in the copy,
  so do the byte work offline in capstone rather than in the probe.
