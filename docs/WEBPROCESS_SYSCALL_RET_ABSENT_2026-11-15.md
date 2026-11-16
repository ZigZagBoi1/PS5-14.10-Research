# No `syscall;ret` anywhere in WebProcess code — the browser chain must call stubs, not ROP through syscall

Offline measurement, 2026-11-15, on the WebKitGTK 2.42.0 reproduction build (Build-wc, LLInt-only,
JIT/DFG/FTL/WASM/ISO_MALLOC/SYSTEM_MALLOC all OFF — the closest configurable match to the PlayStation
port; see `docs/WEBKIT_TEXT_SIZE_BUILD_ESTIMATE_2026-11-12.md`).

Motivation: upstream p691 (commit 13de1acf, 2026-11-15) mapped the GOT.PLT at VP+0x2000..VP+0x4000 and
stated the next step as "find `syscall;ret` via SPRX import tables or offline binary analysis". This
note supplies the offline-binary-analysis half.

## Method

Full gadget census over every object file in Build-wc (2,198 `.o` files, all components: WebCore,
JavaScriptCore, WTF, bmalloc, ANGLE, PAL). Two independent passes:

1. Byte-pattern scan over SHF_EXECINSTR PROGBITS sections (readelf -SW) for 13 target patterns.
2. capstone 5.0.6 linear sweep (`skipdata=True`) over the same sections, counting decoded `syscall`
   instructions — this is the same method 1186a used for the eboot ymm0 census
   (`docs/EXEC_ONLY_LIBKERNEL_14_10.md`).

## Results

| pattern | hits |
|---|---|
| `0f 05 c3` syscall;ret | 0 |
| `0f 05 90 c3` syscall;nop;ret | 0 |
| `0f 31 c3` rdtsc;ret | 0 |
| `49 89 ca c3` mov r10,rcx;ret | 0 |
| `41 58/59/5a c3` pop r8/r9/r10;ret | 0 |
| `c5 fc 11 07 c3` vmovups [rdi],ymm0;ret | 0 |
| `c5 fc 10 07 c3` vmovups ymm0,[rdi];ret | 0 |
| `5f c3` pop rdi;ret | 35,190 |
| `5e c3` pop rsi;ret | 16,188 |
| `5c c3` pop rsp;ret | 22,229 |
| `58 c3` pop rax;ret | 359 |
| `5a c3` pop rdx;ret | 50 |

Decoded `syscall` instructions in the entire 2,198-object build: **exactly one**, at
`LowLevelInterpreter.cpp.o` .text+0x83a6 — and it is a decoy. The `0f 05` bytes sit in LLInt
opcode-table slack between `llint_op_unsigned_wide16` and `llint_op_unsigned_wide32`, preceded by
`jmp *(%rsi,%rax,8)` (dispatch away) and followed by the next opcode label. It is never executed and
is not followed by `ret`.

Disassembly-path sanity anchor: the same sweep decodes 64 `int3` instructions, so the pass detects
real instructions — `syscall` genuinely is never emitted.

## Why this is the expected result, not a build artifact

Userspace WebKit never issues a raw `syscall`. Every kernel transition goes through libc/libkernel
stubs (`mov rax,N; mov r10,rcx; syscall; ret`), which live in SPRX module text, not in the WebProcess
binary. Compiler codegen does not emit `syscall` for library code, and none of WebKit's hand-written
assembly (LLInt, offlineasm) contains one either — the single hit above is opcode-table data.

This is a codegen property, not a port property: the Sony 605.1.15 build uses the same compiler class
and the same stub indirection, so the conclusion carries despite the GTK skew caveat that applies to
size numbers.

## Consequence for the p691 chain

The WebProcess address space contains **no readable code segment with a `syscall;ret` gadget**:

- WebProcess text (measured here): none.
- libkernel text: has the stubs, but is execute-only via protection keys — unreadable from userland
  (`docs/EXEC_ONLY_LIBKERNEL_14_10.md`, probes 1183a/1183b). Its gadgets cannot be byte-verified or
  scanned.
- eboot (Lua loader side, different process): full 4.6 MB scan already found zero `syscall;ret`
  (probe 56s, dead-ends reference).

So the "SPRX import tables" half of upstream's plan is the only route, and it does not yield a gadget
— it yields the **stub itself**. The chain shape that works is the one the Lua loader already uses:
`call [import_slot]` (or `call resolved_stub`) with the syscall number in rax and args in
rdi/rsi/rdx/r10/r8/r9. Notably the libkernel stub form `mov rax,N; mov r10,rcx; syscall; ret` means
the stub entry handles the r10 shuffle internally — the chain only needs `call [slot]`, not a
`mov r10,rcx;ret` gadget (also absent: 0 hits).

The rich pop-gadget set (rdi/rsi/rsp plentiful, rax 359, rdx 50 — byte-count before execution
verification, same caveat as CHAIN_14_10.md's "byte hits must be checked by execution") is enough for
argument setup around stub calls. What does not exist is a way to drop the stub dependency.

## Caveats

- GTK 2.42.0 reproduction build, not the Sony binary. Absolute gadget *offsets* will differ on
  device; absence of `syscall`/`rdtsc`/YMM-store gadgets will not.
- Byte-pattern counts (pop gadgets) are pre-verification counts — suffix-of-longer-instruction hits
  included. Only the zero counts are claimed as final.
- SPRX modules other than libkernel (libc, libSceWebKit2 support libs) were not scanned here — no
  decrypted PS5 SPRX exists in this checkout. libc on the Lua-loader side is readable; whether the
  WebKit process's libc contains `syscall;ret` is open but bounded by the same codegen argument
  (libc syscall stubs end in `ret`, so `0f 05 c3` at stub+7 equivalent offsets is plausible there —
  that is the one place a scan is still worth running on-device).
