# sys 601 `mdbg_service` — limits of the 13.60 evidence

> **Date:** 2026-11-05. Source: `docs/dumps_13.60/kernel_text.bin` /
> `kernel_data.bin` (13.60 labeled capture; acquisition authenticity
> unresolved — see `docs/dumps_13.60/README.md`). Every address is a 13.60
> RVA from kernel base `0xffffffff8a9c0000`. **14.10 status: measured live**
> (PR #90, probes 322a–324a, captures
> `results/phase17_new_vectors/322a_sys601_commands_20261022_122315.txt`
> through `324a_sys601_sweep2_20261022_122438.txt`; plus 55d, 83a, 83c).
> This doc does not extend the 14.10 evidence — it marks where the static
> record ends, so the live results and the old dossier claims stop being
> cited as if they describe the same thing.

## What the capture does contain

| field | value |
|---|---|
| sysent thunk | `0x265e18` (from `sysent_index.json` entry 601, narg 3) |
| handler body | thunk `jmp` targets RVA `0xca0630` |
| body extent | `0xca0630`–`0xca2310` (4,328 bytes; epilogue at `0xca221c`, thunk-style padding after `0xca230a`) |
| stack canary | loaded from `[rip+0x2c7bcc5]` = RVA `0x32dc310` (outside both captured ranges) |

Entry block (`0xca0630`–`0xca067d`):

```asm
0xca0658  mov eax, dword ptr [rsi]        ; cmd = arg0 low dword
0xca065a  cmp rax, 0x27
0xca065e  ja  0xca221c                    ; out of range -> common return (r14d=0x4e=78)
0xca0664  lea rcx, [rip + 0xdb0af5]       ; rcx = 0x1a51160  <-- JUMP TABLE RVA
0xca066b  mov r15, qword ptr [rsi + 8]    ; arg1
0xca066f  mov r12, qword ptr [rsi + 0x10] ; arg2
0xca0676  movsxd rdx, dword ptr [rcx + rax*4]
0xca067a  add rdx, rcx
0xca067d  jmp rdx
```

## The limit: the 40-entry jump table is not in the capture

The table RVA resolves as:

```
lea end (0xca066b) + disp (0xdb0af5) = 0x1a51160
```

`0x1a51160` is **outside every retained range**:
`kernel_text.bin` covers RVA `< 0xe6e5c0`, and `kernel_data.bin` covers
`0x1000000`–`0x1400000`. A full cross-reference scan of `kernel_text.bin`
(`48 8d 05 rel32` pattern, target = `0x1a51160`) finds exactly one
referencing site — the dispatch `lea` at `0xca0664` — so no other retained
code path reveals the table's contents either.

Consequences, stated plainly:

1. **Only 9 of the 40 command targets are known.** The mapping table in
   `docs/SYS601_1360_DISPATCH_AUDIT_2026-10-22.md` (0x05/0x06 → `0xca221c`,
   0x0c → `0xca0e7d`, 0x10 → `0xca15df`, 0x11 → `0xca0f58`,
   0x12 → `0xca1032`, 0x24/0x25 → `0xca067f`, 0x07 → `0xca0d6c`,
   0x09 → `0xca0b7e`, 0x0d → `0xca141e`) cannot be reverified from the
   retained bytes, because the table those offsets were read from is absent.
   They are treated as prior-analysis claims, consistent with the live
   14.10 results but not independently established here.
2. **31 commands (including 0x02, 0x03, 0x04, 0x08, 0x0e–0x0f, 0x13–0x23,
   0x26–0x27) have no attributable body at all in this capture.** Any
   statement about their argument layouts, gates, or effects from static
   material alone is unsupported.
3. The large sub-regions described in
   `results/kernel_handlers/analysis/sys_601_deep.md` ("Device Name
   Matching", "Device Configuration Writer", "Process Teardown",
   "Init/Shutdown", "VFS Path Resolution" — offsets up to `0x3a60`+
   relative to the body start) would extend to at least RVA `0xca4090`,
   past the verified body end (`0xca2310`). They are **outside the handler
   body** as bounded by its epilogue; if they exist as described, they are
   separate functions reached from table targets the capture does not
   contain. Their auth and vulnerability claims are therefore also
   table-dependent and unverifiable from this dump.

## What the retained bytes do show (verified against `dis_rva.py` output)

- **Common return `0xca221c`:** canary check, `mov eax, r14d`, `ret`. The
  out-of-range path enters with `r14d = 0x4e` (78) preloaded at the body
  prologue (`0xca064b`), so an unmapped or out-of-range command returns
  78 (`ENOSYS`-class), not a handler-specific error.
- **cmd 0x12 copyout path (`0xca1b2c`–`0xca1bad`)** — the kptr_hunt
  OBJECT-sourced site at `0xca1b8b` (`copyout(src=[r13+0x578], len=0x480)`)
  is a **paired read-back**, verified instruction-by-instruction:
  `+0x528` flag bit 0x400 is *cleared* (`and rax, ~0x400`), the existing
  `+0x578` buffer is copied out, then freed (`call 0xc08df0` with a
  heap-pointer-size class), then `+0x578` is zeroed. It is the read half of
  the store/load pair installed by cmd 0x11 — not an unconditional leak and
  not an arbitrary process write. This confirms the audit doc's correction
  over the older `sys_601_deep.md` "cmd 0x12 arbitrary write / kfree
  primitive" reading.
- **cmd 0x07 (`0xca0d6c`):** allocates `0x1000` bytes (`call 0xc08b50`,
  malloc-class) and calls `0x259900` (uiomove-class) with `rsi=rbx` (the
  fresh allocation), `rdi=r15` (arg1), `rdx=0x1000`. The "BEXTR bitfield
  extraction" label in `sys_601_deep.md` is unsupported; whether the page
  is copied *to* or *from* userland, and whether it is zeroed first,
  depends on helper `0x259900`'s direction, which this doc does not
  resolve. Live: returns 0 and writes nothing to the caller's buffer
  (PR #90).
- **cmd 0x09 (`0xca0b7e`):** loads the process state object
  `[r8+8]->+0x568`, takes its `+0x28` mutex, and modifies fields of that
  object — not a "global byte leak at 0x316d0f8".
- **cmd 0x0d (`0xca141e`):** locks, loads `+0x528` flags, tests bit
  `0x100`, and branches on a state field at `proc+0x36c` — a state/flag
  path, not "thread enumeration".

## 14.10 live results (already on record — cited, not re-derived)

From PR #90 (merged) and the earlier probes it reconciles:

| cmd | 14.10 result |
|---|---|
| `0x00` | ret 0, writes `0x00000100` into the first output word |
| `0x01`, `0x02`, `0x05`, `0x06`, `0x0a`, `0x10`, `0x12` | ret -1, buffer untouched |
| `0x03`, `0x04` | **terminate the process** |
| `0x07`, `0x09`, `0x0d`, `0x13`, `0x14`, `0x19` | ret 0, buffer untouched |
| `0x15`–`0x18` | ret -1 (55d) |

83c established that cmd 0x00's output word (`0x100`) is a record-size
report with no following record (`arg2_after=0x100`, arg3 sentinel
unchanged; with arg2 null it returns -1).

## How the three records line up

1. The static decode shows a 40-command debugger/service multiplexer whose
   interesting commands are paired store/load operations against a
   per-process state object (`proc+0x568`), keyed by flag bit `0x400` in
   `+0x528`.
2. The live 14.10 results are exactly the shape of that service **with no
   session installed**: the store side (0x11) was never successfully
   exercised, so the read side (0x12) and the info commands (0x05/0x10)
   refuse (-1), the flag-mutating commands (0x07/0x09/0x0d/0x13/0x14/0x19)
   succeed but touch nothing observable, and the size query (0x00) reports
   a record it will not produce.
3. `sys_601_deep.md`'s HIGH/CRITICAL items (0x0c hardcoded auth, 0x12
   process write, signed-comparison ring-buffer underflow, 0x10 kernel page
   leak) are all either table-dependent, outside the verified body, or
   contradicted by retained instructions and live results. None should
   guide probe design; `docs/PROBE_INDEX.md` and
   `docs/ATTACK_SURFACE.md` already carry that correction.

## What would close the gap

- A 14.10 (or re-dumped 13.60) read of the 160 bytes at kernel base +
  `0x1a51160` would recover all 40 command targets; every command body in
  the `0xca0000`–`0xca4000` neighborhood is already in
  `kernel_text.bin`, so a table read alone would make the whole handler
  statically auditable. From the Lua loader this is unreachable (no kernel
  read primitive); it is a note for whoever next has kernel R/W.
- The helper identities (`0x2591d0` = copyout, `0x259280` = copyin per
  `tools/offline/kptr_hunt.py`; `0x259900` uiomove-class; `0xc08b50`
  malloc-class; `0xc08df0` free-class; `0x4c6a00`/`0x4c6fa0` lock-class)
  are inferred from call-site shape and cross-handler reuse, not from
  symbols — the capture carries no symbol table.
