# sys 656 `dynlib_get_info_for_libdbg` gate chain — 13.60 capture decode

> **Date:** 2026-11-05. Source: `docs/dumps_13.60/kernel_text.bin` +
> `kernel_data.bin` (13.60 labeled capture; acquisition authenticity
> unresolved — see `docs/dumps_13.60/README.md`). All addresses are 13.60 RVAs
> from kernel base `0xffffffff8a9c0000`. **14.10 status: gate holds.** PR
> #193's probe 1300a section D (capture
> `results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt`)
> called 656 with real arguments on 14.10 — `-1` for handles 0-5 even after
> `debug_init(1)` returned 0, zero kernel pointers — matching the gate model
> decoded below (retail unit → both predicates false → error 1).
> Earlier measurements: `-1` for six zeros
> (`docs/SYSENT_PRESENCE_14_10.md` line 650), and 247a/248a "refuses every
> layout tried (consistent with a debugger-credential gate)"
> (`docs/ATTACK_SURFACE.md` line 476) — that parenthetical was an inference;
> the actual gate is decoded below and it is **not** a credential check.

## Identity

| field | value |
|---|---|
| sysent thunk | `0x2655a0` |
| handler body | `0x34c350`–`0x34c670` (947 bytes) |
| narg | 2 |
| handler name string | `"sys_dynlib_get_info_for_libdbg"` (kernel_data RVA `0x13a3d13`) |
| copyout classifier | flagged by `tools/offline/kptr_hunt.py`: copyout from `[r14 + 0x10]` (set @ `0x34c3a1`) — one of the 17 OBJECT-sourced candidates |

The function at `0x34c670` immediately following is a **different syscall
(672, `dynlinker library list`)** whose error string is
`"sys_dynlib_get_list_for_libdbg"` (kernel_data RVA `0x1306572`). It shares
the same gate pair. The 13.60 name table's `659 dynlib_get_list2` label
belongs to a different body; do not conflate the two `_for_libdbg` handlers.

## Gate chain (the reason for this doc)

The handler's first action after loading args
(`656(id: u32, info: void*)`, `0x34c370`–`0x34c37b`) is:

```
0x34c382  call 0xacce10        ; gate1
0x34c387  test eax, eax
0x34c389  jne  0x34c398        ; gate1 != 0 -> PASS
0x34c38b  call 0xacce50        ; gate2
0x34c390  test eax, eax
0x34c392  je   0x34c5be        ; gate2 == 0 -> error 1
```

So the predicate is `gate1() != 0 || gate2() != 0`. Neither gate touches the
calling thread's credential — there is **no authid triple and no bit-62
test** in either gate or in the handler body. The "debugger-credential gate"
inference in `docs/ATTACK_SURFACE.md` is wrong for 13.60; the gate is a
unit/firmware class check.

### gate1 `0xacce10` — debug-class unit OR (unknown global)

```
if pred_5e2da0() != 0: return 1
if pred_5e2cc0() != 0: return 1
if pred_5e30c0() == 0: return 0
return (~dword[global_0x3cc1390]) & 1
```

### gate2 `0xacce50` — debug-class unit AND flag bit clear

```
if none of pred_5e2da0/5e2cc0/5e30c0: return 0
return (byte[global_0x3cc1390] & 4) == 0
```

(gate1 and gate2 read the same global dword at RVA `0x3cc1390`.)

### The three unit predicates

Each predicate: zero a 16-byte stack buffer, `memcpy` 16 bytes from a global
blob at kernel_data RVA `0x1a5c068`, and compare the u16 at offset +4:

| predicate | match word(s) at blob+4 |
|---|---|
| `0x5e2da0` | `0xA302` or `0x8202` |
| `0x5e2cc0` | `0x8102` or `0xA202` |
| `0x5e30c0` | `0xA902` |

The `0x02` low byte and the per-model high byte read as a hardware/product
class field (the `0xacce90` neighbour writes similar 16-byte blobs with ASCII
content). **Caveat:** kernel_data RVA `0x1a5c068` and the gate-result global
RVA `0x3cc1390` are both **zero-filled / outside the captured kernel_data
region**, so the blob contents and the retail-vs-debug outcome cannot be
confirmed from this capture. The low-byte-`0x02` pattern across five model
values is consistent with "compare against the running unit's product code,"
where the running unit's own 16-byte descriptor would make exactly one
predicate true — that reading is inferred, not proven.

### Cross-check with the 14.10 gate inventory

`docs/OFFLINE_HANDLER_DECODE_2026-10-23.md` lines 33-34 already listed
`0xacce10`/`0xacce50` as "model/boot predicates ... used by 656, 623" and
called them "debug-capable unit predicates, not authid checks". This doc adds
the exact decode: which three predicates, which comparison words, which
global bits, and the OR/AND structure of the two gates.

### Who else uses these gates

Raw-text xref scan (direct `call` sites): gate1 has 30+ callers
(`0x293213`, `0x336415`, `0x34a7d0`, `0x34c382` (656), `0x34c68b` (672),
`0x4c0352`, `0x4e59e0`, `0x540d64`, `0x644517`, `0x66dd83`, …), gate2 a
similar set (`0x34c38b` (656), `0x34c694` (672), `0x4c0349`, …). This is a
kernel-wide "is this a debug-capable unit" facility, not a 656-specific
check. On a retail 14.10 console the expected outcome is both predicates
false → both gates take their early-out → **656 returns error 1**, which is
what the 14.10 measurements already show.

## Post-gate contract (reachable only when the gate passes)

1. Same entry gate as 593/608/660: `[proc+0x3e8]` non-NULL and
   `[[r15+0x10]+0x148]` non-NULL, else printf
   `"this is not dynamic linked program.\n"` and error 1
   (`0x34c398`–`0x34c5b7`).
2. `copyin(info, &size, 8)`; require `size == 0x160` exactly, else errno
   `0xe`/`0x16` (`0x34c3ca`–`0x34c3f7`).
3. `malloc(0x160)`, zero it, echo the size qword at `out+0` — **unlike 593,
   which does not echo the size** (`0x34c44f`–`0x34c453`).
4. Walk the process module list for `[module+0x28] == id` under the dynlib
   lock (`0x34c430`–`0x34c440`); no match → error 3.
5. Fill: module path basename at `out+8..0x107` with the same `/host/` → `\`
   separator translation as 593/608 (`0x34c456`–`0x34c4cb`).
6. Segment table: up to 4 records of **0x10 bytes each** at `out+0x108` —
   `{u64 vaddr (seg+8), u32 size (seg+0x10), u32 prot}` where prot is decoded
   from `seg+0`→`+0xc` bits 0/1/2 → out bits 0/1/2 — segment count at
   `out+0x148` (`0x34c4de`–`0x34c598`). Note the record stride is 0x10, not
   593's 0x18 legacy layout and not 608's `proc+0xc81` new-style walk.
7. NID/fingerprint block: `memcpy(out+0x14c, module+0x150, 0x14)`
   (`0xb2b740`, called at `0x34c613`).

### Kernel-pointer assessment

The kptr_hunt flag is for the copyout *site* (`[r14+0x10]` feeds the staging
buffer's provenance chain), but every byte placed in the staging buffer comes
from the same module-record fields 593 already exposes: userland VAs, sizes,
prot bits, and the 0x14-byte NID block. There is **no kernel-VA source** in
the fill path. If the gate passed on 14.10, 656 would leak the same class of
userland module layout as 593 — with the segment table in a denser 0x10-stride
format. The 13.40 community cross-check (issue #170, `docs/DEAD_ENDS.md` line
183) independently reports 656 "denied or wrote no pointer-shaped output."

## Probe status — settled on 14.10

PR #193's probe 1300a section D (2026-11-05) ran the discriminating shape:
`debug_init(1)` first (ret 0 — 560's known no-capability success), then 656
with handles 0-5. Every call returned `-1`; zero kernel pointers. Combined
with the six-zeros sweep and 247a's layout sweep, the gate question is
answered on retail 14.10: the debug-unit predicates are false and 656 never
reaches its body. The one thing no probe captured is the errno value — under
this decode it should be 1 (gate failure), and a capture showing errno 3
would instead mean the gate passed and only the handle lookup failed, which
would contradict the model. That distinction is the only remaining value a
re-run could add, and it is diagnostic only.

## References

- PR #193 — 14.10 live confirmation (probe 1300a section D, capture
  `results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt`)
- `docs/OFFLINE_HANDLER_DECODE_2026-10-23.md` lines 33-34, 102-112 — gate
  inventory entry and the original 656 summary this doc expands
- `docs/SYSCALL_CONTRACTS_13_60.md` line 141 — contract table row
- `docs/SYS_608_DYNLIB_GET_INFO_EX_13_60.md` — sibling handler decode
  (2026-11-05) with the shared 593-family machinery
- `docs/DEAD_ENDS.md` line 183 — 13.40 community cross-check (issue #170)
- `results/kernel_handlers/analysis/sys_656.md` — prior Ghidra-carrier
  analysis (thunk-only; body analysis here supersedes it)
