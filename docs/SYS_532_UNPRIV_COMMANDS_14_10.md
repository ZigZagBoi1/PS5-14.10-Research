# sys 532 — what a game process can actually call

Firmware 14.10, measured 2026-11-09. Sys 532 is Sony's GPU/compute resource
manager: a command dispatcher with roughly seventy sub-operations behind
`priv_check(td, 0x2aa)`.

Every earlier 532 probe swept the command space with a null or scalar argument
and concluded the handler refuses a game process: `results/phase17_new_vectors/430a_sys532_copyout_20261022_234902.txt`
through `results/phase17_new_vectors/433a_sys532_handle_map_20261022_235907.txt`
report `0x800d0203` ("command not found in the registry table") for almost every
code, apart from `0x2F` (rv=0) and `0x18` (`0x800D0202`, null pointer).

The 13.60 body shows why that reading is wrong. At
`results/kernel_handlers/asm/sys_532_deep.asm:118-131` the entry calls
`priv_check(td, 0x2aa)` and, when that fails, lets a **fixed set of command codes
through anyway**:

```
af00f6  lea ecx,[r14-0x18]      ; cmd - 0x18
af00fa  cmp ecx,0x7
af00fd  jb  0xaf02a6            ; 0x18..0x1F  pass
af0103  cmp r14d,0x2f
af0107  je  0xaf02a6            ; 0x2F        pass
af010d  cmp r14d,0x20
af0111  je  0xaf02a6            ; 0x20        pass
af0117  jmp 0xaf1223            ; everything else
```

Every other command answers `0x800d0203`. So the reachable surface is exactly
`{0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x2F}` — ten codes, never
called with a real input struct before `1352a`.

## Argument shape

`results/kernel_handlers/asm/sys_532_deep.asm:29-48` reads a five-dword argument
array from `rsi`: `[rsi]` = command, `[rsi+8]` = sub-command, `[rsi+0x10]` = output
pointer, `[rsi+0x18]` = input pointer, `[rsi+0x20]` = size. In Lua that is
`532(cmd, sub, out_ptr, in_ptr, size, 0)`.

## Measured

`results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt`
(cmd + size sweep, zeroed input page), `results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt`
(field sweep) and `results/phase35_dead_end_reruns/1354a_sys532_write_dest_20261109_105712.txt`
(destination validation).

| cmd | rv | status in `out[0]` | effect |
|---|---|---|---|
| `0x18`, `0x19` | 0 | `0x800D0203` with `in[0]==0`, `0x800D0204` with `in[0]!=0` | registry lookup |
| `0x1A`-`0x1D` | 0 | `0x800D0203` up to size 0x800, `0x800D0204` at 0x818 | registry lookup |
| `0x1E` | 0 | `0` for an all-zero input, `3` for any input with a non-zero dword | input predicate |
| `0x1F` | -1 | untouched | refused |
| `0x20` | 0 | `0x800D0219` at size 0x30, `0x800D0208` at any other size | fixed 0x30 request, inner validation |
| `0x2F` | 0 | `0` | zero-fills `arg3` for `arg4` bytes |

Details worth keeping:

- `0x2F` follows the size argument exactly: 0x30 zeroed 12 dwords, 0x40 zeroed
  16, 0x100 zeroed 64. The destination is validated — an unmapped user address
  (`0x1000`) and a kernel image address (`0xFFFFFFFFC1000000`) both answer
  `0x800D0210` and leave the process alive. A null destination is accepted and
  does nothing.
- `0x1E` returns 3 for four different non-zero input patterns (all words equal to
  0x11223344, only `in[0]`, alternating words) and 0 for an all-zero page, so it
  is a very coarse predicate, not a count.
- `0x20`'s `0x800D0219` is stable across `in[0]`, `in[4]` and `in[8]` sweeps and
  across a prior `0x1E`+`0x2F` call, so it is not an uninitialised-state answer.
- `0x18`/`0x19` switch rejection code on the first input dword, which makes that
  dword a structural field (present/version flag) rather than a handle.

## What this does not give

No copy-out: in every successful call only `out[0]` changed, and `out[1..]` kept
the sentinel. `0x2F`'s fill is bounded by the entry size gate (`cmp rcx,0x801`
at `af02f4`, 0x819 for `0x1A`-`0x1D`) and predicated on a user destination, so it
is not a kernel write. The `0x18`-`0x1D` registry tables are outside every dumped
region (`0x18de230`, `0x18de34c`), so the command-to-handler mapping still cannot
be resolved offline.

## Captures

| probe | capture | result |
|---|---|---|
| 1352a | `results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt` | ten codes × five sizes, COMPLETE, alive pid=143 |
| 1353a | `results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt` | field sweeps, COMPLETE |
| 1354a | `results/phase35_dead_end_reruns/1354a_sys532_write_dest_20261109_105712.txt` | destination validation, COMPLETE |
