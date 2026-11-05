# sys 591 `dynlib_dlsym` blocklist recovery + mode-flag decode — 13.60 capture

> **Date:** 2026-11-05. Source: `docs/dumps_13.60/kernel_text.bin` +
> `kernel_data.bin` (13.60 labeled capture; acquisition authenticity
> unresolved — see `docs/dumps_13.60/README.md`). All addresses are 13.60 RVAs
> from kernel base `0xffffffff8a9c0000`. This corrects and completes the 591
> section of `docs/OFFLINE_HANDLER_DECODE_2026-10-23.md`, which marked the
> 14-entry blocklist "outside both captured ranges". **The strings are in the
> capture** — the cited addresses were absolute VAs, not RVAs.
> 14.10 status: 591 was called live with real handles in PR #193 (probe
> 1300a section B, "0 kernel ptrs"); the blocklist contents themselves are a
> 13.60 static observation.

## The addressing error

`docs/OFFLINE_HANDLER_DECODE_2026-10-23.md` line 55 cites the blocklist
strings at `0x8bcf053e…0x8bd58f0e` and marks them unrecoverable. Those are
**absolute kernel VAs**. Subtracting the 13.60 kernel base
(`0xffffffff8a9c0000`) gives RVAs (`0x8bcf053e` → RVA `0x133053e`,
`0x8bd58f0e` → RVA `0x1398f0e`) that land inside `kernel_data.bin`
(RVA `0x1000000`–`0x1400000`). Rule of thumb before declaring anything
outside the capture: translate VA → RVA with the kernel base, then check
both `kernel_text.bin` (RVA < `0xe6e5c0`) and `kernel_data.bin`.

## Recovery method

The 591 handler body (`0x34ae90`–`0x34b510`) contains exactly 14 calls to a
bounded-`strncmp` helper (`0x8d1a30`, third arg always `0xa00`) comparing the
`copyinstr`'d user symbol name (at `[rbp-0xa30]`) against a string referenced
by `lea rsi, [rip+disp]`. Pairing each call with its preceding `lea rsi`
yields all 14 string RVAs in code order:

| # | string RVA | content | on match |
|---|---|---|---|
| 1 | `0x133053e` | `BaOKcng8g88` | r12d = 1, branch to resolve (0x34b275) |
| 2 | `0x131b9fb` | `KpDMrPHvt3Q` | r12d = 1, branch to resolve |
| 3 | `0x13799ab` | `module_start` | r12d = 0, branch to resolve |
| 4 | `0x12766a4` | `module_start_2` | r12d = 1 (kept), branch to resolve |
| 5 | `0x12dd45c` | `module_stop` | r12d = 1 (kept), branch to resolve |
| 6 | `0x131ba07` | `sceSysmodulePreloadModuleForLibkernel` | branch to resolve |
| 7 | `0x12d2d88` | `sceSysmoduleIsCameraPreloaded` | branch to resolve |
| 8 | `0x135ae55` | `__asan_malloc_replace` | branch to resolve |
| 9 | `0x136f660` | `__asan_new_replace` | branch to resolve |
| 10 | `0x136f673` | `__asan_malloc_replace_external` | branch to resolve |
| 11 | `0x1306556` | `__asan_new_replace_external` | branch to resolve |
| 12 | `0x129f2ea` | `__cfi_check` | branch to resolve |
| 13 | `0x1398ef0` | `__ubsan_handle_cfi_check_fail` | branch to **0x34b02f** (r12d = 0 first) |
| 14 | `0x1398f0e` | `__ubsan_handle_cfi_check_fail_abort` | r12d = 0, branch to resolve |

(The per-entry "on match" notes come from the `r12d` writes at
`0x34b095`/`0x34b0db`/`0x34b23a` and the branch targets; entries without an
explicit r12d write keep the current value. r12d is initialized to 1 at
`0x34b095` only in the fall-through path after entry 1 fails — see the
mode-flag section for the full state machine.)

The first two strings are the previously-unknown obfuscated names; their
base-minus arithmetic confirms they are exactly the `0x8bcf053e` and (near)
`0x8bd58f0e` the earlier decode cited.

## What the blocklist is

Not a security blocklist — a **mode-select allowlist**. Every match steers
the resolution into the special path at `0x34b275`; the categories are:

- sanitizer internals: `__asan_*` (4), `__cfi_check`, `__ubsan_handle_cfi_*`
  (2) — these must resolve to the kernel-side/runtime replacement symbols,
  so the resolver treats them specially;
- module lifecycle: `module_start`, `module_start_2`, `module_stop`;
- sysmodule internals: `sceSysmodulePreloadModuleForLibkernel`,
  `sceSysmoduleIsCameraPreloaded`;
- two obfuscated names whose role is unresolved (see below).

## Mode-flag (r12d) state machine

r12d is passed as the resolver's fourth argument (`r8d`) at
`0xb29ff0`, where it is immediately OR'd with `0xa` (`0xb2a01a`) — so it is a
flag word, and the blocklist only toggles one bit of it. The full flow:

1. Caller-module attribution: `0xa0bd50(td, 1, &retaddr_fn,
   &caller_module)`; failure or NULL caller → error 3 (`0x34af78`–`0x34af91`).
2. If `caller_module == [dynlib_obj+0x18]` (process primary module #1):
   enter the blocklist cascade with **r12d = 1** (`0x34b095`).
3. If `caller_module == [dynlib_obj+0x20]` (primary module #2): skip the
   cascade, go straight to resolve with **r12d = 0** (`0x34afa4`–`0x34afa8`).
4. Otherwise (`0x34afae`): `priv_check(0x10)` — if it passes AND
   `module+0x11d & 1` (hidden-module bit) is clear, run the injected-bundle
   allowlist helper `0x34b3c0` (below); if the requested name matches one of
   the 9 injected-bundle sprx paths, resolve with r12d unchanged (0), else
   error 3.
5. If `priv_check(0x10)` fails or the module is hidden: proc-lock, call
   `0x6096b0(proc)`; if that returns 0 and the proc dword at `+0x5d4` (read
   by `0xb27060`) is `>= 0x4000000`, check `caller_module+0x11d & 5` — clear
   means resolve with r12d = 0; set means error 3. All other paths land at
   `0x34b02f` → resolve with r12d = 0.
6. Blocklist cascade effects on r12d: entry 3 (`module_start`) clears it;
   entries 13/14 (`__ubsan_handle_cfi_*`) clear it; entries 1, 2, 4, 5 leave
   it set (entry 1 explicitly sets it before the test).

So the bit the blocklist controls is the difference between "resolve from
the process primary module with elevated lookup" (r12d=1) and "ordinary
lookup" (r12d=0), and the two obfuscated strings plus the lifecycle symbols
are the names that keep the elevated mode. The OR with `0xa` inside the
resolver means the caller-visible distinction is one additional bit on top
of flags `0xa`.

### The injected-bundle allowlist helper (`0x34b3c0`)

Iterates a 9-entry pointer table (text-tail RVA `0xe6b960`, absolute VAs)
of sprx path tails, formats each into a 0x80-byte buffer as either
`/%s/%s` (proc->p_dynlib+0xa38 prefix, when `[dynlib_obj+0x148] != 0`) or
`/system/%s`, and `strrchr`-matches the requested name's tail against the
formatted path. The 9 table entries:

```
common/lib/libSceWebBrowserInjectedBundle.sprx
common_ex/lib/libSceWebBrowserInjectedBundle.sprx
common/lib/libSceWebCdlgInjectedBundle.sprx
common_ex/lib/WebAppBundle.sprx
common/lib/libScePrecompiledShaders.sprx
common/lib/libSceRnpsInjectedBundle.sprx
common_ex/lib/libSceRnpsInjectedBundle.sprx
common_ex/lib/libSceNKWebCdlgInjectedBundle.sprx
common_ex/lib/libSceRnpsNKInjectedBundle.sprx
```

This is the browser/injected-bundle fast path: a WebKit-bundle caller with
the right privilege can dlsym inside these sprx modules by tail name.

## The two obfuscated names

`BaOKcng8g88` and `KpDMrPHvt3Q` are the only entries that set r12d=1
unconditionally on match. They are 11/12 chars, printable, and match no
known Sony or sanitizer symbol. Candidates: hashed/rotated known symbols,
per-build canary names, or sanitizer-adjacent internals. Nothing else in the
capture references them. **Unresolved** — flagged so a future 14.10 kernel
image or a string-search over a fuller 13.60 dump can settle them. Treating
them as a backdoor would be speculation; the r12d=1 they produce is the same
mode the primary-module caller already gets for free, so on the 13.60
evidence they are convenience aliases at most.

## 14.10 notes

- PR #193 (probe 1300a section B) called 591 with real handles on 14.10 and
  recorded "0 kernel ptrs" — no blocklist contents were observable from
  userland, so the strings above remain 13.60-only knowledge until a 14.10
  image exists.
- The syscall remains reachable and ungated on 14.10 (same `-1` for zeros as
  13.60's handle-0 error 3). A live probe resolving a known benign NID
  through 591 would confirm the path; probing the blocklist names themselves
  is **not** recommended — `__asan_*`/`__cfi_check` resolution could return
  sanitizer runtime addresses, and that is exactly the kind of result that
  must be re-confirmed under fresh ASLR before any claim.

## References

- `docs/OFFLINE_HANDLER_DECODE_2026-10-23.md` lines 48-57 — the original 591
  decode this doc corrects (stale absolute addresses)
- `docs/SYSCALL_CONTRACTS_13_60.md` line ~91 (591 row) — contract table
- PR #193 — 14.10 live call (1300a section B)
- `docs/SYS_608_DYNLIB_GET_INFO_EX_13_60.md` — sibling decode with the same
  VA→RVA capture-layout rules
