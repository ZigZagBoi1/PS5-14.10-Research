# sys 608 `dynlib_get_info_ex` contract — 13.60 capture decode

> **Date:** 2026-11-05. Source: `docs/dumps_13.60/kernel_text.bin` (13.60
> labeled capture; acquisition authenticity unresolved — see
> `docs/dumps_13.60/README.md`). Every address is a 13.60 RVA from kernel base
> `0xffffffff8a9c0000`. **Nothing here is 14.10 evidence**; 14.10 behavior
> must be measured live. On 14.10 the only 608 measurement is `-1` for six
> zero arguments (`docs/SYSENT_PRESENCE_14_10.md` line 602) — an untested
> contract, not a verdict.

## Identity

| field | value |
|---|---|
| sysent thunk | `0x265598` |
| handler body | `0x34bdc0`–`0x34c350` (estimated 1219 bytes) |
| narg | 3 |
| handler name string | `"sys_dynlib_get_info_ex"` (kernel_data RVA `0x128a674`) |
| six-zeros errno | `1` — the handler takes the early `[proc+0x3e8]==NULL` bailout, which `printf`s `"this is not dynamic linked program.\n"` (kernel_data RVA `0x135ae30`) and returns error 1 |

Body-layout correction already on record (`docs/HANDLER_CLAIM_CORRECTIONS.md`
§1a): 593's body is `0x34b7b0`–`0x34bc60`, 660's is `0x34bc60`–`0x34bdc0`,
608's is `0x34bdc0`–`0x34c350`. The "593 priv_check at 0x7dd/0x895" offsets
cited in `docs/VERIFIED_HANDLER_ANALYSIS.md` are 608-relative-to-593 linear
run-over; the instruction-level evidence for the `dynlib_get_info_ex` struct
map exists in 608's body only.

## Argument contract

`608(handle: u32, flags: u32, user_info: u64*)`

The handler reads `args[0]` low dword (handle), `args[1]` low dword (flags,
cached at `0x34be06`/`0x34be19`), and `args[2]` as a user pointer
(`0x34be0c`). It then:

1. `copyin(user_info, &size, 8)` at `0x34be33` — a **size prefix**, same as
   593/660. Failure → errno `0xe` (EFAULT).
2. Requires `size == 0x1a8` exactly (`0x34be4a`–`0x34be57`), else errno
   `0x16` (EINVAL). 593/660 require `0x160`; 608's larger struct is the
   difference the "_ex" name implies.
3. Allocates a `0x1a8`-byte kernel buffer (`malloc(0x1a8, M_DYNLIB?, 0xa)` at
   `0x34be5d`), zeroes it, fills it from the module record, `copyout`s all
   `0x1a8` bytes to `user_info` (`0x34c255`), frees, returns 0.

Entry gate (shared with 593/660): `[td+8] = proc`, `r15 = [proc+0x3e8]` must
be non-NULL (process dynlib object), and `[[r15+0x10]+0x148]` must be
non-NULL (`0x34bde0`–`0x34be00`). This is a "process is dynamically linked"
check, **not** a credential check. There is no authid-triple gate and no
bit-62 gate anywhere in the body; the only privilege tests are the two
`priv_check`-style calls described below.

Module lookup: the handler walks the process module list `[r15]` matching
`[module+0x28] == handle` (`0x34be90`–`0x34bea0`) under the dynlib list lock
(`0xc4bb20`/`0xc4c4b0` around `r15+0x70`). No match → unlock, free,
errno `3` (`0x34c0cf`–`0x34c0f3`).

## Output struct map (0x1a8 bytes at user_info)

Filled from the matched module record (`r15` below). `priv_check(N)` is the
call `0xb2bb00` with `edi = N`: it tests `[dynlib_obj+0x140] & N` on the
current process — a per-process flag word, not a credential comparison.

| out offset | source | gate |
|---|---|---|
| +0x000 | `size` (echoes 0x1a8 — set by copyin consumer; not written by handler body) | — |
| +0x008..+0x106 | module path basename, 0x100 bytes | unconditional: picks `/` or `\` separator (the `/host/` prefix check at `0x34becb`–`0x34befd` switches separator to `0x5c`), `strrchr` (`0x272200`), `strlcpy`-style copy (`0x984440`) into `out+8` (`0x34bf04`–`0x34bf2c`) |
| +0x107 | NUL terminator | unconditional |
| +0x108 | `module+0x28` (handle/id echo) | unconditional (`0x34bf37`) |
| +0x10c | `movzx(module+0x70)` (u16) | unconditional (`0x34bf42`) |
| +0x10c | OR'd with bitfield from `module+0x11c` | **flags bit 0 set** (`0x34bf4e`): `bextr(module+0x11c, 0x108)` + `(module+0x11c & 1)*2`, shifted `<<16`, OR into +0x10c (`0x34bf54`–`0x34bf71`) |
| +0x008.. | name field re-zeroed (`memset(out+8, 0, 0x100)`) | **flags bit 1 set** AND `module+0x11d & 1` clear AND `priv_check(2) != 1` (`0x34bf78`–`0x34bfa4`). This is the "name is hidden from unprivileged callers" gate claim 1 cites as `0x7dd` |
| +0x110 | `module+0x78` (mapbase) | **unconditional** (`0x34bfa4`–`0x34bfad`) |
| +0x118 | `module+0x80` (text_size) | **unconditional** (`0x34bfb4`) |
| +0x11c | `module+0x88` | **unconditional** (`0x34bfc2`) |
| +0x120 | `module+0x90` | **unconditional** (`0x34bfd0`) |
| +0x124 | `module+0x98` | **unconditional** (`0x34bfde`) |
| +0x128, +0x130 | TLS: `module+0xe8` (tls_init), `module+0xf0` (tls_size) | only when `priv_check(2) == 0` AND `module+0x11d & 0x10` clear (`0x34c0f5`–`0x34c114`); otherwise both zeroed |
| +0x138, +0x140 | zeroed | unconditional (`0x34bfec`–`0x34bff7`) |
| +0x148 | `module+0xf8` (init_proc) | **unconditional** (`0x34c002`) |
| +0x150 | `module+0x108` (fini_proc) | **unconditional** (`0x34c010`) |
| +0x158 | `module+0x100` (eh_frame_hdr) | **unconditional** (`0x34c01e`) |
| +0x15c | `module+0x110` | **unconditional** (`0x34c02c`) |
| +0x1a4 | `module+0x20` | **unconditional** (`0x34c03a`) |
| +0x128..+0x1a0 variant A | if `priv_check(2) != 0`: zero +0x128/+0x130/+0x1a0, memset `out+0x160` 0x40 bytes (`0x34c052`–`0x34c087`) | privileged-false path |
| +0x160..+0x19f variant B1 | if `proc+0xc81 != 0`: up to 4 segment records, 0x18 bytes each (src `module+0x40` array): +0x00 = `seg+8` (vaddr), +0x08 = `seg+0x10` (size), +0x0c = permission bits decoded from `seg+0`→`+0xc` bits 0/1/2 → out bits 0/1/2 (`0x34c12a`–`0x34c1c9`); count → +0x1a0 | process byte `+0xc81` set (the same process flag that gates sys 676 per `CLAUDE.md`) |
| +0x160..+0x19f variant B2 | if `proc+0xc81 == 0`: two legacy records — text from `[module+0x50]`: vaddr `[+8]`, size `[+0x10]`, prot 5; data from `[module+0x60]`: vaddr `[+8]`, size `[+0x10]`, prot 3; count 2 → +0x1a0 (`0x34c1d2`–`0x34c222`) | default for a normal game process |

Difference from 593/660: 593's fill routine (`0x34b950`) is gated on
`priv_check(1) == 0` for the whole fixed region and produces a 0x160-byte
struct whose segment records are legacy-only (`module+0x50`/`+0x60`, and
`+0x58` when `module+0x48 == 3`); 660 passes `mode = 0` to the same routine
and returns early; 608 carries the extended map above with the `proc+0xc81`
new-style segment walk and the always-unconditional `+0x110..+0x15c` fields.

## Kernel-pointer assessment

The unconditional fields (`+0x110` mapbase, `+0x148` init, `+0x150` fini,
`+0x158` eh_frame_hdr, `+0x15c`, `+0x1a4`) are **module-relative** values —
userland VAs or offsets, same class as 593's existing output (39 userland
module bases, `CLAUDE.md` "userland module-base discovery"). The kptr_hunt
classifier (`tools/offline/kptr_hunt.py`) does **not** flag 608: its copyout
source is the `malloc`'d staging buffer, and the bytes placed in it come from
the module record fields enumerated above, none of which is a kernel VA. The
segment-record sources (`module+0x40` array entries) are userland vaddr/size
pairs. Expect 608 on 14.10, if reachable, to leak **userland** module layout
only — the same verdict 593/660 already have.

## Proposed 14.10 probe (discriminating, console required)

Goal: establish whether 14.10 keeps this contract, and harvest the extended
fields 593 does not return (TLS init/size at +0x128/+0x130, `+0x15c`,
`+0x1a4`, and the new-style segment records if any process flag permits).
Modeled on the 593 calling pattern in
`probes/phase7_heap_exploitation/` and the 247a lesson that the struct must
be zeroed except the size prefix.

```lua
-- CRASH_CLASS: LOW
-- PROBE: sys 608 dynlib_get_info_ex real-argument contract test
local sc608 = make_syscall(608)
local info = memory.alloc(0x200)
-- zero the whole buffer, then set the size prefix only (247a lesson:
-- canary-filled structs make 593 fail; zeroed with size at +0 works)
for i = 0, 0x1ff, 4 do safe_wd(info + i, 0) end
safe_wq(info, uint64(0x1a8))
for handle = 0, 60 do
    local ret = to_num(sc608(uint64(handle), uint64(0), uint64(info)))
    if ret == 0 then
        print(string.format("608 handle=%d OK name=%s", handle,
            memory.read_buffer(info + 8, 64)))
        for off = 0, 0x1a7, 8 do
            local q = safe_rq(info + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("  KPTR? +0x%x = %08x_%08x", off, h, l))
                end
            end
        end
    else
        print(string.format("608 handle=%d ret=%d", handle, ret))
    end
    for i = 0, 0x1ff, 4 do safe_wd(info + i, 0) end
    safe_wq(info, uint64(0x1a8))
end
-- variants worth one pass each: flags=1 (bit0: +0x10c bitfield),
-- flags=2 (bit1: name-hiding gate check), flags=3
```

Expected results under this contract:

- `ret == 0` for the same handle range 593 answers (0..~38), name at `+0x008`,
  and identical values at `+0x110`/`+0x118` to what 593 returns in its own
  layout — confirms 14.10 kept the handler.
- `ret == -1` with errno distinguishable via the loader's errno path:
  `1` = process gate (should not happen for the game process), `3` = handle
  not found (bounds the valid handle range), `0x16` = size-prefix mismatch
  (means 14.10 changed the struct size — retry with other sizes), `0xe` =
  copyin fault (arg layout changed).
- Any `KPTR?` line would be a kernel-pointer leak and must be re-confirmed
  against a second fresh-ASLR run before being claimed; per repo rule,
  `0xFFFFFFFF_xxxxxxxx` values are sentinels, not pointers.

## References

- `docs/HANDLER_CLAIM_CORRECTIONS.md` §1a — body-range attribution (593/660/608)
- `docs/VERIFIED_HANDLER_ANALYSIS.md` §1 — the struct map (corrected to 608)
- `docs/OFFLINE_HANDLER_DECODE_2026-10-23.md` — error-code convention
  (positive SCE code from body → userland `-1`/errno at dispatch)
- `docs/SYSENT_PRESENCE_14_10.md` line 602 — 14.10 six-zeros status
- `docs/ATTACK_SURFACE.md` line 476 — dynlib family canary lesson (247a/248a)
