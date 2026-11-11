# Argument 4 is now under control, and it closes the aio route

Measured 2026-11-05 (twentieth boot, loader pid 80) with probes 1216b, 1218a, 1219a, 1219b,
1220a. Statics from `docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, offset == RVA).

## 1. The trampoline

`libkernel_base + 0x3B0` is a syscall stub whose `+7` byte is a real `mov r10, rcx`, so

```lua
native.fcall_with_rax(libkernel_base + 0x3B7, sysno, rdi, rsi, rdx, rcx, r8, r9)
```

delivers **argument 4** to any syscall. That is the first time in this project that r10 has been
under control.

### 1.1 How it was proved (and why the cheap test is not enough)

The first attempt (probe 1216b) called `663(ids={0}, count=1, out, mode=0, timeout=0)` through the
candidate and read `out[0]`. It returned `0x80020003`, the signature of the mode-0 id loop, which
looks like proof. It is not: a stale r10 that happens to be below 3 produces exactly the same
result. Probe 1217a then failed on the same stub with count 2, which is what exposed the ambiguity.

The decisive test is differential (probe 1218a):

| call | rcx | expected if rcx reaches r10 | expected if it does not |
|---|---|---|---|
| A | 0 (mode 0) | bound passes, id loop runs, `out[0] = 0x80020003` | stale r10 decides |
| B | 4 (mode 4) | bound rejects, `out[0]` untouched, errno 22 | stale r10 decides |

Measured on `libkernel_base + 0x3B7`: **A = 0x80020003, B = 0xAAAAAAAA untouched, errno 22.**
Two adjacent calls use the same chain, so a stale value cannot fake a mode change. The trampoline
is real.

## 2. The aio use-after-free is patched on 14.10

Probe 1219a and 1219b, all through the trampoline, ids either {0} or real pending reads:

| count | mode | result |
|---|---|---|
| 1 | 0 | `out[0] = 0x80020003` — the mode-0 path runs |
| 2 | 0 | **EINVAL 22, status untouched** |
| 3 | 0 | EINVAL, status untouched |
| 0x80 | 0 | EINVAL, status untouched |
| 2 | 1 | `0x80020003` for both entries |
| 2 | 2 | `0x80020003` for both entries |
| 0x80 | 1 | works |
| 2 | 3 | EINVAL (the ordinary mode bound) |

and the same EINVAL appears with `ids = NULL` (not EFAULT) and with `timeout = NULL`, so the
rejection happens **before the id list is touched** and does not depend on any object.

The 13.60 body produces EINVAL at exactly two instructions — the count bound `0x3b03a3` and the
mode bound `0x3b041c` — and count 2 passes the count bound, as the mode 1 and mode 2 rows prove.
So 14.10 has an additional check that 13.60 does not: **`mode == 0 && count > 1` is refused
outright.** That is precisely the shape of the Bagagwa / Relapse `aio_multi_wait` bug (one waiter
node linked onto every request, unlinked only from the last, then freed), so the bug is **patched**
on 14.10.

Consequences:

* the mode-0 dangling-node route is closed; modes 1 and 2 advance the node pointer correctly
  (`r14 += 0x38` per pass at `0x3b0798`), so there is no aliasing to exploit;
* every earlier "aio is a hard wall" observation in this corpus that was attributed to the
  privilege gate was at least partly this guard — 1211a's EINVAL for count 2 mode 0 is the guard,
  not a stale r10;
* any future aio work on 14.10 must start from modes 1/2, which do not alias.

This also removes the reason the previous three sessions were chasing the aio family as the primary
kernel primitive. The remaining value of argument 4 is elsewhere.

## 3. First real `mtypeprotect` sweep (syscall 379)

`379(va, len, id, prot)` with `id = 0x0A` on a `mmap`ped 0x8000 region at `0x310ADC000`
(type 0x33, i.e. the direct-memory mapping the corpus uses for heap work). `547(va, probe)` before
the sweep returned

```
rec = 0x10ADC000 0x00000003 0x10AE4000 0x00000003 0x00000033 0x00610020
```

i.e. start `0x310ADC000`, end `0x310AE4000`, prot 3, type 0x33, flags `0x00610020`.

| prot | errno |
|---|---|
| 0x00 | 45 EOPNOTSUPP |
| 0x01 | 45 |
| 0x02 .. 0x07 | 13 EACCES |
| 0x08 | 22 EINVAL (bit 3 is the loose-table reject at `0xabbdfc`) |
| 0x10 | 45 |
| 0x40 | 45 |
| 0x100 | 45 |
| 0x200 | 13 EACCES |
| 0x300 | **payload died** (binary output, LOADER-STUCK afterwards) |

Three things worth keeping:

1. `prot` now demonstrably reaches the kernel: the returns are prot-dependent, and the bit-3
   rejection matches the static table exactly. Before this, every 379 sweep was measuring a stale
   r10.
2. `0x200` is the plausible PS5 execute bit: the body computes
   `protbits = ((prot >> 1) & 0x141) | prot`, which maps bit 9 to bit 8 (FreeBSD's `PROT_EXEC` is
   0x4 and PS5's appears shifted), and 0x200 is the only value tested that is not rejected by the
   loose mask `test dl,8` and yet still fails later, inside `vm_map_protect`.
3. Changing the protection of a type-0x33 direct-memory mapping is dangerous: `prot = 0x300`
   killed the payload. A safer target is a plain anonymous mapping, and the next sweep must not
   touch device regions.

## 4. Next

1. Decode 379's return-code table (`lea rdx,[rip+0xe20173]` at `0xabbe3a`, then
   `mov eax,[rdx+rax*4]`, so a 0..9 code maps to an errno) from `kernel_data.bin`: it tells us
   whether EACCES means "wrong id", "wrong mtype" or "no privilege", and that decides whether 379
   can ever grant execute.
2. Re-run the prot sweep on an anonymous mapping instead of a device mapping, starting at
   `prot = 0x200` and never touching type 0x33 again.
3. Re-audit the other 4-argument handlers with a working argument 4. Probe 1213c's eboot work and
   the libc PLT map in `docs/SYSCALL_ARG4_R10_14_10.md` section 12 give the tooling; the ranking
   belongs to `docs/ARG4_RETEST_PLAN_14_10.md`.

### 3.1 What the 379 return codes mean

The body ends with

```
ABBE27  call 0x2cd3c0                 ; vm_map_protect
ABBE2C  mov ecx, eax
ABBE2E  mov eax, 0x16                 ; EINVAL by default
ABBE33  cmp ecx, 9
ABBE36  ja  0xabbe44                  ; code > 9 -> EINVAL
ABBE3A  lea rdx, [rip + 0xe20173]     ; RVA 0x18DBFB4 - outside every retained dump
ABBE41  mov eax, [rdx + rax*4]
```

so the call returns a **0..9 code** from `vm_map_protect` mapped through a table that was not
captured. A 0..9 code with this shape is FreeBSD's `kern_return_t`:

| code | name | likely errno |
|---|---|---|
| 0 | KERN_SUCCESS | 0 |
| 1 | KERN_INVALID_ADDRESS | EFAULT |
| 2 | KERN_PROTECTION_FAILURE | **EACCES 13** |
| 3 | KERN_NO_SPACE | ENOMEM |
| 4 | KERN_INVALID_ARGUMENT | EINVAL / EOPNOTSUPP |
| 5 | KERN_FAILURE | ? |
| 6 | KERN_RESOURCE_SHORTAGE | ENOMEM |
| 8 | KERN_NO_ACCESS | EPERM / EACCES |

Measured: prot 0x02..0x07 and 0x200 give 13, i.e. **KERN_PROTECTION_FAILURE**, not a parameter
error. The call is well formed; the VM layer refuses the change. For a type-0x33 direct-memory
mapping that is expected: it is device memory owned by another mtype, so 0x0A cannot re-protect it.
prot 0x00/0x01/0x10/0x40/0x100 giving 45 EOPNOTSUPP is consistent with code 4
(KERN_INVALID_ARGUMENT), i.e. an empty or meaningless protection mask.

The consequence for the next run is concrete: 0x200 is not being rejected as an illegal value, it
is being rejected as an illegal *change to that mapping*. The experiment has to be repeated on a
mapping this process owns outright - a page-aligned anonymous region - before any conclusion about
W^X can be drawn.
