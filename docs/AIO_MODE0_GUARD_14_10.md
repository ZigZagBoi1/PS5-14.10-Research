# 663 refuses mode 0 with count > 1 on 14.10 - the public aio shape is patched

Measured 2026-11-05 (twentieth boot, pid 80) with probes 1219a, 1219b and 1221a. Statics from
`docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, offset == RVA).

## 1. The measurement

`663(ids, count, states, mode, timeout)` through the loader's ordinary syscall stub:

| count | mode | states array | errno |
|---|---|---|---|
| 1 | 0 | `0x80020003` | - |
| 2 | 0 | **untouched (0xAAAAAAAA)** | **22 EINVAL** |
| 3 | 0 | untouched | 22 |
| 0x80 | 0 | untouched | 22 |
| 2 | 1 | `0x80020003` twice | - |
| 0x80 | 1 | `0x80020003` twice | - |
| 2 | 2 | `0x80020003` twice | - |
| 2 | 3 | untouched | 22 |

The same EINVAL appears with `ids = NULL` (EINVAL, **not** EFAULT), with `timeout = NULL`, and with
real pending requests behind the ids. The status array is written by the cleanup loop, so the
count-2/mode-0 call returns **before the loop and before the id list is copied in**.

## 2. Why it is a guard and not a bounds accident

The 13.60 body of 663 (RVA `0x3b0210`, argument unpacker `0x3b01f0`) materialises EINVAL at exactly
two instructions:

```
3b0384  mov rcx, [rbx + 0x70]     ; count
3b0388  lea eax, [rcx - 0x81]
3b038e  cmp eax, 0xffffff7f
3b0393  ja 0x3b03b8               ; accepted for count 1..0x80
3b03a3  mov r14d, 0x16            ; <-- EINVAL, count bound

3b03b8  cmp r13d, 3               ; r13d = mode
3b03bc  jae 0x3b040e
3b041c  mov r14d, 0x16            ; <-- EINVAL, mode bound
```

Count 2 is inside the count bound and mode 1 / 2 pass the mode bound, which the table above
confirms by producing statuses. So a count-2 **mode-0** call reaching either bound is impossible in
the 13.60 code. The 14.10 handler must therefore contain an additional check of the form
`if (mode == 0 && count > 1) return EINVAL`, evaluated before the id copy-in.

That check is exactly the shape of the public Bagagwa / Relapse `aio_multi_wait` bug, whose entire
premise is that mode 0 with two or more entries links one waiter node onto every request, overwrites
`node->owner` each time, and then frees the array while requests 0..n-2 still point into it.

**Conclusion: the public aio kernel bug is patched on 14.10.** Modes 1 and 2 advance the node
pointer correctly (`r14 += 0x38` per pass at `0x3b0798`), so there is no aliasing to build on, and
mode 0 is refused for any batch.

## 3. What this changes in the repository

* The aio family stops being a kernel-R/W candidate on 14.10. This agrees with the upstream
  retraction of the "AIO double-free" record (`docs/AIO_BATCH_14_10.md`,
  `docs/RELAPSE_14_10.md`) and gives the mechanical reason: the entry point of the public shape
  returns EINVAL.
* `docs/SYSCALL_ARG4_R10_14_10.md` is retracted. Argument 4 was never the problem: the stock stub
  is `mov rax, <num> ; mov r10, rcx ; syscall ; ret` (upstream `docs/THREADING_ALIVE_14_10.md:130`,
  `docs/PROBE_INDEX.md` row 157a) and probe 1221a shows stock and `libkernel+0x3B7` returning
  byte-identical results for 379 prot and 663 mode calls.
* The 379 `mtypeprotect` returns recorded in `docs/ARG4_TRAMPOLINE_14_10.md` are valid as measured,
  but they are not new information about argument delivery: prot was always delivered. Prot 0x08
  gives EINVAL (the loose-table bit-3 reject at `0xabbdfc`), ordinary masks give EACCES /
  EOPNOTSUPP from `vm_map_protect` through a `kern_return_t` 0..9 table at RVA `0x18DBFB4`
  (outside every retained dump).

## 4. What is worth measuring next

1. `379` on a page-aligned **anonymous** mapping rather than a type-0x33 direct-memory mapping,
   sweeping prot around 0x200. The earlier EACCES is `KERN_PROTECTION_FAILURE`, i.e. a refusal to
   change *that* mapping, not a rejected value.
2. The upstream tree already contains `docs/AIO_BATCH_14_10.md`, `docs/AIO_FAMILY_13_60_DECODE.md`,
   `docs/AIO_OBJECT_FORENSICS.md`, `docs/RELAPSE_14_10.md` and `docs/research/relapse_variant_analysis.md`.
   Any new aio claim must be checked against those five first.
