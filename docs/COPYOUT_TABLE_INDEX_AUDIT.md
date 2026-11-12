# Copy-out table-index audit: global tables, scaled indices, and the userland copy

**Class:** out-of-bounds table reads copied to userland.
**Corpus:** `results/kernel_handlers/` (13.60 bodies; image base `0xffffffff8a000000`, RVA = VA - base).
**Reachability:** `docs/SYSENT_PRESENCE_14_10.md` (measured on 14.10).
**Status of every statement below:** STATIC unless explicitly marked INFERRED. No live measurement was performed for this note.

## 中文摘要

1. 全库只有 19 个 asm 文件 / 27 个 decompiled 文件引用 copy 助手 `0xffffffff8ac191d0`，不是 `docs/TZ_TABLE_638_14_10.md` 所说的 62 个（该文档列出的 674/659/649/656/652/662/664/663/650/651 十个文件里该地址出现次数为 **0**）。
2. 42 个字节级调用点中，copy 源全部是栈帧或调用者数组；唯一「全局表 + 缩放索引 + copyout」的形状是时区表 `0xffffffff8e2d5920`，被 638（读）、639（读，反向）、636（写）共用。
3. 该表的索引有严格上界，且上界与被写侧 636 的 `1..512` 门禁共同构成结构不变量：count 全局量恰好位于 `table + 0x2000`，即 512 条记录之后，所以 count <= 512 与「表窗口 0x2000」是同一件事。
4. **可证实的越界读：0 例。** 638/639 在 14.10 上 present 且六零参数返回 0（无凭据门禁），但索引被二元搜索不变量锁在 `[0, count-1]`。
5. 唯一接近「索引来自表内容、循环上界来自另一张表的 count」这一子模式的是 618/620/624/628/637/642 共用的函数体，但它把索引打进的**是调用者自己的数组**，不是内核表。

---

## 0. Verdict

| item | count |
|---|---|
| asm files containing a byte-level `call ffffffff8ac191d0` | 19 |
| decompiled files naming `func_0xffffffff8ac191d0` | 27 |
| byte-level call sites in those 19 files | 59 occurrences, 42 distinct call sites |
| distinct functions containing a copy site | 8 |
| functions with a **global table + scaled index** reaching the copy | 2 (638 body, 639 body) — same table |
| provable out-of-bounds table reads reaching userland | **0** |
| present on 14.10 among the in-class slots | 638 `0`, 639 `0`, 636 `-1` (EPERM) — all present |

The class is a clean negative. The single in-class shape is the timezone table, and it is bounded by construction rather than by luck: the count global sits exactly `512 * 0x10 = 0x2000` bytes after the table base, so the table window and the count cannot disagree, and the only writer of the count (636) accepts `1..512` only.

## 1. Corpus count: the `62 handlers` figure does not reproduce

`docs/TZ_TABLE_638_14_10.md` closes with a top-10 list of handlers to audit and the sentence `... 52 more, 1-18 calls each`, i.e. 62 handlers. Measured on this corpus, that list is empty:

| file named by the TZ doc | claimed calls | `8ac191d0` hits | `8ac19280` hits | `8ac190b0` hits | file size |
|---|---|---|---|---|---|
| `sys_674.asm` | 26 | **0** | 0 | 0 | 621 KB |
| `sys_659.asm` | 22 | **0** | 0 | 0 | 628 KB |
| `sys_649.asm` | 21 | **0** | 0 | 0 | 623 KB |
| `sys_656.asm` | 21 | **0** | 0 | 0 | 625 KB |
| `sys_652.asm` | 20 | **0** | 0 | 0 | 1808 KB |
| `sys_662.asm` | 20 | **0** | 0 | 0 | 982 KB |
| `sys_664.asm` | 20 | **0** | 0 | 0 | 982 KB |
| `sys_663.asm` | 20 | **0** | 0 | 0 | 982 KB |
| `sys_650.asm` | 18 | **0** | 0 | 0 | 1806 KB |
| `sys_651.asm` | 18 | **0** | 0 | 0 | 1806 KB |

Reproduce: `grep -c 8ac191d0 results/kernel_handlers/asm/*.asm` returns non-zero for exactly 19 files. Consequence for planning: the sweep the TZ doc asks for is already complete in this note; the remaining 43 files of the `62` do not exist in this corpus and auditing them by name would read 636 KB - 1.85 MB of unrelated bodies for nothing. (One real artefact remains: `sys_674.asm:8167` carries the comment `copyout_candidate RVA 0x2591d0`, which is why the address looks present to a substring search that also matches RVA notation.)

## 2. Method

### 2.1 Detector

PART 3 of each asm dump is the byte-annotated disassembly (`ADDR:\tBYTES\tmnemonic`). Parse it, split by `ffffffffXXXXXXXX <label>:` boundaries, keep functions containing a call to `8ac191d0`, and list memory operands matching `(%rXX,%rYY,(1|2|4|8))` (the only encoding that can express `table + index*stride` in one instruction). Result: the scaled-index operand exists inside a copyout function **only** in `sys_636.asm` / `sys_638.asm` / `sys_639.asm`, and only in the two timezone bodies.

A second pass covered the case the first pass cannot see: a table base loaded with `lea table(%rip),%reg` and then advanced by `add $stride,%reg` in a loop (no scaled-index operand). Every RIP-relative `lea`/`mov` global inside a copyout function was resolved and traced to the `rdi` argument of the copy. Non-table globals found: `0xffffffff8e2dc310` (per-CPU stack canary, read into the frame canary slot, never copied), `0xffffffff8dede038/8dede060` (list heads in the 618 body), `0xffffffff8d248d60` and `0xffffffff8bd0f297` (log format strings passed to `0xffffffff8b5da3e0`, the audit call the brief says to ignore), `0xffffffff8c0e35bc` (a 6-entry jump table, see F6). No table base is formed by pointer arithmetic into a copy site.

### 2.2 Helper semantics, and why the direction is INFERRED

The helper body is **not** in the corpus: `grep -n '^ffffffff8ac191d0 <' results/kernel_handlers/asm/*.asm` returns 0 hits. Direction (rdi = kernel source, rsi = user destination, rdx = length) is inferred from the call sites, and it is direction-consistent at all 42:

- sources are kernel stack frames (`lea -0x38(%rbp),%rdi` at `ffffffff8b07e75b`, `lea -0x98(%rbp),%rdi` at `ffffffff8b47e0a9`, `lea -0x68(%rbp),%rdi` at `ffffffff8ae630ae`), which no `copyin` would accept;
- destinations are values loaded from the syscall argument block (`mov 0x10(%rbx),%r14` at `ffffffff8b07e770`, `mov 0x18(%rbx),%rbx` at `ffffffff8b07e7a5`), and the helper's return value is returned to userland as the syscall errno (`test %eax,%eax; jne` straight into the epilogue at `ffffffff8b07e7d6`);
- one site copies a kernel stack record **to** `uap->r[2] + idx*0x68` (`ffffffff8b47e0b3`), which only makes sense as kernel -> user.

### 2.3 What counts as `table-index pattern`

A finding is in class only if all three hold: (a) the copy source is a RIP-relative global base plus a register scaled by the element size; (b) the index is derived from user input, a global count, or a field of a user structure; (c) the copy length is constant or derived and the resulting address can leave the table window. Condition (a) is what separates a table read from the 40 stack-frame copies.

## 3. Findings

### F1 — syscall 638 `utc_to_localtime`: the only in-class table read, bound is a loop invariant, not a compare

Presence: `| 638 | `utc_to_localtime` | `0` | present |` (`docs/SYSENT_PRESENCE_14_10.md`). Body `ffffffff8b07e5c0`, quoted from `results/kernel_handlers/asm/sys_636.asm` PART 3 (the 638 body is in the 636 window too).

Globals resolved:

```
3255| ffffffff8b07e5d4: 48 8d 3d 25 73 25 03  lea 0x3257325(%rip),%rdi   # ffffffff8e2d5900   (lock)
3263| ffffffff8b07e5f0: 8b 05 2a 93 25 03     mov 0x325932a(%rip),%eax   # ffffffff8e2d7920   (count, int32)
3267| ffffffff8b07e603: 48 8d 0d 16 73 25 03  lea 0x3257316(%rip),%rcx   # ffffffff8e2d5920   (record table, stride 0x10)
```

Index formation and the access that has no adjacent check:

```
3264| ffffffff8b07e5f6: 85 c0                 test %eax,%eax
3265| ffffffff8b07e5f8: 0f 84 b6 00 00 00     je   ffffffff8b07e6b4        ; count == 0 -> unlock, return 0x22
3266| ffffffff8b07e5fe: ba 01 00 00 00        mov  $0x1,%edx              ; lo = 1
3268| ffffffff8b07e60a: 83 f8 02              cmp  $0x2,%eax
3269| ffffffff8b07e60d: 7c 40                 jl   ffffffff8b07e64f        ; count < 2 -> use index 0
3279| ffffffff8b07e62a: 44 8d 0c 17           lea  (%rdi,%rdx,1),%r9d
3281| ffffffff8b07e631: 41 c1 e8 1f           shr  $0x1f,%r8d
3283| ffffffff8b07e638: 41 d1 f8              sar  $1,%r8d                ; mid = (hi+lo)/2 signed
3285| ffffffff8b07e63e: 49 c1 e1 04           shl  $0x4,%r9               ; index * 0x10
3286| ffffffff8b07e642: 49 39 34 09           cmp  %rsi,(%r9,%rcx,1)      ; key compare
3291| ffffffff8b07e64f: 48 63 f2              movslq %edx,%rsi
3293| ffffffff8b07e659: 48 c1 e6 04           shl  $0x4,%rsi
3295| ffffffff8b07e664: 48 8b 7c 0e f0        mov  -0x10(%rsi,%rcx,1),%rdi ; table[(edx-1)].key
3296| ffffffff8b07e669: 48 8b 74 0e f8        mov  -0x8(%rsi,%rcx,1),%rsi  ; table[(edx-1)].{offset,correction}
```

What controls the index: the caller's `input` (`(%rbx)`, read at `ffffffff8b07e60f`) only selects *which* record the search lands on; the index value itself is `edx-1` where `edx` is the binary-search insertion point.

Bound and why it is sufficient: the access at `ffffffff8b07e664` has **no adjacent `cmp`** against the count. It is safe because `edx` is an invariant of the search loop:

- `edx` is initialised to 1 at `ffffffff8b07e5fe` and re-initialised to 1 at `ffffffff8b07e612`;
- `edx` is only ever raised to `mid+1` (`inc %r8d` at `ffffffff8b07e620`, `mov %r8d,%edx` at `ffffffff8b07e623`), and `mid < hi <= count`;
- the loop exits at `ffffffff8b07e626: 39 fa cmp %edi,%edx` / `7d 25 jge` only when `edx >= hi`, so on every exit `1 <= edx <= count`;
- therefore the effective address is `table + (edx-1)*16` with `0 <= edx-1 <= count-1`, i.e. at most `table + (count-1)*16 + 8`.

Table window and the count, as one structure: the count global is at `0xffffffff8e2d7920 = 0xffffffff8e2d5920 + 0x2000`, and `0x2000 / 0x10 = 512` records. The window is therefore *defined* by the count's address. A read past the last used slot can still be inside the window (the TZ doc records 258 used of 512), but a read past `table + 0x1ffe` would land on the count itself, and that requires `count > 512`.

The `count <= 512` invariant is enforced by the write side, see F3.

Copy length vs stride: three constant copies, `8`, `0x10`, `4`, into the caller's `uap->r[2]`, `uap->r[3]`, `uap->r[4]` (`mov 0x10(%rbx),%r14`, `mov 0x18(%rbx),%rbx`), each skipped when the destination pointer is null, each failure returned immediately:

```
3367| ffffffff8b07e75b: 48 8d 7d c8  lea  -0x38(%rbp),%rdi     ; value = input + offset + correction
3368| ffffffff8b07e75f: ba 08 00 00 00  mov $0x8,%edx
3370| ffffffff8b07e767: e8 64 aa b9 ff  call ffffffff8ac191d0
3381| ffffffff8b07e790: 48 8d 7d d0  lea  -0x30(%rbp),%rdi     ; the 16-byte record {key,offset,correction}
3382| ffffffff8b07e794: ba 10 00 00 00  mov $0x10,%edx
3384| ffffffff8b07e79c: e8 2f aa b9 ff  call ffffffff8ac191d0
3395| ffffffff8b07e7c5: 48 8d 7d c4  lea  -0x3c(%rbp),%rdi     ; nearest non-zero correction
3396| ffffffff8b07e7c9: ba 04 00 00 00  mov $0x4,%edx
3398| ffffffff8b07e7d1: e8 fa a9 b9 ff  call ffffffff8ac191d0
```

The 0x10-byte copy length equals the 0x10-byte stride, and the record slots it reads are the same `table[(edx-1)]` pair stored at `ffffffff8b07e66e`/`ffffffff8b07e672`; stride and length agree. The 4-byte copy reads `record+0xc` (`mov 0xc(%r9,%rcx,1),%r9d` at `ffffffff8b07e698`, and `mov 0xc(%r8,%rcx,1),%r8d` at `ffffffff8b07e6eb`), which is the `correction` dword of a 16-byte record, so length and field agree too.

Worst case: 16 bytes of `.data` per call, at an index the caller can steer to any of the records by choosing `input`, from a window that is public timezone data. No OOB. **STATIC** for all bounds; the table contents and the 258-of-512 occupancy are the TZ doc's measurement, not re-derived here.

### F2 — syscall 639 `localtime_to_utc`: three indices, three separate bounds, all inside the same window

Presence: `| 639 | `localtime_to_utc` | `0` | present |`. Body `ffffffff8b07e800`, quoted from `results/kernel_handlers/asm/sys_639.asm`.

Same table, same count, same lock, plus the mode global:

```
3363| ffffffff8b07e814: 48 8d 3d e5 70 25 03  lea 0x32570e5(%rip),%rdi  # ffffffff8e2d5900  (lock)
3372| ffffffff8b07e837: 8b 05 e3 90 25 03     mov 0x32590e3(%rip),%eax  # ffffffff8e2d7920  (count)
3373| ffffffff8b07e83d: 85 c0                 test %eax,%eax
3374| ffffffff8b07e83f: 0f 84 1c 01 00 00     je   ffffffff8b07e961       ; count == 0 -> unlock, return 0x22
3376| ffffffff8b07e84b: b9 01 00 00 00        mov  $0x1,%ecx             ; lo = 1, on both entry paths
3381| ffffffff8b07e85d: 48 8d 3d bc 70 25 03  lea 0x32570bc(%rip),%rdi  # ffffffff8e2d5920  (table)
3382| ffffffff8b07e864: 41 89 c0              mov  %eax,%r8d             ; hi = count
3387| ffffffff8b07e876: 44 39 c1              cmp  %r8d,%ecx
3388| ffffffff8b07e879: 7d 51                 jge  ffffffff8b07e8cc
```

Index 1 — the selected record, `edx = ecx-1`:

```
3413| ffffffff8b07e8cc: 8d 51 ff              lea  -0x1(%rcx),%edx       ; 1 <= ecx <= count  =>  0 <= edx <= count-1
3490| ffffffff8b07e9f9: 39 c2                 cmp  %eax,%edx             ; explicit re-check: edx < count
3491| ffffffff8b07e9fb: 72 0f                 jb   ffffffff8b07ea0c
3498| ffffffff8b07ea0c: 8b 46 0c              mov  0xc(%rsi),%eax         ; record correction, rsi = table+edx*16
```

The invariant here is even more explicit than in F1: `ecx` is set to 1 at `ffffffff8b07e84b` and re-set at `ffffffff8b07e858`, raised only by `inc %r9d; mov %r9d,%ecx` (`ffffffff8b07e870`/`ffffffff8b07e873`) from `mid+1`, and the loop exits at `ffffffff8b07e876` when `ecx >= count`. So `1 <= ecx <= count` and `edx = ecx-1` is in `[0, count-1]`, additionally re-checked with `cmp %eax,%edx; jb` before the `record+0xc` read.

Index 2 — the overlap partner, `ecx-2`:

```
3419| ffffffff8b07e8e0: 83 f9 02              cmp  $0x2,%ecx
3420| ffffffff8b07e8e3: 41 0f 9c c0           setl %r8b                 ; guard: ecx >= 2 required for this path
3421| ffffffff8b07e8e7: 41 08 f8              or   %dil,%r8b
3422| ffffffff8b07e8ea: 0f 85 af 00 00 00     jne  ffffffff8b07e99f      ; ecx < 2 or offset < 0 -> no second index
3424| ffffffff8b07e8f3: 44 8d 49 fe           lea  -0x2(%rcx),%r9d
3428| ffffffff8b07e904: 49 c1 e3 04           shl  $0x4,%r11             ; (ecx-2) * 0x10
3430| ffffffff8b07e90c: 4d 63 74 3b 08        movslq 0x8(%r11,%rdi,1),%r14
3432| ffffffff8b07e915: 4d 63 54 3b 0c        movslq 0xc(%r11,%rdi,1),%r10
```

The `cmp $0x2,%ecx; setl` guard is the bound: the `(ecx-2)*16` read is only reachable with `ecx >= 2`, and `ecx <= count`, so the address is at most `table + (count-2)*16 + 0xc`. No underflow.

Index 3 — the backwards `correction` walk, which is the closest thing in the corpus to the flagged `index derived from table contents` sub-pattern:

```
3476| ffffffff8b07e9c9: 85 c9                 test %ecx,%ecx
3477| ffffffff8b07e9cb: 7e 2a                 jle  ffffffff8b07e9f7      ; ecx <= 0 -> skip the walk entirely
3481| ffffffff8b07e9e0: ff c9                 dec  %ecx                  ; decrement BEFORE the read
3482| ffffffff8b07e9e2: 49 89 c8              mov  %rcx,%r8
3483| ffffffff8b07e9e5: 49 c1 e0 04           shl  $0x4,%r8
3484| ffffffff8b07e9e9: 45 8b 44 38 0c        mov  0xc(%r8,%rdi,1),%r8d   ; table[ecx-1].correction
3485| ffffffff8b07e9ee: 45 85 c0              test %r8d,%r8d
3486| ffffffff8b07e9f1: 75 0c                 jne  ffffffff8b07e9ff      ; stop on the first non-zero correction
3487| ffffffff8b07e9f3: 85 c9                 test %ecx,%ecx
3488| ffffffff8b07e9f5: 7f e9                 jg   ffffffff8b07e9e0      ; continue only while ecx > 0
```

This is a content-driven walk: the loop `dec`s until it finds a non-zero `correction`, so the number of iterations is a property of the *table contents*, not of any count. Its bound is the entry guard plus the back-edge guard, both on the same `ecx`: entry `jle` refuses `ecx <= 0`, and the `dec` happens before the load, so the loaded index is `ecx-1 >= 0`; the back-edge `jg` re-enters only when `ecx > 0`, so the next `dec` also cannot go negative. Since `ecx <= count`, the maximum address is `table + (count-1)*16 + 0xc`. The walk cannot run off the front of the table, and it cannot run off the back because it only ever decrements.

The same walk exists in 638 in forward form, `ffffffff8b07e6e0`-`ffffffff8b07e6f9`, where the iteration count is `eax = count - edx + 1` and the index is `esi + edx_delta` with `esi = edx-1`, so the last index is `(edx-1) + (count-edx) = count-1` exactly. Bounded, and bounded by the *same* table's count.

Copyouts mirror 638 at constant lengths 8 / 0x10 / 4:

```
3528| ffffffff8b07ea77: 48 8d 7d c8  lea  -0x38(%rbp),%rdi
3529| ffffffff8b07ea7b: ba 08 00 00 00  mov $0x8,%edx
3531| ffffffff8b07ea83: e8 48 a7 b9 ff  call ffffffff8ac191d0
3542| ffffffff8b07eaac: 48 8d 7d d0  lea  -0x30(%rbp),%rdi
3543| ffffffff8b07eab0: ba 10 00 00 00  mov $0x10,%edx
3545| ffffffff8b07eab8: e8 13 a7 b9 ff  call ffffffff8ac191d0
3556| ffffffff8b07eae1: 48 8d 7d c4  lea  -0x3c(%rbp),%rdi
3557| ffffffff8b07eae5: ba 04 00 00 00  mov $0x4,%edx
3559| ffffffff8b07eaed: e8 de a6 b9 ff  call ffffffff8ac191d0
```

Worst case: identical to F1, 16 bytes per call, no OOB. Worst case for the *walk* is a full backwards scan, i.e. `count` iterations of a 4-byte read, all inside the window. **STATIC**.

### F3 — syscall 636 `set_timezone_info`: the write side, and the reason F1/F2 are safe

Presence: `| 636 | `set_timezone_info` | `-1` | present |`, and `docs/TZ_TABLE_638_14_10.md` records that every argument shape returns `EPERM` because the credential bit is tested before argument validation. This is not a read, but it is the load-bearing guard for the whole class, so it has to be stated with the read findings:

```
if (!sub_ffffffff8afc8f90(PTR(td,0x140))) return 1;        // bit 62 of cred+0x60
if ((uint32_t)(a->count-513U) < 0xfffffe00U) return 22;    // accepts 1..512
sub_ffffffff8ac19280(a->records, 0xffffffff8e2d5920, count*16);
*(uint32_t*)0xffffffff8e2d7920 = a->count;
```

(Quoted from `docs/TZ_TABLE_638_14_10.md`, which quotes the 636 body at `ffffffff8b07e4d0`; this note verified that the 636 *window* contains the 638/639 bodies but did not re-read `8b07e4d0`, so the five lines above are the doc's quotes, not this note's. Marked **INFERRED-BY-DOCUMENT**.)

Why it matters: `count <= 512` makes `table + (count-1)*16 + 0xc <= table + 0x1ffc`, i.e. strictly inside the 0x2000 window whose end is the count global. And the `count*16` copyin length equals the stride times the element count, so the write cannot spill into the count either. If a future firmware relaxes that gate to `count <= 0x1000`, F1/F2 become `/dev/mem`-grade `.data` reads immediately, with no change to their own code.

Worst case today: 8 KB write at a fixed `.data` RVA, behind a credential bit, `EPERM` on 14.10 for every shape probed. **STATIC (doc-sourced)**.

### F4 — syscalls 618/620/624/628/637/642: table-shaped, but the table is the caller's array

One shared body `ffffffff8b47dad0` (`handler_618_body` in `sys_618.asm`, the same body in the other five windows). The same window holds a second, separate copy site at `ffffffff8b47e22a` (length `0x3f8`); its function contains no scaled-index operand either, so it is not a table read. Names and presence: 618 `get_paging_stats_of_all_objects` `-1`, 620 `free_stack` `0`, 624 `get_vm_map_timestamp` `3377`, 628 `mmap_dmem` `-1`, 637 `set_phys_fmem_limit` `-1`, 642 `get_map_statistics` `-1`, all `present`.

This is the shape that a grep for `mov (%rax,%rN,8)` + `call 8ac191d0` flags, and it is the only place where an index produced by walking kernel data drives a copy:

```
4356| ffffffff8b47e068: 48 8b 58 10        mov  0x10(%rax),%rbx      ; rax = uap  =>  r[2], caller-owned base
4360| ffffffff8b47e07c: 44 3b 70 08        cmp  0x8(%rax),%r14d       ; index vs r[1], caller-declared count
4361| ffffffff8b47e080: 0f 8d 3b fb ff ff  jge  ffffffff8b47dbc1       ; index >= count -> stop, then inc
4362| ffffffff8b47e086: 49 6b c6 68        imul $0x68,%r14,%rax
4367| ffffffff8b47e09c: 48 01 c3           add  %rax,%rbx             ; rbx = r[2] + index*0x68
4369| ffffffff8b47e0a4: ba 68 00 00 00     mov  $0x68,%edx            ; length == stride
4370| ffffffff8b47e0a9: 48 8d bd 68 ff ff ff  lea -0x98(%rbp),%rdi     ; SOURCE = kernel stack record
4371| ffffffff8b47e0b0: 48 89 de           mov  %rbx,%rsi             ; DESTINATION = caller array
4372| ffffffff8b47e0b3: e8 18 b1 79 ff     call ffffffff8ac191d0
```

`rax` is the uap: `mov %rsi,%r14` at `ffffffff8b47daeb` (rsi = second handler argument) and `mov %r14,-0xb8(%rbp)` at `ffffffff8b47db39`, read back as `-0xb8(%rbp)` at `ffffffff8b47e053`/`ffffffff8b47e075`.

So the copy is source = kernel stack, destination = `uap->r[2] + i*0x68`, and `i` is the output counter. `uap->r[1]` bounds that counter, and the counter is incremented at `ffffffff8b47dbc1` only on success, never by the walk itself. The kernel never reads through the caller's base pointer here; the caller only supplies where its own bytes go. Not an OOB read, and not a kernel read at all.

The flagged sub-pattern — index derived from table contents, loop bound from another table's count — is nonetheless present in *form*: the index `r14d` advances with a linked-list walk (`mov 0x8(%r15),%r15` at `ffffffff8b47dbd0`, head `mov 0x200(%rbx),%r13` at `ffffffff8b47db7d`, termination `cmp %r13,%r15; je` at `ffffffff8b47dbb2`/`ffffffff8b47dbd4`), while the bound that gates the copy is a count field of a *different* object (the caller's array). The mismatch is harmless because the walk cannot address kernel memory: it only decides how many times the caller's own buffer is filled. If the list were corrupted into a cycle that never returns to the head, the loop would hang, not over-read — a availability question, not this class.

Worst case: writes up to `r[1] * 0x68` bytes into the caller's own array, each 0x68-byte chunk a fixed-size stack record. **STATIC**.

### F5 — syscalls 632/633/634 `thr_*_ucontext` and 616 `thr_get_name`: fixed-length copies out of a stack buffer whose filler is outside the corpus

Presence: all four `present` (632 `-1`, 633 `-1`, 634 `-1`, 616 `-1`). Body `ffffffff8adf9150` (632/633/634, also linked into 616's window):

```
3365| ffffffff8adf9297: 4c 8d bd d0 fa ff ff  lea  -0x530(%rbp),%r15   ; 0x500-byte buffer
3366| ffffffff8adf929e: be 00 05 00 00        mov  $0x500,%esi
3391| ffffffff8adf92fd: ba c0 04 00 00        mov  $0x4c0,%edx
3392| ffffffff8adf9302: 4c 89 ff              mov  %r15,%rdi             ; rdi = the 0x500-byte buffer
3393| ffffffff8adf9305: 48 89 de              mov  %rbx,%rsi             ; rsi = uap->r[1]
3394| ffffffff8adf9308: e8 c3 fe e1 ff        call ffffffff8ac191d0
```

Constant length `0x4c0` from a `0x500` buffer that was zeroed with `mov $0x500,%esi` and then filled by `call ffffffff8b3cbb60` (`ffffffff8adf92b7`). **Correction (2026-11-04, from the companion audit):** the zeroing is *in* this window, not outside it — `sys_634.asm:3366-3368` issues `mov $0x500,%esi` + `call ffffffff8ac18ff0` (bzero) over the whole frame slot before the fill, so the copied `0x4c0` bytes are always fully defined. What stays outside the corpus is only the callee body `8b3cbb60`; there the concern would be a frame overflow, not a partial-initialisation leak. `sys_634.asm:3411` also checks the canary at `-0x30(%rbp)`, so a length raised toward `0x500` would copy the canary — a shape for a future firmware, not a 14.10 defect. That is a *different* class (does the filler respect the 0x500 frame slot?), and it would be a stack overflow, not a table-index read. Recorded so the next auditor does not mistake the `0x4c0` copy for an in-class finding.

616's own first site is the same shape at a smaller size: `ffffffff8adf8d37: 4c 89 f7 mov %r14,%rdi` (a 0x20-byte stack buffer at `-0x50(%rbp)`), `ffffffff8adf8d3d: 4c 89 fa mov %r15,%rdx` (length = helper return + 1, capped by the `0x1f` argument passed to `ffffffff8ae04eb0`), `ffffffff8adf8d40: e8 8b 04 e2 ff call ffffffff8ac191d0`. Derived length, bounded by `0x20` via the `0x1f` cap, source is the stack buffer. Out of class.

### F6 — excluded bodies, with the quote that excludes them

**617 `set_gpo` / 623 `get_gpo`** (`present`; 617 returns `0`, 623 `-1`), body `ffffffff8b2925a0`. The 4-byte copy source is a stack int, initialised to zero and optionally filled by a call:

```
3169| ffffffff8b2925cc: c7 45 e4 00 00 00 00  movl $0x0,-0x1c(%rbp)
3181| ffffffff8b2925ff: 48 8d 7d e4           lea  -0x1c(%rbp),%rdi
3182| ffffffff8b292603: ba 04 00 00 00        mov  $0x4,%edx
3184| ffffffff8b29260b: e8 c0 6b 98 ff        call ffffffff8ac191d0
```

The unchecked `0x40`-stride table at `0xffffffff8cf0b950` (`ffffffff8b29381a: 4c 8d 2d 2f 81 c7 01 lea 0x1c7812f(%rip),%r12` in the same dump) is read by *neighbouring* functions `ffffffff8b293cb9`/`ffffffff8b293e08`/`ffffffff8b293eec`, not by 617's body, and none of them calls the copy helper. So the unbounded-looking table never reaches userland.

**625 `opmc_set_hw` / 626 `opmc_get_hw`** (`present`; both `-1`), body `ffffffff8afc4cf0`. The only table is a 6-entry jump table, bounded:

```
3252| ffffffff8afc4e4d: 8b 0e                 mov    (%rsi),%ecx
3253| ffffffff8afc4e4f: ff c9                 dec    %ecx
3254| ffffffff8afc4e51: 83 f9 05              cmp    $0x5,%ecx
3255| ffffffff8afc4e54: 0f 87 ce 00 00 00     ja     ffffffff8afc4f28
3256| ffffffff8afc4e5a: 48 8d 15 5b e7 11 01  lea    0x111e75b(%rip),%rdx   # ffffffff8c0e35bc
3257| ffffffff8afc4e61: b8 06 00 00 00        mov    $0x6,%eax
3258| ffffffff8afc4e66: 48 63 0c 8a           movslq (%rdx,%rcx,4),%rcx
3259| ffffffff8afc4e6a: 48 01 d1              add    %rdx,%rcx
3260| ffffffff8afc4e6d: ff e1                 jmp    *%rcx
```

(`sys_626.asm` PART 3, body `ffffffff8afc4cf0`.) The copyout is 8 bytes from `-0x128(%rbp)`, which holds an MSR read (`rdmsr` of `0xc0010241` / `0xc0010189` at `ffffffff8afc4f8c`/`ffffffff8afc4f96`) or a helper return. No table source.

**627 `get_cpu_usage_all` / 641 `get_cpu_usage_proc`** (`present`; both `-1`), body `ffffffff8ae62de0`. The 0x38-byte record is assembled on the stack from caller memory, then copied to a caller pointer:

```
4036| ffffffff8ae630ae: 48 8d 7d 98        lea  -0x68(%rbp),%rdi
4037| ffffffff8ae630b2: ba 38 00 00 00     mov  $0x38,%edx
4038| ffffffff8ae630b7: 48 89 de           mov  %rbx,%rsi        ; rbx = 0x8(%rcx) from the caller structure
4039| ffffffff8ae630ba: e8 11 61 db ff     call ffffffff8ac191d0
```

Both call sites (`ffffffff8ae630ba`, `ffffffff8ae6316a`) take `rsi` from `mov 0x8(%rcx),%rbx` (`ffffffff8ae6314c`), i.e. a pointer read out of the caller's structure. No global table.

## 4. All files that reference the helper

27 decompiled files name `func_0xffffffff8ac191d0`; 19 of them also carry the byte-level call in the asm dump. `table-index pattern?` answers the question for the copy site(s) in that file: `yes` means the copy source is a global table plus a scaled index, `no` means every copy source in the file is a stack frame or a caller pointer.

| # | file | byte-level call in asm dump | helper calls in decompiled dump | which body the calls belong to | table-index pattern? |
|---|---|---|---|---|---|
| | `results/kernel_handlers/asm/sys_616.asm` / `decompiled/sys_616.c` | yes | 19 | `8adf8c90` (616) + `8adf9150` | no |
| | `results/kernel_handlers/asm/sys_617.asm` / `decompiled/sys_617.c` | yes | 15 | `8b2925a0` (617) | no |
| | `results/kernel_handlers/asm/sys_618.asm` / `decompiled/sys_618.c` | yes | 15 | `8b47dad0` + `8b47e1c0` (618) | no |
| | `results/kernel_handlers/asm/sys_619.asm` / `decompiled/sys_619.c` | no | 15 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_620.asm` / `decompiled/sys_620.c` | yes | 16 | `8b47dad0` (620) | no |
| | `results/kernel_handlers/asm/sys_621.asm` / `decompiled/sys_621.c` | no | 18 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_623.asm` / `decompiled/sys_623.c` | yes | 18 | `8b2925a0` (623) | no |
| | `results/kernel_handlers/asm/sys_624.asm` / `decompiled/sys_624.c` | yes | 17 | `8b47dad0` (624) | no |
| | `results/kernel_handlers/asm/sys_625.asm` / `decompiled/sys_625.c` | yes | 15 | `8afc4cf0` (625) | no |
| | `results/kernel_handlers/asm/sys_626.asm` / `decompiled/sys_626.c` | yes | 16 | `8afc4cf0` (626) | no |
| | `results/kernel_handlers/asm/sys_627.asm` / `decompiled/sys_627.c` | yes | 14 | `8ae62de0` (627) | no |
| | `results/kernel_handlers/asm/sys_628.asm` / `decompiled/sys_628.c` | yes | 15 | `8b47dad0` (628) | no |
| | `results/kernel_handlers/asm/sys_629.asm` / `decompiled/sys_629.c` | no | 14 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_631.asm` / `decompiled/sys_631.c` | no | 18 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_632.asm` / `decompiled/sys_632.c` | yes | 14 | `8adf9150` (632) | no |
| | `results/kernel_handlers/asm/sys_633.asm` / `decompiled/sys_633.c` | yes | 14 | `8adf9150` (633) | no |
| | `results/kernel_handlers/asm/sys_634.asm` / `decompiled/sys_634.c` | yes | 17 | `8adf9150` (634) | no |
| | `results/kernel_handlers/asm/sys_635.asm` / `decompiled/sys_635.c` | no | 13 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_636.asm` / `decompiled/sys_636.c` | yes | 17 | `8b07e5c0` (638) + `8b07e800` (639) in the same window | **yes** (638/639 bodies) |
| | `results/kernel_handlers/asm/sys_637.asm` / `decompiled/sys_637.c` | yes | 15 | `8b47dad0` (637) | no |
| | `results/kernel_handlers/asm/sys_638.asm` / `decompiled/sys_638.c` | yes | 17 | `8b07e5c0` (638) + `8b07e800` (639) | **yes** |
| | `results/kernel_handlers/asm/sys_639.asm` / `decompiled/sys_639.c` | yes | 16 | `8b07e800` (639) | **yes** |
| | `results/kernel_handlers/asm/sys_640.asm` / `decompiled/sys_640.c` | no | 7 | window neighbour (`8ae62de0`) only | no |
| | `results/kernel_handlers/asm/sys_641.asm` / `decompiled/sys_641.c` | yes | 15 | `8ae62de0` (641) | no |
| | `results/kernel_handlers/asm/sys_642.asm` / `decompiled/sys_642.c` | yes | 15 | `8b47dad0` + `8b47e1c0` (642) | no |
| | `results/kernel_handlers/asm/sys_644.asm` / `decompiled/sys_644.c` | no | 18 | window neighbours only | no |
| | `results/kernel_handlers/asm/sys_645.asm` / `decompiled/sys_645.c` | no | 18 | window neighbours only | no |

`sys_639.asm` also contains a second copy at `ffffffff8b07e800` labelled `handler_639_body`, which is the same function the 636/638 windows carry as `frame_candidate_6be800`/`8b07e800`; the three `yes` rows are therefore one table, not three.

## 5. Ranked candidates

Ranked by closeness to a violation, since none is provably a bug. `OOB?` is the answer after the bound proof, not a severity.

| rank | syscall(s) | 13.60 name | 14.10 | index source | bound | length vs stride | OOB? |
|---|---|---|---|---|---|---|---|
| 1 | 638 | `utc_to_localtime` | `0` present | caller `input` -> binary-search insertion point `edx-1` | search invariant `1 <= edx <= count` (`8b07e626`), no compare at the load (`8b07e664`) | 8 / 0x10 / 4 vs stride 0x10, agree | no |
| 2 | 639 | `localtime_to_utc` | `0` present | caller value -> `ecx-1`, plus `ecx-2` and a content-driven backwards walk | `1 <= ecx <= count` (`8b07e876`), `ecx >= 2` guard (`8b07e8e0`), decrement-before-load (`8b07e9e0`) | 8 / 0x10 / 4 vs 0x10, agree | no |
| 3 | 618/620/624/628/637/642 | `get_paging_stats_of_all_objects` etc. | all present | kernel circular-list walk advances `r14d` | `uap->r[1]` (`8b47e07c`) - a *different* object's count | 0x68 == 0x68, agree (dest is the caller's array) | no |
| 4 | 636 | `set_timezone_info` | `-1` present (EPERM) | caller `count` | `1..512` gate, `count*16` copyin | 16 == 16, agree | no (write side) |
| 5 | 632/633/634 | `thr_suspend_ucontext` / `thr_resume_ucontext` / `thr_get_ucontext` | present | none (constant) | 0x4c0 into 0x500 | 0x4c0 vs n/a | no |
| 6 | 616 | `thr_get_name` | present | none | derived length <= 0x20 | <= 0x20 into 0x20 buffer | no |
| 7 | 627/641 | `get_cpu_usage_all` / `get_cpu_usage_proc` | present | none (caller structure fields) | n/a | 0x38 constant | no |
| 8 | 625/626 | `opmc_set_hw` / `opmc_get_hw` | present | user dword into a jump table | `cmp $0x5` + `ja default` | 8 bytes, no table | no |

## 6. What a real OOB in this class would look like

The corpus would have to show one of these, and none of the 42 sites does:

1. `cmp/jae` against a **different** global than the table's own count (or against a stale copy of the count taken before the lock);
2. a `<=` instead of `<` at the upper bound, so `table[count]` is reachable - with 512 slots used and the count at `table+0x2000`, `table[512]` is the count global itself, an 4-byte leak from `.data` that would look benign in a hex dump;
3. a stride larger than the copy length, or an `imul` by a stride that disagrees with the element size used to compute the table's extent;
4. an index formed by `add` of two offsets where only one is bounded (`lea (%rsi,%rdx,1)` with `rsi` from the search and `rdx` from a caller field);
5. a count global *not* adjacent to its table, so `count <= N` and `window == M` are independent facts that can drift apart.

Given the layout at `0xffffffff8e2d5920`/`0xffffffff8e2d7920`, (5) is structurally impossible for this table and (2) is the only one worth a second look in a future firmware: a `jbe` instead of a `jb` at either search exit.

## 7. Limits

* No live measurement. Presence and return values are quoted from `docs/SYSENT_PRESENCE_14_10.md`; the table occupancy (258 of 512) is `docs/TZ_TABLE_638_14_10.md`'s measurement.
* The helper body `0xffffffff8ac191d0` is not in the corpus, so source/destination roles are inferred from 42 call sites, all consistent.
* The table contents, the count value, and the mode global live in `.data` past the dumped `.text` extent; only relationships between their addresses are used here.
* 14.10 bodies were not dumped for this note. 638/639 return `0` on 14.10 with six zero arguments, which is consistent with the 13.60 body but does not prove it is byte-identical.
* `sys_632.asm`, `sys_633.asm`, `sys_634.asm`, `sys_616.asm` all contain `ffffffff8adf9150`; the analysis is done once and applied to all four.

## 4. Cross-check: the partial-initialisation half is clean too

The companion audit (`docs/COPYOUT_PARTIAL_STACK_AUDIT.md`, 428 lines) audits the orthogonal
question — is the *source* fully defined for the number of bytes copied, and is the *length*
trustworthy — over the same 15 distinct `call ffffffff8ac191d0` instructions (46 listing lines,
9 distinct function bodies; 616/632/633 are all entries into the 634 body at `0x8adf9150`).

| item | count |
|---|---|
| sites whose source is a stack local | 15 / 15 |
| sites provably partially initialised inside the copied length | **0 / 15** |
| sites with a caller-supplied or global length | **0 / 15** |
| sites whose length is an immediate | 14 (4, 8, 0x10, 0x38, 0x68, 0x3f8, 0x4c0) |
| sites whose length is computed | 1 — 616 `strnlen(s,0x1f)+1 <= 0x20`, the size of the filling `memcpy` |

Every copied range is covered either by a `bzero` at least as long as the copy (634 `bzero 0x500`
for `len 0x4c0`; 642 `0x68/0x68`; 641 `0x38/0x38`) or by field stores that fill it exactly.
Together with the tables above, the two ways a copy-out helper can betray its caller — a bad
*index* and a bad *extent* — are both clean across the corpus, and every one of the 19 syscall
numbers involved is present on 14.10 (616/618/623/625/626/627/628/632/633/634/636/637/641/642
return `-1`; 617/620/638/639 return `0`; 624 returns `3377`), so the negatives are not an
artefact of dead slots. 640 is excluded and documented in the companion note: its table copy is
an inline `rep movsq` from `0xffffffff8e5b6a60 + idx*0x58` with no `stac`, i.e. kernel-to-kernel.

The strongest residual shape is 634 `thr_get_ucontext`: 0x4c0 bytes out of a 0x500-byte frame slot,
safe only because of the preceding `bzero`. Raise the immediate toward 0x500 on a future firmware
and the tail would include the canary at `-0x30(%rbp)` (`sys_634.asm:3411`). On 14.10 the length
is an immediate, so no argument reaches it.
