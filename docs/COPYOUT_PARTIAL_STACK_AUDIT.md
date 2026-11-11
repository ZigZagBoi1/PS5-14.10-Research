# Copy-out partial-initialisation and length-mismatch audit

**Class:** a kernel stack frame (or a partially filled struct) copied to a user pointer, so that
bytes the handler never wrote reach userland — or a copy whose length is caller-controlled.
**Corpus:** `results/kernel_handlers/` (13.60 bodies; image base `0xffffffff8a000000`, RVA = VA - base).
**Reachability:** `docs/SYSENT_PRESENCE_14_10.md` (measured on 14.10 by `tools/syscall_isolation_sweep.py`).
**Status of every statement below:** STATIC unless explicitly marked INFERRED. No live measurement
was performed for this note.

Companion note: `docs/COPYOUT_TABLE_INDEX_AUDIT.md` audits the *index* half of this helper
(global table + scaled index). This note audits the orthogonal half: is the **source buffer fully
defined** for the number of bytes copied, and is the **length** trustworthy.

## 中文摘要

1. 真正的调用点不是 62 个文件，而是 19 个 asm / 27 个 decompiled / 8 个 analysis（`results/kernel_handlers/` 内共 54 个文件；全库 63 个，其余 9 个是 docs/tools/json/pkl）。字节级 `call ffffffff8ac191d0` 指令共 **15 条**，在 19 个窗口中重复列出，合计 46 行。
2. 15 条指令的源**全部**是栈局部（`lea -0xNN(%rbp)`），没有一条以全局表或调用者指针为源。
3. **可证的「部分未初始化」：0 条。** 每一条的拷贝区间都被完整覆盖：要么调用前 `bzero` 的长度 ≥ 拷贝长度，要么字段级写入恰好写满拷贝长度。最接近「危险」的 634 也有 `bzero 0x500` 对 `len 0x4c0`。
4. **调用者可控长度：0 条。** 14 条是立即数（4/8/0x10/0x38/0x68/0x3f8/0x4c0），唯一非常量的 616 是 `strnlen(s,31)+1`，恒 ≤ 0x20 = 被 memcpy 填满的缓冲大小。
5. 结论：本类在 13.60 语料上为**干净否定**。计数见 §1，逐点证据见 §3–§4，最接近的 5 个「差一步就泄漏」的点见 §5。

## 0. Verdict

| item | count |
|---|---|
| asm files containing a byte-level `call ffffffff8ac191d0` | 19 |
| decompiled `.c` files naming the helper | 27 |
| analysis `.md` files naming the helper | 8 |
| call lines in those asm files (dual listings + shared bodies) | 46 |
| **distinct call instructions in the 13.60 image** | **15** |
| distinct functions containing one of the 15 | 9 |
| sites whose source is a stack local | **15 / 15** |
| sites provably **partially initialised** inside the copied length | **0 / 15** |
| sites with a caller-supplied / global length | **0 / 15** |
| sites whose destination is not derived from an already-copied uap | 0 |
| candidates that leak kernel stack to userland | **0** |

A clean negative is the finding: these 15 copy instructions are the complete set of user-copy
primitives reached from the handlers in this corpus, and every one of them is preceded by a
definition of the whole copied range.

## 1. Corpus count: the "62 handlers" figure does not reproduce

Reproduce the denominator (from the repo root):

```
grep -l 8ac191d0 results/kernel_handlers/asm/*.asm        # 19 files
grep -l 8ac191d0 results/kernel_handlers/decompiled/*.c   # 27 files
grep -l 8ac191d0 results/kernel_handlers/analysis/*.md    #  8 files
grep -c 'call.*8ac191d0 <' results/kernel_handlers/asm/*.asm | awk -F: '{s+=$2} END{print s}'   # 46
```

The 19 asm files are `sys_616 617 618 620 623 624 625 626 627 628 632 633 634 636 637 638 639 641 642`.
A repo-wide byte search for `8ac191d0` returns 63 files: the 54 above plus
`all_callgraph_forward.json`, `docs/CHANGELOG.md`, `docs/COPYOUT_TABLE_INDEX_AUDIT.md`,
`docs/FINDINGS.md`, `docs/TZ_TABLE_638_14_10.md`, `malloc_streams.pkl` and three scripts under `tools/`.

The "62" comes from the closing top-10 list in `docs/TZ_TABLE_638_14_10.md` ("… 52 more, 1-18 calls
each"). As `docs/COPYOUT_TABLE_INDEX_AUDIT.md` §1 shows with per-file counts, none of those ten
named files contains the address at all; the list is not a measurement of this corpus. The audit
below therefore covers the 19 files / 15 instructions that exist.

Every asm file is a 4096-byte window of 512 neighbouring trampolines and only the first trampoline
is syscall N (`results/kernel_handlers/asm/sys_638.asm:9`: `; Only first trampoline is syscall 638;
remaining 511 are neighboring stubs.`). A call site inside a window therefore does not
necessarily belong to that file's syscall. Each site below is attributed to its **enclosing
function**, recovered from the function label in PART 3; the RVA labels map as
`frame_candidate_6be5c0` = `0xffffffff8a9c0000 + 0x6be5c0` = `0xffffffff8b07e5c0`.

## 2. Helper semantics — STATIC, from the helper's own bytes

The copy helper's body *is* in the corpus, as a supplemental objdump dump inside
`results/kernel_handlers/asm/sys_646.asm` (repeated verbatim in sys_647/649/650). Quotes below are
`sys_646.asm` line numbers, RVA addresses (`0x2591d0` = `0xffffffff8ac191d0`).

```
15583:   2591d0:	55                   	push   rbp
15585:   2591d4:	65 48 8b 04 25 20 00 	mov    rax,QWORD PTR gs:0x20
15587:   2591dd:	4c 8d 1d 7c 00 00 00 	lea    r11,[rip+0x7c]        # 0x259260
15588:   2591e4:	4c 89 98 08 01 00 00 	mov    QWORD PTR [rax+0x108],r11
15589:   2591eb:	48 85 d2             	test   rdx,rdx
15591:   2591f0:	48 89 f0             	mov    rax,rsi
15592:   2591f3:	48 01 d0             	add    rax,rdx
15593:   2591f6:	72 68                	jb     0x259260
15596:   259202:	48 39 c8             	cmp    rax,rcx          ; rcx = 0x800000000000
15597:   259205:	77 59                	ja     0x259260
15601:   259214:	80 b8 91 05 00 00 00 	cmp    BYTE PTR [rax+0x591],0x0
15605:   259227:	48 21 c6             	and    rsi,rax          ; rax = 0x7fffffffffff
15606:   25922a:	48 87 f7             	xchg   rdi,rsi
15610:   259235:	0f 01 cb             	stac
15611:   259238:	f3 48 a5             	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
15614:   259240:	f3 a4                	rep movs BYTE PTR [rdi],BYTE PTR [rsi]
15629:   259260:	0f 01 ca             	clac
15634:   259277:	48 c7 c0 0e 00 00 00 	mov    rax,0xe
```

Established, all STATIC:

* signature is `copyout(kernel_source = RDI, user_destination = RSI, length = RDX)`: the
  `xchg rdi,rsi` at `0x25922a` puts the user pointer in RDI for `rep movs`, so bytes flow
  **from RDI to RSI**;
* the destination is masked to the low canonical half (`and rsi,0x7fffffffffff` at `0x259227`), so
  a kernel pointer passed as a destination becomes a user address and faults instead of writing
  kernel memory;
* the only length checks are `len != 0` (`0x2591eb`), `dest+len` no-carry (`0x2591f6`) and
  `dest+len <= 0x800000000000` (`0x259205`); a per-process byte `[proc+0x591]` is tested
  (`0x259214`). **No page probing, no copyout-probe-first.** Faults are caught by the
  `pcb_onfault` slot installed at `0x2591e4` and converted to `0xe` (EFAULT) at `0x259277`.
* **Consequence for this class:** the helper faithfully delivers whatever bytes the source buffer
  contains. Nothing between the handler's frame and userland inspects or clears them, so the whole
  question is "which bytes of the source were written before the call".

The zeroing helper is likewise in the corpus (`sys_646.asm:15549-15573`, `0x258ff0`):
`rep stos QWORD/BYTE` with `xor eax,eax` — i.e. `bzero(RDI, RSI)`, with a stack-bounds sanity
call at `0x259015` when `dst+len < rsp`. Every `mov $0xNN,%esi` + `lea -0xNN(%rbp),%rdi` +
`call ffffffff8ac18ff0` below is therefore a proven full zero-fill of that many bytes.

## 3. All 19 files, and all 15 sites

### 3.1 Per-file table

"Owner" is the function containing the instruction, not necessarily the file's syscall.
"Partial" counts sites in that file whose copied range is not fully defined.

| asm file | call lines | distinct sites shown | owner function(s) of those sites | stack source | partial |
|---|---|---|---|---|---|
| `sys_616.asm` | 2 | `8adf8d40`, `8adf9308` | `handler_616_body`, `0x8adf9150` (= 634 body) | 2 | 0 |
| `sys_617.asm` | 1 | `8b29260b` | `0x8b2925a0` (= 623 body; window label `frame_candidate_8d25a0`) | 1 | 0 |
| `sys_618.asm` | 3 | `8b47e0b3`, `8b47e155`, `8b47e22a` | `0x8b47dad0` (= 642 body), `0x8b47e1c0` | 3 | 0 |
| `sys_620.asm` | 3 | same three | same | 3 | 0 |
| `sys_623.asm` | 1 | `8b29260b` | `handler_623_body` | 1 | 0 |
| `sys_624.asm` | 3 | same three | same as 618 | 3 | 0 |
| `sys_625.asm` | 1 | `8afc4fd2` | `0x8afc4cf0` (= 626 body; window label `frame_candidate_604cf0`) | 1 | 0 |
| `sys_626.asm` | 1 | `8afc4fd2` | `handler_626_body` | 1 | 0 |
| `sys_627.asm` | 2 | `8ae630ba`, `8ae6316a` | `0x8ae62de0` (= 641 body; window label `frame_candidate_4a2de0`) | 2 | 0 |
| `sys_628.asm` | 3 | same three as 618 | same | 3 | 0 |
| `sys_632.asm` | 1 | `8adf9308` | `0x8adf9150` (= 634 body) | 1 | 0 |
| `sys_633.asm` | 1 | `8adf9308` | `0x8adf9150` (= 634 body) | 1 | 0 |
| `sys_634.asm` | 1 | `8adf9308` | `handler_634_body` | 1 | 0 |
| `sys_636.asm` | 6 | `8b07e767`, `8b07e79c`, `8b07e7d1`, `8b07ea83`, `8b07eab8`, `8b07eaed` | `0x8b07e5c0` (= 638 body), `0x8b07e800` (= 639 body) | 6 | 0 |
| `sys_637.asm` | 3 | same three as 618 | same | 3 | 0 |
| `sys_638.asm` | 6 | the six `8b07exxx` | 638 body (3) + 639 body (3) | 6 | 0 |
| `sys_639.asm` | 3 | `8b07ea83`, `8b07eab8`, `8b07eaed` | `handler_639_body` | 3 | 0 |
| `sys_641.asm` | 2 | `8ae630ba`, `8ae6316a` | `handler_641_body` | 2 | 0 |
| `sys_642.asm` | 3 | same three as 618 | `handler_642_body` (2) + `0x8b47e1c0` (1) | 3 | 0 |
| **totals** | **46** | **15 distinct** | **9 functions** | **15** | **0** |

### 3.2 The 15 sites, with what defines the copied bytes

| # | instruction | owning handler (13.60 name) | source local | len | what defines every copied byte | verdict |
|---|---|---|---|---|---|---|
| 1 | `8adf8d40` | 616 `thr_get_name` | `-0x50(%rbp)` | `strnlen+1` | memcpy 0x20 at `8adf8cf2`; len <= 0x20 | clean |
| 2 | `8adf9308` | 634 `thr_get_ucontext` | `-0x530(%rbp)` | `0x4c0` | bzero 0x500 at `8adf92a6` | clean |
| 3 | `8b29260b` | 623 `get_gpo` | `-0x1c(%rbp)` | `4` | `movl $0x0` at `8b2925cc` | clean |
| 4 | `8b47e0b3` | 642 `get_map_statistics` | `-0x98(%rbp)` | `0x68` | bzero 0x68 at `8b47e036` + memcpy 0x20 | clean |
| 5 | `8b47e155` | 642 body | `-0x9c(%rbp)` | `4` | `movl $0x0` at `8b47db9c`, then `inc` store | clean |
| 6 | `8b47e22a` | `0x8b47e1c0` (helper) | `-0x418(%rbp)` | `0x3f8` | bzero 0x3f8 at `8b47e200` | clean (all zeros) |
| 7 | `8afc4fd2` | 626 `opmc_get_hw` | `-0x128(%rbp)` | `8` | `mov %rdx,-0x128(%rbp)` from RDMSR | clean |
| 8 | `8ae630ba` | 641 `get_cpu_usage_proc` | `-0x68(%rbp)` | `0x38` | bzero 0x38 at `8ae62e2b` + 8 field stores | clean |
| 9 | `8ae6316a` | 641 body | `-0x68(%rbp)` | `0x38` | entry bzero + 3 field stores | clean |
| 10 | `8b07e767` | 638 `utc_to_localtime` | `-0x38(%rbp)` | `8` | `mov %rax,-0x38` at `8b07e737` | clean |
| 11 | `8b07e79c` | 638 body | `-0x30(%rbp)` | `0x10` | two qword stores at `8b07e66e`/`8b07e672` | clean |
| 12 | `8b07e7d1` | 638 body | `-0x3c(%rbp)` | `4` | `movl $0x0` at `8b07e652` + 2 conditional stores | clean |
| 13 | `8b07ea83` | 639 `localtime_to_utc` | `-0x38(%rbp)` | `8` | computed at `8b07ea53` | clean |
| 14 | `8b07eab8` | 639 body | `-0x30(%rbp)` | `0x10` | both qwords written on all 3 predecessor paths | clean |
| 15 | `8b07eaed` | 639 body | `-0x3c(%rbp)` | `4` | `movl $0x0` at `8b07e82b` (entry) | clean |

## 4. Findings, with quotes

### F1 — 616 `thr_get_name`: the only non-constant length, bounded by the fill

`results/kernel_handlers/asm/sys_616.asm`:

```
3248: ffffffff8adf8cdc:	4c 8d 75 b0          	lea    -0x50(%rbp),%r14
3250: ffffffff8adf8ce7:	ba 20 00 00 00       	mov    $0x20,%edx
3253: ffffffff8adf8cf2:	e8 79 ee 51 00       	call   ffffffff8b317b70   ; memcpy(-0x50, [obj+0x294], 0x20)
3261: ffffffff8adf8d0f:	be 1f 00 00 00       	mov    $0x1f,%esi
3263: ffffffff8adf8d17:	e8 94 c1 00 00       	call   ffffffff8ae04eb0   ; strnlen(-0x50, 0x1f)
3266: ffffffff8adf8d25:	4c 8d 78 01          	lea    0x1(%rax),%r15
3270: ffffffff8adf8d37:	4c 89 f7             	mov    %r14,%rdi
3271: ffffffff8adf8d3a:	48 89 de             	mov    %rbx,%rsi
3272: ffffffff8adf8d3d:	4c 89 fa             	mov    %r15,%rdx
3273: ffffffff8adf8d40:	e8 8b 04 e2 ff       	call   ffffffff8ac191d0
```

The block `8adf8cdc`–`8adf8d40` is straight-line (no branch between the memcpy and the call),
the memcpy fills all 0x20 bytes of the local, and `strnlen` cannot return more than 0x1f, so
`len in [1,0x20]`. The shape to grep for on a future firmware is the bound and the buffer
disagreeing (e.g. `mov $0x40,%esi` with the same 0x20 memcpy). Today: **clean**.

### F2 — 632/633/634 `thr_*_ucontext`: 0x4c0 copied out of a 0x500-byte zeroed frame area

`results/kernel_handlers/asm/sys_634.asm` (same body appears in the sys_616/632/633 windows as
`frame_candidate_439150` = RVA `0x439150`):

```
3365: ffffffff8adf9297:	4c 8d bd d0 fa ff ff 	lea    -0x530(%rbp),%r15
3366: ffffffff8adf929e:	be 00 05 00 00       	mov    $0x500,%esi
3368: ffffffff8adf92a6:	e8 45 fd e1 ff       	call   ffffffff8ac18ff0   ; bzero(-0x530, 0x500)
3369: ffffffff8adf92ab:	48 8d b5 10 fb ff ff 	lea    -0x4f0(%rbp),%rsi
3370: ffffffff8adf92b2:	4c 89 f7             	mov    %r14,%rdi
3372: ffffffff8adf92b7:	e8 a4 28 5d 00       	call   ffffffff8b3cbb60   ; fills the ucontext body at -0x4f0
3391: ffffffff8adf92fd:	ba c0 04 00 00       	mov    $0x4c0,%edx
3392: ffffffff8adf9302:	4c 89 ff             	mov    %r15,%rdi
3393: ffffffff8adf9305:	48 89 de             	mov    %rbx,%rsi
3394: ffffffff8adf9308:	e8 c3 fe e1 ff       	call   ffffffff8ac191d0
```

bzero covers `-0x530 .. -0x31`; the copy covers `-0x530 .. -0x71` (0x4c0 bytes), strictly
inside the zeroed span, and the only meaningful fill lands at `-0x4f0` inside it. The user
receives zeros everywhere except the ucontext body. This also corrects
`docs/COPYOUT_TABLE_INDEX_AUDIT.md` §F5 ("the filler is outside the corpus"): the filler is
`8adf92a6` and `8adf92b7`, both inside the window. **Clean** — and at 1216 bytes the
highest-consequence copy in the set, hence #1 in §5.

The path at `8adf9286` (`mov $0x3,%eax` / `jmp 0x8adf9341`) skips the bzero and lands on the
common epilogue (`cmp -0x30(%rbp),%rcx` / `add $0x508,%rsp` / `ret` at `8adf9341`), so it
cannot reach the copy with an unzeroed frame.

### F3 — 623 `get_gpo`: 4 bytes, zero-initialised before the optional fill

`results/kernel_handlers/asm/sys_623.asm`:

```
3168: ffffffff8b2925ca:	74 46                	je     ffffffff8b292612   ; error path, no copy
3169: ffffffff8b2925cc:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
3173: ffffffff8b2925dc:	48 8d 7d e4          	lea    -0x1c(%rbp),%rdi
3174: ffffffff8b2925e0:	e8 5b 5f d9 ff       	call   ffffffff8b028540   ; optional value fill
3181: ffffffff8b2925ff:	48 8d 7d e4          	lea    -0x1c(%rbp),%rdi
3182: ffffffff8b292603:	ba 04 00 00 00       	mov    $0x4,%edx
3183: ffffffff8b292608:	48 89 de             	mov    %rbx,%rsi
3184: ffffffff8b29260b:	e8 c0 6b 98 ff       	call   ffffffff8ac191d0
```

The branch at `8b2925da` may skip the fill call, but the `movl $0x0` at `8b2925cc` dominates
both variants. **Clean.**

### F4 — 642 `get_map_statistics` body (shared with 618/620/624/628/637)

`results/kernel_handlers/asm/sys_618.asm`, function `0x8b47dad0`:

```
4346: ffffffff8b47e02a:	be 68 00 00 00       	mov    $0x68,%esi
4347: ffffffff8b47e02f:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
4348: ffffffff8b47e036:	e8 b5 af 79 ff       	call   ffffffff8ac18ff0   ; bzero(-0x98, 0x68)
4349: ffffffff8b47e03b:	49 8d b7 50 01 00 00 	lea    0x150(%r15),%rsi
4350: ffffffff8b47e042:	ba 20 00 00 00       	mov    $0x20,%edx
4352: ffffffff8b47e04e:	e8 1d 9b e9 ff       	call   ffffffff8b317b70   ; memcpy(-0x98, obj+0x150, 0x20)
4362: ffffffff8b47e086:	49 6b c6 68          	imul   $0x68,%r14,%rax
4369: ffffffff8b47e0a4:	ba 68 00 00 00       	mov    $0x68,%edx
4370: ffffffff8b47e0a9:	48 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%rdi
4371: ffffffff8b47e0b0:	48 89 de             	mov    %rbx,%rsi
4372: ffffffff8b47e0b3:	e8 18 b1 79 ff       	call   ffffffff8ac191d0
```

0x68 zeroed, 0x20 meaningful, 0x68 copied. The index site:

```
4061: ffffffff8b47db9c:	c7 85 64 ff ff ff 00 	movl   $0x0,-0x9c(%rbp)
4070: ffffffff8b47dbc4:	44 89 b5 64 ff ff ff 	mov    %r14d,-0x9c(%rbp)
4409: ffffffff8b47e146:	48 8d bd 64 ff ff ff 	lea    -0x9c(%rbp),%rdi
4410: ffffffff8b47e14d:	ba 04 00 00 00       	mov    $0x4,%edx
4412: ffffffff8b47e155:	e8 76 b0 79 ff       	call   ffffffff8ac191d0
```

`-0x9c` is *outside* the bzero'd `-0x98..-0x31` block, so it needed its own proof: the
`movl $0x0` at `8b47db9c` runs before the loop is entered (`jmp 0x8b47dbdd` at `8b47dbbf`)
and the only other write is the loop increment at `8b47dbc4`. Every path reaching the copy
passes the init. **Clean.**

Third site, function `0x8b47e1c0`:

```
4451: ffffffff8b47e1c9:	48 81 ec 08 04 00 00 	sub    $0x408,%rsp
4460: ffffffff8b47e1f1:	4c 8d b5 e8 fb ff ff 	lea    -0x418(%rbp),%r14
4461: ffffffff8b47e1f8:	be f8 03 00 00       	mov    $0x3f8,%esi
4463: ffffffff8b47e200:	e8 eb ad 79 ff       	call   ffffffff8ac18ff0   ; bzero(-0x418, 0x3f8)
4470: ffffffff8b47e21f:	ba f8 03 00 00       	mov    $0x3f8,%edx
4471: ffffffff8b47e224:	4c 89 f7             	mov    %r14,%rdi
4472: ffffffff8b47e227:	48 89 de             	mov    %rbx,%rsi
4473: ffffffff8b47e22a:	e8 a1 af 79 ff       	call   ffffffff8ac191d0
```

0x3f8 zeroed and 0x3f8 copied with no fill in between: the payload is entirely zeros. **Clean**
(an "empty struct out" idiom, not a leak).

Observation (INFERRED, not a leak): the destination of site #4 is `[uap+0x10] + r14*0x68` with a
signed bound check `cmp 0x8(%rax),%r14d ; jge` at `8b47e080`. A negative index would pass that
check and make the destination `base - k*0x68` — still a *user* address after the helper's 47-bit
mask, so it writes inside the caller's own address space and cannot touch kernel memory. Out of
class; recorded so the next auditor does not re-derive it as a leak.

### F5 — 626 `opmc_get_hw`: 8-byte RDMSR result

`results/kernel_handlers/asm/sys_626.asm`:

```
3329: ffffffff8afc4f8c:	0f 32                	rdmsr
3335: ffffffff8afc4f9e:	48 09 c2             	or     %rax,%rdx
3336: ffffffff8afc4fa1:	48 89 95 d8 fe ff ff 	mov    %rdx,-0x128(%rbp)
3343: ffffffff8afc4fc3:	48 8d bd d8 fe ff ff 	lea    -0x128(%rbp),%rdi
3344: ffffffff8afc4fca:	ba 08 00 00 00       	mov    $0x8,%edx
3346: ffffffff8afc4fd2:	e8 f9 41 c5 ff       	call   ffffffff8ac191d0
```

8 bytes written, 8 bytes copied. The MSR-number range check (`cmp $0x3,%ebx` / `ja`, bases
`0xc0010241` / `0xc0010189`) is the subject of `docs/TIER1_CLAIMS_4_8_AUDIT.md` claim 7 and is
not re-litigated here. **Clean** for this class.

### F6 — 641 `get_cpu_usage_proc` (and 627 `get_cpu_usage_all`): 0x38 struct zeroed at entry

`results/kernel_handlers/asm/sys_641.asm`:

```
3433: ffffffff8ae62e17:	0f 84 6e 01 00 00    	je     ffffffff8ae62f8b   ; -> mov $0x4e,%eax ; jmp epilogue
3434: ffffffff8ae62e1d:	e8 be fe ff ff       	call   ffffffff8ae62ce0
3435: ffffffff8ae62e22:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
3436: ffffffff8ae62e26:	be 38 00 00 00       	mov    $0x38,%esi
3437: ffffffff8ae62e2b:	e8 c0 61 db ff       	call   ffffffff8ac18ff0   ; bzero(-0x68, 0x38)
3575: ffffffff8ae63092:	89 45 98             	mov    %eax,-0x68(%rbp)
3577: ffffffff8ae63099:	89 45 9c             	mov    %eax,-0x64(%rbp)
3582: ffffffff8ae630ae:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
3585: ffffffff8ae630ba:	e8 11 61 db ff       	call   ffffffff8ac191d0   ; len 0x38
3620: ffffffff8ae63149:	89 45 98             	mov    %eax,-0x68(%rbp)
3625: ffffffff8ae6315e:	48 8d 7d 98          	lea    -0x68(%rbp),%rdi
3628: ffffffff8ae6316a:	e8 61 60 db ff       	call   ffffffff8ac191d0   ; len 0x38
```

The 0x38-byte struct spans `-0x68 .. -0x31`; the canary is at `-0x30` (`cmp -0x30(%rbp),%rcx`
at `8ae6317a`), so the copy stops exactly one byte short of it. Both sites are reached only after
the entry bzero. The second path writes 4 of the 56 bytes, so 52 bytes are entry zeros; the fields
at `-0x60/-0x58/-0x50/-0x48/-0x40/-0x38` are computed once before the per-record path and reused
for every record (kernel-derived, same object — a stale-field question, not a stack leak). **Clean**
for this class.

### F7 — 638 `utc_to_localtime` / 639 `localtime_to_utc`: 8 / 0x10 / 4, fully written

638, `results/kernel_handlers/asm/sys_638.asm`:

```
3346: ffffffff8b07e652:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
3351: ffffffff8b07e66e:	48 89 75 d8          	mov    %rsi,-0x28(%rbp)
3352: ffffffff8b07e672:	48 89 7d d0          	mov    %rdi,-0x30(%rbp)
3412: ffffffff8b07e737:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
3421: ffffffff8b07e75b:	48 8d 7d c8          	lea    -0x38(%rbp),%rdi
3422: ffffffff8b07e75f:	ba 08 00 00 00       	mov    $0x8,%edx
3424: ffffffff8b07e767:	e8 64 aa b9 ff       	call   ffffffff8ac191d0
3435: ffffffff8b07e790:	48 8d 7d d0          	lea    -0x30(%rbp),%rdi
3436: ffffffff8b07e794:	ba 10 00 00 00       	mov    $0x10,%edx
3438: ffffffff8b07e79c:	e8 2f aa b9 ff       	call   ffffffff8ac191d0
3449: ffffffff8b07e7c5:	48 8d 7d c4          	lea    -0x3c(%rbp),%rdi
3450: ffffffff8b07e7c9:	ba 04 00 00 00       	mov    $0x4,%edx
3452: ffffffff8b07e7d1:	e8 fa a9 b9 ff       	call   ffffffff8ac191d0
```

* `-0x38`: written at `8b07e737` before the `test %r14,%r14` at `8b07e73f`, so it is defined
  on the path that reaches the copy;
* `-0x30/-0x28`: the 16-byte record pair is loaded from the table at `8b07e664`/`8b07e669`
  (`mov -0x10(%rsi,%rcx,1),%rdi` / `mov -0x8(%rsi,%rcx,1),%rsi`) and stored at
  `8b07e66e`/`8b07e672`, i.e. before the branch at `8b07e676`; every path to `8b07e79c`
  passes both stores;
* `-0x3c`: zero at `8b07e652` on entry to the block, then conditionally overwritten.

639 (`results/kernel_handlers/asm/sys_639.asm`) has the same three sizes: `-0x3c` is zeroed at
`8b07e82b` (entry), `-0x38` is computed at `8b07ea53`, and `-0x30/-0x28` are written on all
three predecessor paths (`8b07e956/95b`, `8b07e992/996`, `8b07e9c1/9c5`). The record index
bounds are `docs/TZ_TABLE_638_14_10.md`'s subject and are not re-derived here; the byte-level
conclusion is that all 0x10 bytes of the record are defined before the copy. **Clean.**

## 5. Ranked residual risk (closest misses — none is a bug today)

Ranked by "how little would have to change for a real stack leak", so a future firmware audit can
start at the top.

| rank | site | why it is the closest | what would have to change |
|---|---|---|---|
| 1 | 634 `thr_get_ucontext` — `0x4c0` from `-0x530` | largest copy in the set (1216 bytes) against the smallest meaningful fill (the ucontext body at `-0x4f0`); the user gets 0x480 zeros *only* because of the `bzero 0x500` | drop or move the bzero, shrink `mov $0x500,%esi`, or raise `0x4c0` toward `0x500` and the tail includes the canary at `-0x30` |
| 2 | `0x8b47e1c0` — `0x3f8` from `-0x418` | copies 1016 bytes with **no** fill at all; safe only while the bzero is the sole initialiser | add a partial-fill path that bypasses `8b47e200`, or remove the bzero |
| 3 | 642 body — `0x68` from `-0x98` | 0x48 of the 0x68 bytes are zeros; the 0x20 memcpy is the only content | raise the memcpy length past 0x20, or move the copy above the bzero |
| 4 | 641 body — `0x38` from `-0x68`, second path writes 4 bytes | 52 of 56 bytes depend on a single entry bzero executed once per call (not per record) | hoist the bzero out of the function, or move the copy above it |
| 5 | 616 `thr_get_name` — `strnlen+1` | the only data-dependent length; safe because 0x1f == 0x20-1 | `mov $0x1f,%esi` → larger, or a shorter memcpy, and the tail of the 0x20 buffer leaves the frame |

## 6. What a real partial-init leak would look like here

To be a leak, the corpus would have to show one of:

1. a `call 8ac191d0` whose `rdi` points at a frame slot that no preceding store covers inside
   the copied `edx` range — e.g. `lea -0x100(%rbp),%rdi` with a fill of only `-0x100..-0xe0`
   and `mov $0x80,%edx`;
2. a copy length exceeding the zero-fill: `mov $0x100,%esi` (bzero) with `mov $0x140,%edx`
   (copy), which would put the canary and saved registers into the user buffer;
3. a length loaded from memory (`mov 0x10(%rbx),%edx`) instead of an immediate, letting the caller
   choose how far past the filled structure the copy runs;
4. `bzero` on a *different* frame slot than the copy source (a plausible typo: `lea -0x98` for
   the fill, `lea -0x90` for the copy).

None of the 15 sites matches any of the four: 15/15 sources are the same slot as their fill,
0/15 lengths exceed their fill, 0/15 lengths are memory-sourced, and every fill is >= the copy.

## 7. Adjacent shapes deliberately excluded

* **Inline copies.** A scan of all 145 asm windows for `stac`/`clac`/`rep movs` finds only the
  helper dumps themselves plus `sys_640.asm` (`8b4513f6`, `8b45163c`:
  `rep movsq (%rsi),(%rdi)`, 0xb qwords from `-0x70`/`-0x88` into the kernel table at
  `0xffffffff8e5b6a60 + idx*0x58`) and `sys_558_deep.asm`. 640's copies are kernel→kernel (no
  `stac`, destination is a kernel global), so they cannot hand bytes to userland directly; they
  are noted because a partially filled 0x58-byte record written into that table would be a
  second-order leak if another syscall ever reports the table.
* **Other copy helpers.** 640 also calls `0x8ac19be0` (`8b4515b5`: `lea -0x8c(%rbp),%rdi`,
  `mov $0x4,%edx`, `rsi = user+index`) — copyin-shaped by register role (INFERRED). It reads
  *from* userland, so it cannot leak kernel stack; not audited further.
* **The timezone table index** — see `docs/COPYOUT_TABLE_INDEX_AUDIT.md`; 0 OOB reads proven there.

## 8. Limits

* No live measurement. Presence/return values are quoted from `docs/SYSENT_PRESENCE_14_10.md`; the
  13.60 bodies are not proof that 14.10 ships byte-identical handlers.
* 15 call instructions is the count of direct `call ffffffff8ac191d0` in the 19 committed
  windows. An indirect call through a function pointer, or a call site in a handler window not
  committed to this corpus, would not be visible. The corpus holds 145 of the ~676 slots.
* The `bzero` helper's stack-bounds sanity path (`call 0x258fd0` when `dst+len < rsp`) is
  treated as a panic/warn; its exact semantics are not needed for the conclusion.
* All 19 numbers audited here are `present` on 14.10 (`616 -1, 617 0, 618 -1, 620 0, 623 -1,
  624 3377, 625 -1, 626 -1, 627 -1, 628 -1, 632 -1, 633 -1, 634 -1, 636 -1, 637 -1, 638 0, 639 0,
  641 -1, 642 -1`). Had a partial initialisation existed in any body, it would have been reachable
  at uid 1 on 14.10, so the clean result is not an artefact of unreachable slots.
