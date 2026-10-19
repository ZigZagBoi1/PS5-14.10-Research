# Tier-1 claims 4-8: audit against `docs/dumps_13.60/`

Scope: `docs/VERIFIED_HANDLER_ANALYSIS.md:123-151`, claims 4-8. Every address
below is an RVA into `docs/dumps_13.60/kernel_text.bin` (15,132,096 bytes =
`0xe6e5c0`). Byte strings are hex as they appear in that file. Static only:
no console was contacted and no 14.10 artifact exists in this repository.

## Verdict table

| # | Claim | Verdict | One-line evidence |
|---|---|---|---|
| 4 | sys 622 device control: 95% unchecked (534 vs 27); 0x000-0x0FF bypasses credentials via unsigned underflow in the bitmask index | **PARTIAL** | `27 checked` reproduces exactly (`0x7dce0e` bitmap: 22 + `0x7dd00b` bitmap: 2 + 3 specials); `534` has no derivable denominator and the bit index never underflows — the gate's own `ja 0x7dce4f` sends every cmd < 0x100 to the no-auth block before `bt` runs |
| 5 | sys 588 DMEM page attribute: no priv_check, no ucred, no auth ID; only vm_map bounds; EACCES treated as proceed | **CONFIRMED** | body `0xabc5f0-0xabc70e`: 5 direct calls, none to `0xb2bb00` (priv_check) or any `0x609xxx` auth-id predicate, no `+0x5d4/+0x5d8` read; `0xabc6d1 cmp eax,0xd; je 0xabc6da` proceeds to `0x2d2e50` |
| 6 | sys 639/638 memory region info: kernel region base/size/offset to any caller, binary search, direct copyout | **PARTIAL** | binary search and unguarded copyout confirmed (`0x6be62a`, `0x6be767/0x6be79c/0x6be7d1`); the record is a 16-byte `{key, offset, correction}` delta entry, not a region triple, and `docs/sysent-names-13.60.csv` names the pair `utc_to_localtime`/`localtime_to_utc` |
| 7 | sys 626 RDMSR: `0xC0010241+2*index` and `0xC0010189+2*index`, 6+ sites, no permission check | **PARTIAL** | both formulas exact (`0x604f86 or ecx,0xc0010241`, `0x604f90 add ecx,0xc0010189`); 2 RDMSR in the body, 6 reachable including helper `0x605000`, 46 in the committed 8192-byte window — "6+" conflates those three counts |
| 8 | sys 629 jail bypass: `cmpq $0x1,(%rsi); je 0xb8` reaches the internal function, skipping five steps and credential check `0xcecc90` | **PARTIAL** | `48 83 3e 01` at `0x91c64b` and `0f 84 a0 00 00 00` at `0x91c652` → `0x91c6f8` = body+0xb8, and all five steps are skipped; `0xcecc90` is table data, is the target of no branch and is embedded nowhere, so the cited credential check does not exist |

Reproduce: `python tools/tier1_claims_audit.py` (table),
`--check` (exit 1 on drift), `python -m unittest tools.test_tier1_claims_audit`.

## Resolution used throughout

`sysent_index.json` gives each syscall's slot RVA; the 8 bytes there are
`E9 rel32` and the body is `slot + 5 + rel32` with base 0. The sysent table's
own RVA is `15132096`, the artifact's length, so the table begins where the
dump ends and **every data table the handlers index is outside it**.
That single fact decides several of the verdicts below.

| sys | narg | slot | slot bytes | body | extent used here |
|---|---|---|---|---|---|
| 588 | 3 | `0x265e08` | `e9e3678500cccccc` | `0xabc5f0` | `0xabc5f0-0xabc70e` (one function) |
| 622 | 6 | `0x265e98` | `e9a36e5700cccccc` | `0x7dcd40` | dispatcher `0x7dcd40-0x7ddba3` |
| 626 | 5 | `0x265eb8` | `e933ee3900cccccc` | `0x604cf0` | `0x604cf0-0x604ff5` + helper `0x605000-0x6050c7` |
| 629 | 4 | `0x265ed0` | `e96b676b00cccccc` | `0x91c640` | `0x91c640-0x91c73d` |
| 638 | 4 | `0x265f10` | `e9ab864500cccccc` | `0x6be5c0` | `0x6be5c0-0x6be7f7` |
| 639 | 5 | `0x265f18` | `e9e3884500cccccc` | `0x6be800` | `0x6be800-0x6beb13` |

Extents are not recorded in the dump. The rule used here: a body ends at the
first `ret`/`ud2`/unconditional `jmp` whose following bytes are `nop`/`int3`
padding and then a prologue (`55 48 89 e5`) or a known sysent body start.
This matters: the "next sysent start" rule alone gives 622 31,440 bytes with
53 prologues inside it, 626 747,904 bytes with 1,858 prologues, and 639
148,928 bytes with 583. Those regions are handler clusters, not bodies.

Each extent therefore ends after the stack-canary failure block
(`call 0x6fd6b0; ud2`), so that call appears in every call list below and is
not on any normal return path.

---

## Claim 4 — sys 622 device control

**Verdict: PARTIAL.** The 27-checked count is exact. The 534 is not derivable
from this artifact, and the stated mechanism ("unsigned underflow in bitmask
index") is not what the code does.

### The gate

```
0x7dcdf5  4181fe70020000        cmp r14d, 0x270
0x7dcdfc  0f8f14010000          jg  0x7dcf16        ; special-command ladder
0x7dce02  418d8600ffffff        lea eax, [r14 - 0x100]
0x7dce09  83f833                cmp eax, 0x33
0x7dce0c  7741                  ja  0x7dce4f        ; <-- no-auth block
0x7dce0e  48b9d5000000ff8f0f00  movabs rcx, 0xf8fff000000d5
0x7dce18  480fa3c1              bt  rcx, rax
0x7dce1c  0f83e9010000          jae 0x7dd00b        ; bit clear -> second bitmap
0x7dce22  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]   ; ucred
0x7dce29  e8e2c2e2ff            call 0x609110       ; auth-id == 0x4800000000000007
0x7dce2e  83f801                cmp eax, 1
0x7dce31  741c                  je  0x7dce4f
0x7dce33  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dce3a  e801c2e2ff            call 0x609040       ; auth-id == 0x4800000000000006
0x7dce41  b84e000200            mov eax, 0x8002004e ; EPERM-equivalent
0x7dce46  83f901                cmp ecx, 1
0x7dce49  0f853cffffff          jne 0x7dcd8b
0x7dce4f  488d7d90              lea rdi, [rbp - 0x70]              ; memset + dispatch
```

`0x609110` and `0x609040` are one-instruction predicates over
`[rdi+0x58]` (the auth-id field; cf. claim 3's `cr_sceAuthId` at
`docs/VERIFIED_HANDLER_ANALYSIS.md:205`): `movabs rcx, imm; cmp [rdi+0x58],
rcx; sete al`. They are not `priv_check` (`0xb2bb00`).

### What the bitmap admits

`0xf8fff000000d5` has 22 bits set within the 0x34-wide window
(0,2,4,6,7,32-43,47-51). Bit *n* corresponds to command `0x100+n`, so 22
commands in `0x100-0x133` reach an auth call and 30 do not. Bits above 0x33
are outside the window and unreachable.

The second bitmap:

```
0x7dd00b  48b90000000000600000    movabs rcx, 0x600000000000
0x7dd015  480fa3c1              bt  rcx, rax
0x7dd019  0f8330feffff          jae 0x7dce4f        ; bit clear -> no auth
0x7dd01f  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dd026  e8e5c0e2ff            call 0x609110
0x7dd034  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dd03b  e890c0e2ff            call 0x6090d0       ; auth-id in {0x22,0x2e,0x101f}
```

Bits 45 and 46 are set, i.e. commands **0x12d and 0x12e** — not "0x12D and
0x130" as the claim's supporting analysis states; `0x130` is bit 48, which is
already set in the first bitmap and is therefore checked there.

The three specials `0x271`, `0x372`, `0x473` take the strictest gate:

```
0x7dcf16  4181fe71020000        cmp r14d, 0x271
0x7dcf1f  4181fe72030000        cmp r14d, 0x372
0x7dcf28  4181fe73040000        cmp r14d, 0x473
0x7dcf35  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dcf3c  e8cfc1e2ff            call 0x609110
0x7dcf4a  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dcf51  e87ac1e2ff            call 0x6090d0
0x7dcf5f  488bbb40010000        mov rdi, qword ptr [rbx + 0x140]
0x7dcf66  e83501a9ff            call 0x26d0a0       ; jmp 0x609150 -> [rdi+0x58]==0x4800000000000010
```

22 + 2 + 3 = **27 checked**. The claim's `27` is exact. There are exactly six
auth-helper call sites in the dispatcher (`0x7dce29`, `0x7dce3a`, `0x7dcf3c`,
`0x7dcf51`, `0x7dd026`, `0x7dd03b`), and no `priv_check` call anywhere in
`0x7dcd40-0x7e4810`.

### Where the "underflow" is

There is no underflowing bit index. For `cmd < 0x100`,
`eax = cmd - 0x100` wraps to `0xffffff00..0xffffffff`, `cmp eax, 0x33`
followed by `ja` fires, and control reaches `0x7dce4f` — the no-auth block —
**before** `bt rcx, rax` at `0x7dce18` executes. The `bt` operand is never
formed for those commands. So the effect the claim describes (the whole
`0x000-0x0FF` range is not credential-gated) is right, and the mechanism it
states is wrong: this is an out-of-range rejection of the bitmap gate, not an
index underflow inside it. A test that "simulates the underflow" would be
modelling an instruction that does not run on that path.

### Why 534 is not derivable

`0x7dce4f` is the common dispatch block: `memset([rbp-0x70], 0, 0x40)` at
`0x7dce4f-0x7dce58`, then a ladder of `cmp r14d` at `0x7dce62` (0x301),
`0x7dce6b` (0x3ff), `0x7dceca` (0x133), `0x7dcf77` (after `add r14d,
-0x201`, range 0x70), `0x7dd045` (0x372) and `0x7dd081` (0x520), each
followed by an indirect `jmp` through a signed-offset table. Those tables are
at RVAs `0x1780c8c`, `0x178057c`, `0x1780a4c` and `0x1780c17` (computed from
`lea rdx, [rip+disp]` at `0x7dce8b`, `0x7dceda`, `0x7dcf81`, `0x7dcfd3`) —
all past the end of the 15,132,096-byte artifact. The command→case mapping is
therefore unavailable, so the number of commands that reach a case at all, and
hence any "unchecked" count, cannot be computed from this dump. The
dispatcher's own case bodies are present (63 of them call the shared
copyin-and-dispatch helper at `0x7ddbb0`), but a case body is not a command.

`534 + 27 = 561` is an arithmetic total, not an observable set. It is
recorded as unresolved rather than accepted.

### What this does not establish

* That any specific command in `0x000-0x0FF` dispatches to a handler that
  performs an operation: the dispatch tables are outside the artifact.
* That the un-gated cases do anything an unprivileged process can observe —
  `results/.../sys_622_deep.md` describes copyin-then-dispatch cases, and the
  copyin helper `0x7ddbb0` was not fully resolved here.
* That `0x520`'s direct call to `0x29a570` is unchecked beyond the dispatcher
  (it is reached at `0x7dd098` with no auth call on that path).
* Nothing about 14.10. Probe 55c recorded `ret=0` with `buf[0]=0x800E0001` for
  every tested command; that is a different artifact and neither confirms nor
  refutes this reading.

---

## Claim 5 — sys 588 DMEM page attribute modify

**Verdict: CONFIRMED.** Body `0xabc5f0-0xabc70e` (286 bytes, one function, one
canary check at `0xabc6ee`). All five direct calls:

```
0xabc663  e878dd1500   call 0xc1a3e0    ; gs:0 log/assert prelude
0xabc676  e885d279ff   call 0x259900    ; copyin 0x20 bytes
0xabc6cc  e89f30d6ff   call 0x81f770    ; vm_map attribute modify
0xabc6e7  e8646781ff   call 0x2d2e50    ; apply attributes
0xabc707  e8a40fc4ff   call 0x6fd6b0    ; canary failure (not on the normal path)
```

No `call 0xb2bb00` (priv_check). No call to any `0x609xxx` auth-id predicate.
No `[reg + 0x5d4]` / `[reg + 0x5d8]` read (the ucred fields claim 20 of
`docs/VERIFIED_HANDLER_ANALYSIS.md:224` calls the auth hierarchy). The only
privilege-shaped thing in the body is the log prelude.

### The validation that is there

```
0xabc623  4c396b20        cmp qword ptr [rbx + 0x20], r13   ; map->start vs addr
0xabc627  0f87c1000000    ja  0xabc6ee                    ; start > addr -> EINVAL
0xabc62d  488b4b28        mov rcx, qword ptr [rbx + 0x28]   ; map->end
0xabc631  4c8b7e08        mov r15, qword ptr [rsi + 8]      ; uap[1] = length
0xabc635  4c29e9          sub rcx, r13
0xabc638  0f96c2          setbe dl
0xabc63b  4c39f9          cmp rcx, r15
0xabc63e  0f92c1          setb cl
0xabc641  08d1            or  cl, dl
0xabc643  0f85a5000000    jne 0xabc6ee
0xabc66c  ba20000000      mov edx, 0x20
0xabc671  4c89f7          mov rdi, r14
0xabc676  e885d279ff      call 0x259900                  ; copyin uap[2], 0x20 bytes
0xabc67b  85c0            test eax, eax
0xabc67d  756f            jne 0xabc6ee
```

So "only vm_map bounds validation" is close but not exact: the body also
copies 0x20 bytes in from `uap[2]` and requires that copyin to return 0, and
it applies two further range gates derived from the address:

```
0xabc6a8  4183fd0e                 cmp r13d, 0xe          ; addr >> 0x28
0xabc6ac  772c                     ja  0xabc6da           ; > 14 -> skip the check
0xabc6ae  48b80100000000080000     movabs rax, 0x80000000001
0xabc6b8  4939c7                   cmp r15, rax           ; computed end
0xabc6bb  721d                     jb  0xabc6da           ; below 8 GB -> skip
```

The `ja 0xabc6da` / `jb 0xabc6da` targets are the proceed block, so both
gates fail *open*.

### The EACCES path

```
0xabc6cc  e89f30d6ff   call 0x81f770      ; returns 0, 0xd, or another errno
0xabc6d1  83f80d       cmp  eax, 0xd      ; 13 = EACCES
0xabc6d4  7404         je   0xabc6da      ; proceed
0xabc6d6  85c0         test eax, eax
0xabc6d8  7514         jne  0xabc6ee      ; any other error -> return it
0xabc6da  488d4db0     lea  rcx, [rbp - 0x50]
0xabc6de  4889df       mov  rdi, rbx
0xabc6e1  4c89f6       mov  rsi, r14
0xabc6e4  4c89fa       mov  rdx, r15
0xabc6e7  e8646781ff   call 0x2d2e50      ; apply the attributes anyway
0xabc6ec  31c0         xor  eax, eax      ; return 0
```

`0x81f770` returns `0xd` at `0x81f8e0` (`mov eax, 0xd`) on its
"no mapping found" path and `0` at `0x81f8a1`. The errno reading is an
inference, but a well-corroborated one: the same dump uses `0x16` (22 EINVAL),
`0x22` (34 ERANGE) and `0x2d` (45 EOPNOTSUPP) as return codes elsewhere
(`0x604f28`, `0x6be6c4`, `0x91be72`), which is the FreeBSD numbering. The
claim's "treats EACCES as proceed anyway" is therefore exact for `0xd`.

Three callees were disassembled in full and contain no privilege call:
`0x81f770-0x81f8f4` (calls `0x7cc240`, `0x7ad1d0`, `0x7ce280`, `0x7ad1f0`),
`0x2d2e50-0x2d2ee0` (calls `0xc4bb20`, `0x4c6a00`, `0x2d1e50`), and
`0x2d1e50-0x2d1fc4` (calls `0x2c6c40`, `0x2cb4e0`, `0x957b70`, `0x2c8910`,
`0x2d2ae0`, `0x2cb770`, `0x6fd6b0`). None calls `0xb2bb00` or any
`0x609xxx` predicate.

### What this does not establish

* That the attributes are actually changed: the callee `0x2d1e50` was only
  read to its extent boundary, and `0x5948e0` (reached from `0x81f770` via a
  tail jump) was not resolved.
* That any of this permits a W^X flip. The claim's conditional ("if the
  underlying function allows W^X flip") is the whole question, and this
  artifact does not answer it.
* That `0x81f770`'s `0xd` is EACCES by anything but errno convention.
* Nothing about 14.10. Two 14.10 probes do exist and record `588(...) = 0`
  for a GPU mmap region with `prot=7`
  (`results/54d_dmem_page_flip_20261018_091257.txt`,
  `results/54l_rwx_verify_20261018_091853.txt`), and 54l's post-call check only
  re-reads page *contents*. That is a separate artifact: it does not show the
  protection changed, and its agreement with the fail-open path here is not
  evidence that 14.10 runs this code.

---

## Claim 6 — sys 639/638 memory region info

**Verdict: PARTIAL.** No permission check, a binary search, and direct
copyout are all real. The data is not memory-region data.

### Shape of both handlers

`638` = `0x6be5c0-0x6be7f7`, `639` = `0x6be800-0x6beb13`. Both are single
functions (one prologue each), both use the same globals and the same copy
helper:

| global | RVA | reached from |
|---|---|---|
| record table base | `0x3915920` | `638` lea `0x6be603`, `639` lea `0x6be85d` |
| record count | `0x3917920` | `638` `0x6be5f0`, `639` `0x6be837` |
| mode | `0x3a705af` | `638` `0x6be65d`, `639` `0x6be715` |

All three are past `0xe6e5c0`, so **the table contents and the count are not
in the artifact**. `count == 0` returns `0x22` (ERANGE) after unlocking
(`0x6be6b4`, `0x6be961`).

The search is an upper-bound binary search over `[1, count)` with 16-byte
records:

```
0x6be62a  448d0c17        lea  r9d, [rdi + rdx]
0x6be631  41c1e81f        shr  r8d, 0x1f
0x6be635  4501c8          add  r8d, r9d
0x6be638  41d1f8          sar  r8d, 1
0x6be63b  4d63c8          movsxd r9, r8d
0x6be63e  49c1e104        shl  r9, 4           ; 16-byte stride
0x6be642  49393409        cmp  qword ptr [r9 + rcx], rsi
0x6be646  7ed8            jle  0x6be620
```

`639` does the same with the record's offset and correction added into the
compared threshold (`0x6be8b3`-`0x6be8c2`, overlap test at `0x6be90c`).

Copyout, three optional destinations, first failure returns:

```
0x6be75b  488d7dc8        lea  rdi, [rbp - 0x38]
0x6be75f  ba08000000      mov  edx, 8
0x6be767  e864aab9ff      call 0x2591d0     ; copyout 8
0x6be790  488d7dd0        lea  rdi, [rbp - 0x30]
0x6be794  ba10000000      mov  edx, 0x10
0x6be79c  e82faab9ff      call 0x2591d0     ; copyout 16
0x6be7c5  488d7dc4        lea  rdi, [rbp - 0x3c]
0x6be7c9  ba04000000      mov  edx, 4
0x6be7d1  e8faa9b9ff      call 0x2591d0     ; copyout 4
```

`639` mirrors this: `mov edx, 8` at `0x6bea7b` then `call` at `0x6bea83`,
`mov edx, 0x10` at `0x6beab0` then `0x6beab8`, `mov edx, 4` at `0x6beae5`
then `0x6beaed`. No `priv_check`, no `0x609xxx` predicate in either
body, and no credential read: the wrapper never touches `[rdi+0x140]`.

### What the record contains

Sixteen-byte stride, one signed qword key and two signed dword deltas:

```
0x6be642  49393409        cmp qword ptr [r9 + rcx], rsi        ; key
0x6be664  488b7c0ef0      mov rdi, qword ptr [rsi + rcx - 0x10] ; key copy
0x6be669  488b740ef8      mov rsi, qword ptr [rsi + rcx - 8]    ; offset+correction
```

and the 8-byte result is arithmetic on the input, not a copied pointer:

```
0x6be72d  480303          add rax, qword ptr [rbx]        ; input + offset
0x6be730  48634dd8        movsxd rcx, dword ptr [rbp - 0x28]
0x6be734  4801c8          add rax, rcx                    ; + correction
...
0x6bea46  486355d8        movsxd rdx, dword ptr [rbp - 0x28]
0x6bea4a  488b0b          mov rcx, qword ptr [rbx]        ; input
0x6bea4d  4801c2          add rdx, rax
0x6bea50  4829d1          sub rcx, rdx                    ; input - offset - correction
```

`docs/sysent-names-13.60.csv` names 638 `utc_to_localtime` and 639
`localtime_to_utc`. That is a name-map cross-reference, not symbol evidence,
but it agrees with the shape: a sorted table of `{epoch key, offset,
correction}` entries and an inverse pair of conversions. Nothing in either
body reads a size, a protection, or a base address, and no field is copied
out untransformed as a pointer.

So: "returns kernel memory region base/size/offset" is **refuted** by the
record shape. "No permission check" and "copies out directly" are confirmed.
Whether the table happens to contain kernel VAs in its key field is
**unresolved**: the table is outside the artifact, and the keys are compared
as signed integers against the caller's input, which is what a time key looks
like and not what a VA looks like.

### What this does not establish

* The table's contents, its writer, or whether the count is ever attacker
  influenced. All are outside the artifact.
* That the name map is correct. It is a committed CSV, not a recovered
  symbol table.
* Anything about 14.10. Probe 54f section C recorded `ret=-1` for every
  tested range on 14.10; that is a separate artifact and is not evidence for
  or against this reading.

---

## Claim 7 — sys 626 RDMSR

**Verdict: PARTIAL.** Both MSR formulas are exact. The "6+ RDMSR sites"
number is right only under one of three possible readings, and the claim does
not say which.

### The body

`0x604cf0-0x604ff5`, narg=5, `command` at `[rsi]`, `domain` at `[rsi+8]`,
`index` at `[rsi+0x10]`, two output pointers at `[rsi+0x18]`/`[rsi+0x20]`.

```
0x604e4d  8b0e            mov  ecx, dword ptr [rsi]
0x604e4f  ffc9            dec  ecx
0x604e51  83f905          cmp  ecx, 5
0x604e54  0f87ce000000    ja   0x604f28          ; return 22
0x604e5a  488d155be71101  lea  rdx, [rip + 0x111e75b]
0x604e61  b806000000      mov  eax, 6
0x604e66  48630c8a        movsxd rcx, dword ptr [rdx + rcx*4]
0x604e6a  4801d1          add  rcx, rdx
0x604e6d  ffe1            jmp  rcx
```

Commands 1-6, dispatch through a signed-offset table at RVA `0x17235bc` —
past the end of the artifact. Which command reaches the RDMSR block is
therefore **unresolved**; the committed `sys_626.md` says the same.

The RDMSR block and its guard:

```
0x604f32  4989f7            mov  r15, rsi
0x604f35  e8d6580d00        call 0x6da810           ; returns global & ~0xf
0x604f3a  3dc00f8400        cmp  eax, 0x840fc0
0x604f41  e8ca580d00        call 0x6da810
0x604f46  b907000000        mov  ecx, 7             ; hw_max = 7 if in range
0x604f4b  3de00f8400        cmp  eax, 0x840fe0
0x604f52  b903000000        mov  ecx, 3             ; else 3
0x604f57  41837f0800        cmp  dword ptr [r15 + 8], 0     ; domain == 0
0x604f5c  b816000000        mov  eax, 0x16
0x604f61  7574              jne  0x604fd7
0x604f63  49837f1800        cmp  qword ptr [r15 + 0x18], 0  ; out1 != NULL
0x604f6b  746a              je   0x604fd7
0x604f6d  48837e2000        cmp  qword ptr [rsi + 0x20], 0
0x604f72  0f95c2            setne dl                        ; out2 != NULL
0x604f75  39cb              cmp  ebx, ecx                   ; index vs hw_max
0x604f77  0f97c1            seta cl                         ; index > hw_max
0x604f7a  08d1              or   cl, dl
0x604f7c  7559              jne  0x604fd7                 ; either -> EINVAL
0x604f7e  8d0c1b            lea  ecx, [rbx + rbx]           ; 2*index
0x604f81  83fb03            cmp  ebx, 3
0x604f84  770a              ja   0x604f90
0x604f86  81c9410201c0      or   ecx, 0xc0010241
0x604f8c  0f32              rdmsr
0x604f8e  eb08              jmp  0x604f98
0x604f90  81c1890101c0      add  ecx, 0xc0010189
0x604f96  0f32              rdmsr
0x604f98  89c0              mov  eax, eax
0x604f9a  48c1e220          shl  rdx, 0x20
0x604f9e  4809c2            or   rdx, rax
```

So the claim's two formulas are exact for the admitted index range:
`index <= 3` reads `0xC0010241 + 2*index` (as an `or`, equivalent there),
`index > 3` reads `0xC0010189 + 2*index`. With `hw_max = 7` that is
`0xC0010241/43/45/47` and `0xC0010191/93/95/97`; with `hw_max = 3` only the
first four.

### Counting the sites

Three different numbers are defensible, and the claim's "6+" does not say
which:

| count | what it counts | evidence |
|---|---|---|
| **2** | RDMSR in the handler body | `0x604f8c`, `0x604f96` |
| **6** | RDMSR reachable from 626 | the 2 above plus 4 in the cmd-1 helper `0x605000` (`0x605043`, `0x60506e`, `0x60508a`, `0x6050a0`), called at `0x604ea9` |
| **46** | `rdmsr` mnemonics in `results/kernel_handlers/asm/sys_626.asm` | spread `0x604f8c-0x6055c9`, i.e. across neighbouring handlers; sys 625's body starts at `0x603c90` and the window is 8192 bytes |

The helper's MSR is a **third** formula, not either of the claim's two:

```
0x60503b  438d8c36310201c0   lea ecx, [r14 + r14 - 0x3ffefdcf]   ; 0xC0010231 + 2*index
0x605043  0f32               rdmsr
```

`-0x3ffefdcf` is `0xc0010231` mod 2^32. So "reading `0xC0010241+2i` and
`0xC0010189+2i`" describes the direct block only; a caller taking command 1
reads `0xC0010231+2i` instead.

### Permission

No `priv_check` call and no `0x609xxx` predicate call in the body. The
command selector's table is outside the artifact, so "no permission check"
is established for the block and **unresolved** for the dispatcher: one of
the six commands could be gated elsewhere and still reach the same block, and
this dump cannot show it.

### What this does not establish

* Which command number reaches the RDMSR block.
* What MSRs `0xC0010241` / `0xC0010189` / `0xC0010231` are. The claim calls
  them event-select and L3 performance-counter registers; the artifact has no
  naming evidence for that, and no vendor table is cited here.
* That the read value is user-visible without further checks: the 8-byte
  copyout goes through `0x2591d0` at `0x604fd2`, whose own validation was not
  audited here.
* Nothing about 14.10. Probes 54a2 and 54k recorded `ret=-1` for every tested
  index on 14.10; those are separate artifacts.

---

## Claim 8 — sys 629 jail bypass

**Verdict: PARTIAL.** The branch, its displacement, and every one of the five
skipped steps are exactly as claimed. The cited credential check does not
exist, and the fast path still enters a delegate that reads credential fields.

### The branch

Body `0x91c640-0x91c73d` (253 bytes), narg=4, uap in `rsi`:

```
0x91c64b  48833e01        cmp qword ptr [rsi], 1
0x91c64f  4989f6          mov r14, rsi
0x91c652  0f84a0000000    je  0x91c6f8          ; 0x91c6f8 - 0x91c640 = 0xb8
```

`cmp qword ptr [rsi], 1` is the same instruction as `cmpq $0x1,(%rsi)`, and
the target is body+0xb8. Both cited facts hold.

### What the fast path skips

```
0x91c658  4989ff          mov  r15, rdi
0x91c65b  488d35ae57c301  lea  rsi, [rip + 0x1c357ae]
0x91c662  bf00040000      mov  edi, 0x400
0x91c667  ba02000000      mov  edx, 2
0x91c66c  e8dfc42e00      call 0xc08b50            ; (1) 0x400-byte allocation request
0x91c671  4d8b26          mov  r12, qword ptr [r14]
0x91c674  65488b3c2500000000  mov rdi, qword ptr gs:[0]
0x91c67d  488d3500daa300  lea  rsi, [rip + 0xa3da00]
0x91c686  4889c3          mov  rbx, rax
0x91c689  e852dd2f00      call 0xc1a3e0
0x91c68e  ba00040000      mov  edx, 0x400
0x91c693  4c89e7          mov  rdi, r12
0x91c696  4889de          mov  rsi, rbx
0x91c699  31c9            xor  ecx, ecx
0x91c69b  e860d293ff      call 0x259900            ; (2) copyin the path, 0x400
0x91c6a0  85c0            test eax, eax
0x91c6a2  7576            jne  0x91c71a
0x91c6a4  803b2f          cmp  byte ptr [rbx], 0x2f ; (3) must start with '/'
0x91c6a7  41bc16000000    mov  r12d, 0x16
0x91c6ad  756e            jne  0x91c71d
0x91c6af  498bbf40010000  mov  rdi, qword ptr [r15 + 0x140]  ; ucred
0x91c6b6  e815ccceff      call 0x6092d0            ; (4) auth-id membership
0x91c6bb  85c0            test eax, eax
0x91c6bd  7479            je   0x91c738
0x91c6bf  488d35ce0df000  lea  rsi, [rip + 0xf00dce] ; literal, RVA 0x181d494
0x91c6c6  ba0c000000      mov  edx, 0xc
0x91c6cb  4889df          mov  rdi, rbx
0x91c6ce  e85d53fbff      call 0x8d1a30            ; (5) strncmp(path, literal, 12)
0x91c6d3  85c0            test eax, eax
0x91c6d5  7461            je   0x91c738
0x91c6d7  488d3da2849800  lea  rdi, [rip + 0x9884a2]
0x91c6de  488d0daf0df000  lea  rcx, [rip + 0xf00daf]
0x91c6e5  4c89fe          mov  rsi, r15
0x91c6e8  4889da          mov  rdx, rbx
0x91c6eb  e8b00eefff      call 0x80d5a0            ; diagnostic
0x91c6f0  41bc02000000    mov  r12d, 2
0x91c6f6  eb25            jmp  0x91c71d
```

All five steps the claim lists are on the skipped side of `je 0x91c6f8`:
allocation (`0x91c66c`), path copyin (`0x91c69b`), path validation
(`0x91c6a4`), the credential predicate (`0x91c6b6`), and the hardcoded
12-byte path comparison (`0x91c6ce`). The claimed sequence is real.

### The cited credential check

`0xcecc90` is not a function. It is a length field in a repeating 24-byte
table entry: `0xcecc88` holds `0xffffffff81090c50`, `0xcecc90` holds
`08 00 00 00 00 00 00 00`, `0xcecc98` holds `0xffffffff81ce7eb8`, and the
pattern repeats from `0xcecc70` to `0xcecd10` and beyond. The address is data
in a `{pointer, 8, pointer}` table, not code.
Nothing in the 15,132,096-byte text branches to it: a scan for `E8`/`E9`
rel32 targets and for its 4-byte and 8-byte immediate encodings returns zero
hits for all three. The address cannot be the skipped credential check,
because it is not code and is referenced nowhere.

The check that *is* skipped is `call 0x6092d0` at `0x91c6b6`. `0x6092d0`
compares `[rdi + 0x58]` (the auth-id field) against
`0x4800000010000004` through `0x4800000010000013` (a range test plus bitset
`0xe001`) and `0x4800000000001010`:

```
0x6092d4  488b4f58          mov  rcx, qword ptr [rdi + 0x58]
0x6092d8  48bafcffffefffffffb7  movabs rdx, 0xb7ffffffeffffffc
0x6092e7  4801ca            add  rdx, rcx
0x6092ea  4883fa0f          cmp  rdx, 0xf
0x6092ee  770b              ja   0x6092fb
0x6092f0  be01e00000        mov  esi, 0xe001
0x6092f5  480fa3d6          bt   rsi, rdx
0x6092f9  720f              jb   0x60930a
0x6092fb  48ba1010000000000048  movabs rdx, 0x4800000000001010
0x609305  4839d1            cmp  rcx, rdx
```

That is an auth-id membership test, the same family as the predicates in
claim 4, and it is a genuine credential check. The claim's mechanism
survives; its citation does not.

### The fast path is not check-free

```
0x91c6f8  31db            xor  ebx, ebx            ; buffer pointer = NULL
0x91c6fa  498b36          mov  rsi, qword ptr [r14] ; arg0, i.e. 1
0x91c6fd  418b5608        mov  edx, dword ptr [r14 + 8]
0x91c701  410fb74e10      movzx ecx, word ptr [r14 + 0x10]
0x91c706  458b4618        mov  r8d, dword ptr [r14 + 0x18]
0x91c70a  4883fe01        cmp  rsi, 1
0x91c70e  480f45f3        cmovne rsi, rbx          ; no-op: rsi is already 1
0x91c712  4531c9          xor  r9d, r9d
0x91c715  e886f5ffff      call 0x91bca0            ; delegate
0x91c71a  4189c4          mov  r12d, eax
0x91c71d  488d35ec56c301  lea  rsi, [rip + 0x1c356ec]
0x91c724  4889df          mov  rdi, rbx            ; NULL
0x91c727  e8c4c62e00      call 0xc08df0            ; free(NULL)
0x91c72c  4489e0          mov  eax, r12d
0x91c72f  5b              pop  rbx
```

`0x91bca0` is reached with the literal `1` as its path argument. It validates
flag bits (`0x91bcc7 test r15b,1; jne EINVAL`; `0x91bcd1 test r15d,
0xffdff1fc; jne EINVAL`), walks a name list comparing strings with `0x8d1a30`,
and reads credential fields:

```
0x91bde9  448b80c0050000  mov r8d, dword ptr [rax + 0x5c0]
0x91bdf6  448b88d0050000  mov r9d, dword ptr [rax + 0x5d0]
0x91bdcb  4181ff00002000  cmp r15d, 0x200000
0x91be11  4181ff00002000  cmp r15d, 0x200000
```

So "completely skipping ... credential check" is true of the wrapper's own
predicate and false as a statement about the call: the delegate reads
`proc+0x5c0` and `proc+0x5d0` and branches on `0x200000`. Whether those fields
gate the operation or merely select a variant is not settled here — the
delegate body was read only to `0x91c163`.

The delegate is also not shown to be a mount function. `docs/sysent-names-
13.60.csv` names 629 `physhm_open`, and the wrapper's first argument is either
`1` (this path) or a path string; the claim's "internal mount function" is an
interpretation the artifact does not carry.

### What this does not establish

* That `arg0 == 1` reaches a privileged operation. The delegate's gate on
  `0x200000` and its credential reads are the open question.
* That the hardcoded path literal (`RVA 0x181d494`, outside the artifact) is
  a jail path. Its bytes are not in the dump.
* That `0x91bca0` is a mount entry point. Only the name map and the wrapper's
  argument shape suggest it.
* Nothing about 14.10. Probe 54b recorded `ret=-1` for every tested argument
  shape on 14.10; that is a separate artifact.

---

## Limits

* Static, 13.60 only. No console was contacted; no socket, no probe run.
* The dump's acquisition authenticity is unresolved
  (`docs/dumps_13.60/README.md`). A wrong image would invalidate every address
  here.
* `kernel_text.bin` is text only: it ends at RVA `0xe6e5c0`, and the sysent
  table RVA is exactly that value. The global tables, dispatch tables and
  string literals these five handlers reference are all past that end. Claims
  that depend on table *contents* are marked unresolved, not refuted.
* Function extents are inferred, not recorded. The rule used here is stated
  above and pinned in the tests. An unconditional `jmp` is only a boundary
  when padding and a prologue follow it, so a tail jump into a shared block
  does not end the extent; "not in the body" is weaker than "unreachable".
* "No call to `priv_check`" is a direct-call scan of the named bodies and, for
  claim 5, of three named callees. Indirect calls are invisible to it.
* Errno identities (`0xd` EACCES, `0x16` EINVAL, `0x22` ERANGE, `0x2d`
  EOPNOTSUPP) are conventions, corroborated by the same dump using all four
  in return paths, not by a committed errno table.
* Nothing here is a 14.10 result. The 14.10 probe records quoted above
  (`55c`, `54a2`, `54k`, `54f`, `54b`) are separate artifacts; no 13.60
  finding is transferred to 14.10 and no 14.10 result is used to settle a
  13.60 question.
