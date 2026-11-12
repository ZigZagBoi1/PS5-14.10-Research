# Syscall 532: the one unchecked indexed load is unreachable

Static, 13.60 dump (base 0xffffffff8a9c0000, offset == RVA) plus the 14.10
runtime measurements already on file. Written to close the last surviving
candidate from `docs/KERNEL_INDEXED_LOAD_CENSUS_14_10.md`.

## 1. The candidate, restated

`docs/KERNEL_INDEXED_LOAD_CENSUS_14_10.md` found exactly one indexed kernel
load in 176 sites whose index comes from a user argument and has no dominating
bound:

    0xaf06d9   movzx eax, word ptr [rax + rcx*2 + 4]

`rcx` is `movsxd` of the first dword of the 8-byte structure copied from
`uap->arg3` (0xaf065e `mov edi,[rbp-0x850]`, 0xaf06d2 `movsxd rcx,edi`), and
`rax` is `[table_array + selector*8]`. The zero-extended word is stored at
`[rbp-0x858]` and copied out 4 bytes to `uap->arg2` at 0xaf121e. If that
instruction could be reached with a chosen index it would be a 2-byte kernel
read at `table + index*2 + 4`, i.e. +-4 GB around a fixed table.

## 2. Four gates stand in front of it

### Gate 1 - the command must be 0x31

The handler is a command dispatcher. At 0xaf00f6-0xaf0111 it first asks
whether the command is one of the ungated few:

    0xaf00f6  lea ecx,[r14-0x18] ; cmp ecx,7 ; jb 0xaf02a6
    0xaf0103  cmp r14d,0x2f ; je 0xaf02a6
    0xaf010d  cmp r14d,0x20 ; je 0xaf02a6
    0xaf0117  jmp 0xaf1223            ; otherwise the credential path

0xaf011c is the capability check (`mov rdi,[rbx+0x140] ; call 0xafc9080 ;
cmp eax,1`). Command 0x31 is not in either bitmap path (0x800003d4 for
commands <= 0x20, 0x2a for 0/1/2/3/4/5), so it only exists further down the
privileged branch, behind the ID lookup of gate 2.

14.10 measurement (probe 87a, 2026-10-22, docs/CHANGELOG.md:2029): the reachable
command set is **0x18-0x1E, 0x20 and 0x2F**. Everything else returns a status
without executing. The three status values 87a saw are the same three constants
that appear in this body, so the 14.10 handler shares this shape:
`0x800D0204` exists exactly once in the whole 13.60 image, at 0xaf143f, and
0x800D0203 at 0xaf0155/0xaf01f6/0xae7xxx.

### Gate 2 - the ID must exist in a table that no syscall writes

The privileged branch validates the packed "handle" in two steps. The integrity
step is forgeable (87a moved the answer from 0x800D0204 to 0x800D0203 by
implementing the checksum). The second step is the wall. It is a global table:

    0xaf014d  movzx esi, word ptr [rip+X]      -> RVA 0x3CF7E40  (entry count)
    0xaf0162  lea rcx, [rip+Y]                 -> RVA 0x3CF7E38  (table base)
    0xaf017c  lea r8,[rdx+rdx*4]               ; 5*index
    0xaf0180  mov edi,[rcx+r8*8+0x18]          ; entry dword id
    0xaf0185  cmp [rbp-0x864],edi ; je 0xaf026f
    0xaf0196  movzx r8d, byte [r9+0x15]        ; repeat count
    0xaf01a6  movzx r9d, byte [r9+0x16]        ; shift
    0xaf01c0  shlx r11d,r10d,r9d ; add r11d,edi ; cmp [rbp-0x864],r11d

So the table is `{dword,dword,word count,...}` at 0x3CF7E38 with 0x28-byte
entries from 0x3CF7E50, each holding an id at +0x18, a count at +0x15 and a
shift at +0x16; the accepted ids are `base + k*(1<<shift)`. A miss returns
0x800D0203 - exactly what 87a got after forging the checksum.

Who can write it? A full linear sweep of the image, resolving every RIP-relative
operand, found 157 references to the window [0x3CF7D80,0x3CF7EC0]. Every single
one lies inside the helper cluster 0xAE6C00-0xAED000, and **not one sysent body
references the window** (the only sysent body in 0xAE4000-0xAF2000 is 532
itself, at 0xAF0040, and it only reads). The writers of the structure are:

    0xAEA2D6  mov dword [0x3CF7E38],eax
    0xAEA2F5  mov dword [0x3CF7E3C],eax
    0xAEA488  mov word  [0x3CF7E40],ax     <- the entry count
    0xAEA42F/0xAEA437/0xAEA442/0xAEA461    dword moves through 0x3CF7E48/0x3CF7E4C
    0xAE9C38  mov dword [0x3CF7E2C],1
    0xAEB0D1/0xAEB239/0xAEB147/0xAEB46E    flag writes 0x3CF7E2C/0x3CF7E00/0x3CF7DE8

and they belong to the boot-time manager that also serves 622. There is no
userland call that registers an entry: a game process cannot populate the table,
so no ID can satisfy the lookup. This is the same wall 87a hit and the same
shape as 622's "no device context".

### Gate 3 - three global boot flags

    0xaf0694  cmp dword [0x3AF7C00],0 ; je reject
    0xaf06a1  cmp dword [0x3AF7C04],0 ; je skip3
    0xaf06aa  cmp dword [0x3AF7BC0],1 ; jne reject

These are boot tunables outside every retained dump; nothing in the sysent table
writes them (the 532 body only reads).

### Gate 4 - proc+0xc81 must be nonzero, and it is not

    0xaf00b3  cmp byte [r13+0xc81],0
    0xaf00be  sete r12b
    0xaf066b  test r12b,r12b ; je 0xaf067e     ; skip the clamp only if c81 != 0
    0xaf0670  cmp edi,1 ; mov edi,2 ; jne reject

With `proc+0xc81 == 0` - the measured state of every process this project can
create (docs/CHANGELOG.md:593, docs/CREATIVE_ROUTES_II_14_10.md:179,
docs/UAP_OVERREAD_SCAN_14_10.md) - the index is forced to 2 and every other
value is rejected before the load. The one and only writer of the byte in the
image is 0x38f7bf inside 0x38f3a0, reached through stub 0x25da60 with no direct
callers, i.e. process creation with mode 2.

## 3. Verdict

**Closed.** The single unchecked indexed load in the corpus cannot be reached
with an attacker-chosen index: it needs a privileged 532 command, a registered
device ID from a boot-time-only table, three boot flags, and `proc+0xc81 != 0`.
Any one of the four is enough to stop it; all four are.

This also disposes of the write side of the same idea: the companion census
(`docs/KERNEL_INDEXED_STORE_CENSUS_14_10.md`, 2691 stores, 30 tainted) found
0 class-U stores, so no caller-chosen index and no caller-chosen value reach a
kernel array together.

## 4. What would reopen it

Only a writer of `proc+0xc81` (one site, process creation) or a userland path
that inserts an entry into the 0x3CF7E38 table (none in the sysent table). Both
are absent in this image, so the route is not "hard", it is structurally
unavailable to a game process.

## 5. Reproduce

    python .local/dis532_handle.py     # full body disassembly -> .local/dis532_full.txt, status-constant sites
    python .local/scan_table532.py     # 157 references to the 0x3CF7E38 window, with RVAs
    python .local/map532_cluster.py    # sysent bodies in 0xAE4000-0xAF2000, status dword sites

Runtime facts quoted from probe 87a: results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_20261022_120531.txt
and the 864a matrix: results/phase17_new_vectors/864a_sys532_matrix_20261022_222612.txt
(0x800D0203 = 2148336131 at cmd 0x18-0x1D with page pointers, -1 with zeros).

## 6. Runtime: command 0x31 is refused one gate earlier than the capability test (probe 1242a)

Probe `probes/phase17_new_vectors/1242a_sys532_cmd31_gate.lua`
(`results/phase17_new_vectors/1242a_sys532_cmd31_gate_20261105_135459.txt`) calls
`532(cmd, selector, outbuf, &index, 0)` and reads the status dword the handler writes into `outbuf`:

| call | ret | outbuf[0] |
|---|---|---|
| cmd 0x18, sel 0 | 0 | `0x800D0203` |
| cmd 0x20, sel 0 | 0 | `0x800D0208` |
| cmd 0x31, sel 0x10..0x16 | -1 | untouched (`0xCDCDCDCD`) |
| cmd 0x31, sel 0x0 / 0x17 | -1 | untouched |
| cmd 0x32 | -1 | untouched |

`errno` is 1 `EPERM` for every 0x31 and 0x32 call, and the refusal comes before the selector bound
is applied. An earlier revision of this section read that EPERM as the capability test refusing the
call. That was wrong about which branch is which, and the correction matters because it changes what
the measurement proves.

**Branch sense.** `0xaf00e6` calls `priv_check(0x2aa)`; `0xaf00f2 test eax,eax` and
`0xaf00f4 je 0xaf011c` send `eax == 0` - priv_check **success** - to `0xaf011c`, which is the body of
the handler. The refusal path is the fallthrough at `0xaf00f6`: a command whitelist (`0x18..0x1E`,
`0x20`, `0x2F` -> `0xaf02a6`, everything else -> `0xaf1223` with `eax = 1`). The capability test at
`0xaf0123` is inside the granted path, and when it fails it does `jne 0xaf02a6`, which builds a
`0x800D0202` status word and returns **0** - it never produces EPERM.

So 1242a proves that `priv_check(0x2aa)` was refused for this process, and that the capability test
never ran for `cmd 0x31`. The two control calls reached the same status builders through the
refusal path's whitelist, so they prove the argument shape and the routing, not a tag pass. 532 is
closed at the privilege gate for a uid-1 game process, and a matching role tag would not open it.

**The tag this body actually tests** is `0x4800000000010003`, compared as a full 64-bit equality
against `cred+0x58` by the 25-byte helper at RVA `0x609080`:

    609080  push rbp / mov rbp,rsp
    609084  movabs rcx,0x4800000000010003
    60908e  xor eax,eax / 609090 cmp qword [rdi+0x58],rcx / 609094 sete al
    609097  pop rbp / ret

No mask, no shift, no second field, no fail-open (a NULL cred faults rather than returning 1). 532's
extent `0xaf0040-0xaf133e` calls no other capability helper. `0x4800000000020002` belongs to
0x6091d0, whose three callers (0x69a180, 0xada436, 0xc36e1f) 532 does not reach; the pairing in
`docs/CAPABILITY_CONTEXT_14_10.md` was wrong on that point and is fixed there.

**What our credential does carry** (from the 587 record, `docs/PRIV_CHECK_CENSUS_14_10.md` section 4a):
`cred+0x60 & 0x7000000000000000 == 0x2000000000000000`, i.e. bit 61 set, bits 62 and 60 clear. That is
the level-2 capability bit. `cred+0x58` is unknown, not zero: 587 copies it only on its granted path,
and the 55e capture (`ret 0`, only `+0x0C = 0x20000000`) is the denied stub.

**Practical value.** `532(cmd=0x31)` is a cheap non-lethal probe of privilege number `0x2aa` for this
process - EPERM is a definite "refused at the privilege gate", and it says nothing about the tag.
