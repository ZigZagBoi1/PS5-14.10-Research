# Uaccess helpers, remaining stac sites, liveness, and the dmem re-check (14.10 static, 13.60 image)

Static only. Image `docs/dumps_13.60/kernel_text.bin`, base `0xffffffff8a9c0000`, file offset == RVA,
length `0xE6E5C0`. Every quoted instruction below was decoded from that file in this session.

Purpose: this document closes four more classes and records the exact helper semantics that any
future "get a kernel address into a kernel-mode load" plan has to work around.

---

## 1. The whole user-access helper family, with real semantics

All of these live in `0x2590b0 .. 0x259b60`. The naming below is derived from the code, not from
symbols.

| RVA | signature (by observation) | masking / checks | AC |
|---|---|---|---|
| `0x2590b0` | memcpy(dst=rdi, src=rsi, len=rdx) | **none**, plain `rep movsq`+`rep movsb` | no stac |
| `0x259100` | copy 16 KiB fixed, `prefetchnta` + `movnti` + `sfence` | none | no |
| `0x259190` | memsetw: fills `rsi` with `ax` (low 16 bits of rdi), count rdx | none | no |
| `0x2591d0` | **copyout**(kernel_src=rdi, user_dst=rsi, len=rdx) | dst: `rsi+rdx` must not carry and must be `<= 0x800000000000`, `[proc+0x591]==0`, then `and rsi,0x7fffffffffff`. **src rdi is never masked or range-checked.** | stac/clac, recovery PC at `gs:[0x20]+0x108` |
| `0x259280` | **copyin**(user_src=rdi, kernel_dst=rsi, len=rdx) | src masked with `0x7fffffffffff`, same carry/limit test | stac/clac + recovery |
| `0x259900` | copyinstr(dst=rdi, src=rsi, len=rdx, outlen=rcx) | src `< 0x800000000000`, masked, per-byte stac/clac | yes |
| `0x2599f0` | copystr kernel→kernel, NUL-terminated | **no range check, no mask, no fault handler** (SMAP-faults on a user source) | no |
| `0x259a50` | privilege trampoline: `lgdt [rdi]`; `jmp +0`; seg = 0x28; `pop rax; push 0x20; push rax; retfq` | n/a | n/a |
| `0x259a70` | condsave: rbx, rsp, rbp, r12 → `[rdi]`, +8, +0x10, +0x18 | n/a | n/a |
| `0x259360` | casuword32 (audited earlier) | user range checks | stac/clac |
| `0x259ad0` | rdmsr helper | n/a | n/a |

Consequence that matters: **copyout's source is trusted by construction.** The only way a kernel
address becomes readable through copyout is for a *user* value to reach the source register of a
copyout call, i.e. a kernel object that stores an attacker pointer and later hands it back as a
kernel pointer. That is the one remaining shape, and it is being censused separately
(`COPYOUT_SOURCE_PROVENANCE` measured 93 sites: A=0, B=82 kernel-held, C=10 constant, D=0, E=1).

Also: **copyin/copyout both mask the *user* side only after the carry test**, so a kernel address on
the user side becomes `0x7fff…` + low bits and faults. Probe 1232a measured exactly that with aio
(no bytes transferred, `recvfrom` EAGAIN).

---

## 2. copystr dispatch: the unguarded variant is unreachable

`0x782760(rdi, rsi, rdx, rcx, r8d)`:

* `r8d == 1` → tail `jmp 0x2599f0` (the **unguarded** kernel-to-kernel copystr).
* `r8d == 0` → `call 0x8b5da3e0` (log/vprintf) then tail `jmp 0x259900` (the guarded one).
* otherwise → error path `0x8b1b1950`.

Its only caller is `0x706545` inside `0x7064e0` (malloc 0x401, call `0x782760` with len 0x401, then
the buffer is strdup'd again into `[r13]`). `0x7064e0`'s callers are `0x706431`, `0x706448`,
`0x70645b`, all inside `0x7063f0` (a three-string builder with an out array of 3 pointers and a
mode index). `0x7063f0`'s callers are only `0x9a6c19` and `0x9a6e53` — the blockpool driver.
**No user pointer reaches the unguarded copystr.** Closed.

---

## 3. stac/clac census of the whole image

Byte scan for `0f 01 cb` (stac): **17 sites**. `0f 01 ca` (clac): 46. Fourteen stac sites are inside
the helper block above. The three outside it:

1. `0x252316` — thread-context restore: `test dword [r8+0x100],0x40000` → stac →
   `and dword [r8+0x100],0xfffbffff` → loads r15/r14/r13/r12/rbp/rsp/rbx/rax from `[r8…]` → `ret`.
   Neighbouring block loads dr7/dr0/dr1/dr2/dr3/dr6. Debug-register restore, not a copy.
2. `0x2581a0` — **an unmasked 8-byte [rdi]→[rsi] copy** with a fault-recovery stub at `0x2581e0` that
   returns `rax=0xe` (EFAULT):
   ```
   2581a0 mov rax, gs:[0x20]
   2581a9 lea r8, [rip+0x30]
   2581b0 mov [rax+0x108], r8      ; set recovery PC
   2581b7 stac
   2581ba mov rax, [rdi]           ; <-- source, NOT masked
   2581bd mov [rsi], rax           ; <-- dest,   NOT masked
   2581c0 clac
   ```
   All seven call sites are inside **execve** (body `0x6e2dc0`, syscall 59): `0x6f49f1`, `0x6f4efe`,
   `0x6f504a`, `0x6f50c4`, `0x6f59b8`, `0x6f5a07`, `0x6f5a53`. In each one `rdi` is an address inside
   the exec `img_firstpage` window plus a 16/32-bit offset taken from the ELF program-header walk
   (`sub r12d, [rdi+8]; shr r12d, 3; mov [rbp+rax*4-0x105e], r12w`), so the reachable address set is
   the user-space exec window only. A crafted ELF cannot move it into supervisor space: every index
   in that loop is computed in 16/32-bit arithmetic. **Dead as a read.**
3. `0x8f1480` — pmap A/D-bit walker, see below.

---

## 4. The pmap walker and the physical map

`0x8f1480(rdi = pmap, rsi = VA)`:

```
8f148b mov r14, rsi
8f148e stac
8f1491 mov rbx, rsi
8f1494 shr r14, 0x27 ; and r14d,0x1ff ; shl r14d,3
8f14a3 add r14, [rdi+0x20]        ; pmap->pm_pml4
8f14a7 mov rdi, r14 ; call 0x8f1590
8f14c3 mov rax, [r14]             ; PML4E
8f14c6 movabs r15, 0xffffffffff000
8f14d0 movabs r12, 0xffff800000000000   ; <-- DMAP base
…  rax = entry & 0xffffffffff000 ; next table = DMAP + (idx<<39|idx<<30|…|pa)
```

It walks pml4 → pdpt → pd → pt **through the DMAP**, calling `0x8f1590` (which takes the *address* of the
PTE) at each level. `0x8f1590` loads `rax=[rdi]`, `esi=0x209`, `rcx=0xffffffffff000` and a set of
`lea rip+…` format strings — i.e. a PTE verify/log helper.

Its only caller is `0x3eecf5`, which is **not a sysent body**: it computes
`rdi = [proc+0x200] + 0x2e8` (the pmap embedded in vmspace at +0x2e8) and `rsi = [rbp-0x58]`, calls the
walker, then prints with `0x8ac1d410` and does `rdmsr`. This is a trap/panic diagnostic path, not
reachable from userland.

Two durable facts: the kernel direct map base is **`0xffff800000000000`**, and `vmspace->pmap` sits at
`vmspace+0x2e8`. Neither is reachable today.

---

## 5. Liveness of the syscall table

Each of the 735 rows in `docs/sysent-names-13.60.csv` has `handler_rva` = the **trampoline**, always
an `e9 rel32` in `0x265760..0x266500`. Resolving the target and testing the 8-byte prefix
`55 48 89 e5 b8 4e 00 00` (`push rbp; mov rbp,rsp; mov eax,0x4e`) gives:

* **703 live**, **32 dead**.
* The single most attractive dead entry: **syscall 619 `test_debug_rwmem`** — body `0xa37650` is the
  ENOSYS stub. Every "debug read/write memory" plan built on 619 is void.
* Also dead: `obs_vread`/`obs_vtrace` (point at nosys `0x5620e0`).

Live bodies worth remembering (number → body RVA): 45 ktrace `0x5e84a0`, 308 kldstat `0x552cb0`,
335 utrace `0x5e8b20`, 570 budget_get, 587 get_authinfo `0x4e1a70`, 604 `0x4f7370`, 607 `0xabc710`,
611 `0xa36bc0`, 612 `0x34ce50`, 613 `0xabca10`, 615 `0xabcc00`, 618 `0xabd0f0`, 623 get_gpo
`0x8d25a0`, 624 `0xabd4f0`, 627 `0x4a2850`, 636 `0x6be4d0`, 641 `0x4a2de0`, 646
`0xabe1c0`, 647 `0xabe7b0`, 649 `0x34cfa0`, 659 `0x34b790`, 660 `0x34bc60`, 667 `0x4a31a0`,
671 `0xabe8b0`, 675 `0x2d36f0`, 705 `0x2d3730`, 717 `0x4f7250`, 721 ampr_ctrl_debug `0x6444d0`,
724 `0x4f7940`, 727 get_aio_debug_request_info `0x3b3090`, 728 virtual_query_by_pid `0xabb660`,
733 `0xabd000`, 734 `0xfc890`.

---

## 6. 532 P2 is dead: the privilege gate precedes the OOB

The READ_IDEA_ATLAS ranked "532 with `proc+0xc81 != 0`" first because `c81` disables a clamp and
exposes `movzx eax, word [rax+rcx*2+4]` at `0xaf06d9`. Disassembling the body **from 0xaf0040** (starting
mid-body at 0xaf00c0 yields garbage instructions and misled the first pass):

```
af0073 mov r13, [rdi+8]       ; td_proc
af00b3 cmp byte [r13+0xc81], 0
af00b8 sete r12b
af00cd mov r13d, r12d ; inc r13d      ; r13d = 2 if c81==0 else 1  (the "clamp")
af00de mov rdi, rbx           ; td
af00e1 mov esi, 0x2aa
af00e6 call priv_check
af00f2 test eax, eax
af00f4 je 0xaf011c            ; SUCCESS (eax==0) -> granted body
af00f6 <denied: cmd whitelist 0x18..0x1E / 0x20 / 0x2F -> 0xaf02a6, else eax=1 EPERM>
af011c mov rdi, [rbx+0x140]   ; cred
af0123 call 0x609080          ; exact tag compare cred+0x58 == 0x4800000000010003
af0128 cmp eax, 1
```

The clamp, the indexed load at `0xaf06d9` and the ±4 GB read are **all inside the granted path**.
Probe 1242a measured priv `0x2aa` as REFUSED for uid 1, so no argument shape reaches them.
**P2 is dead regardless of `proc+0xc81`.** `proc+0xc81` remains interesting only as a *flag read*,
which we already have through syscall 587.

---

## 7. dmem re-check: 586 and 628

**586** `body 0x3ce150`, narg 1 — `set_vm_container(arg dword)`:

```
3ce157 mov rbx, gs:[0] ; mov rax,[rbx+8]        ; td, proc
3ce166 mov eax,[rax+0x5c4] ; dec eax ; cmp eax,3 ; setb cl
3ce176 mov [rdi+0x408], rcx                     ; td+0x408 = "container was 1..4"
3ce182 mov r14d,[rsi]                           ; our arg
3ce185 cmp r14,0xffffffff ; je return 0         ; the "query" form
3ce18a mov esi,0x2ad ; call priv_check          ; <-- refused for uid 1 (probe 1226a)
3ce19d cmp r14d,4 ; ja EINVAL
3ce1a3 imul rcx,r14,0x138 ; lea rdx,[rip+0x3102c9f]     ; container table, 0x138-byte entries
3ce1b1 cmp qword [rcx+rdx+0x38], 0 ; je EINVAL
3ce1bd mov [proc+0x5c4], r14d
```

So the container table is a fixed global array of ≤5 entries. There is no create primitive here.

**628** `body 0xabd540`, narg 6 — `mmap_dmem`. Three **capability** helpers run first
(`0x8afc9560`, `0x8afc95a0`, `0x8afc92d0` on `cred = [proc+0x140]`) — and probes measured EBUSY(16) and
EINVAL(22) rather than EPERM(1), so **the capability stage passes for a level-2 user**. Argument rules
derived from the body:

* `arg0` (address) must satisfy `arg0 < 2^50` (`shl rax,0x32; jne EINVAL`).
* `arg1` (length) must be 16 KiB aligned and `>= 0x4000`.
* `arg2` (prot) may only use bits in `~0xfffffc0c` = `0x3f3`.
* `arg3` (flags) == `0xffffffff` selects "no container lookup"; otherwise a container is resolved by
  index through `0x8ad833e0(proc, idx)` and must exist.
* `arg4` may only use bits in `0x6020d0`; its top byte is a type selector
  (`0x1000000` is a devkit-only branch guarded by `proc+0xc81`).
* `arg5` must be `< 2^50`.

The worker `0x3cb450(…, r8 = physical address/offset, …, r13 = length)` opens with
```
3cb499 mov r14, r8 ; shr r14,0x24 ; cmp r14d,4 ; ja EINVAL     ; r8 < 0x5000000000 (20 GiB)
3cb4a6 movabs r14, 0x4fffffffff ; sub r14,r8 ; inc r14
3cb4ba cmp r14, r13 ; jb EINVAL                               ; r8 + len <= 0x5000000000
3cb633 call 0x8ad83ff0                                        ; find the container's range descriptor
3cb63c cmp byte [rax+0x69], 0xfe
3cb642 cmp qword [rax+0x48], rbx ; jg error                   ; desc.start <= r8
3cb64c cmp rbx, [rax+0x50] ; jge error                        ; r8 <  desc.end
```
**The physical range must already lie inside an allocated descriptor of the selected container.**
Without priv `0x2ad` we cannot create such a descriptor, so 628 cannot be aimed at arbitrary physical
memory. The 20 GiB bound and the descriptor check together close this route for uid 1.

---

## 8. What this leaves

Closed in this block: unguarded copystr (unreachable), raw 8-byte copy `0x2581a0` (execve only,
bounded), pmap walker (trap path), 619 rwmem (dead syscall), 532 P2 (priv-gated), dmem (priv-gated),
and the whole indexed-load "W" set — all 11 are fd-table lookups whose index is checked with
`cmp <idx>, [table] / jae` before the load.

Still open and worth a dedicated pass:

1. **Value-taint into pointer slots**: a user qword stored into a kernel object field that is later
   *dereferenced* (not copied out). `COPYOUT_SOURCE_PROVENANCE` covered the copyout *source* only.
2. The physhm path (629/630) — name-gated by a 12-byte `strncmp` against a string that lives outside
   the .text dump, plus a capability check; and `mmap` of a physhm fd produced a page that both ring 3
   and the kernel faulted on (`PHYSHM_COPYIN_14_10`). Worth one more runtime shape once a valid
   create argument set is known.
3. The 646 table-driven `memcpy` from static pointer tables — check whether the index is user-bounded.
4. 671 / 675 / 705 / 727 / 728 — the small Sony calls nobody has decoded end to end.

## Reproduce

```
.local/uaccess_callers.py   caller counts for all 13 uaccess helpers
.local/copystr_sites.py     copystr dispatch callers
.local/w7064e0.py .local/w7063f0.py   the strdup/three-string builder chain
.local/resolve619.py        619 body decode
.local/liveness.py          trampoline -> body -> ENOSYS test for all 735 rows
.local/stac.py .local/stac3.py   stac/clac byte scan and site disassembly
.local/pmap.py .local/dpmap2.py  pmap walker + PTE helper + caller
.local/d532gates.py         532 gate order
.local/d586.py .local/d628b.py .local/d628c.py   586 / 628 / worker 0x3cb450
```
