# Typed-Pointer Census — PS5 14.10 kernel (image: 13.60 .text)

Status: static census complete. No confirmed primitive. Three candidates survive to a runtime probe.

Image under analysis: `C:\PS5contrib\docs\dumps_13.60\kernel_text.bin` — PS5 13.60 `.text`, base `0xffffffff8a9c0000`, length `0xE6E5C0`, file offset == RVA. All addresses below are **RVAs** (`RVA = VA - 0xffffffff8a9c0000`). Syscall table: `docs\dumps_13.60\sysent_index.json`; `sy_call_off` is a trampoline (`e9 rel32`), real body = `off + 5 + rel32`.

The image is 13.60. Every verdict here is a 13.60 verdict. 14.10 is reached only through the runtime probes in §5, which are written to be firmware-agnostic: they take a slid kernel base at run time instead of encoding one.

---

## 1. Thesis, and why the previous audits do not cover it

**Thesis.** `copyin` (0x259280) and `copyout` (0x2591d0) mask the *user* side of the transfer: `copyin` ANDs the source with `0x7fffffffffff`, `copyout` ANDs the destination with the same mask. Passing a kernel address in a user pointer slot is therefore inert — it is folded into user space and the copy either faults or lands on the wrong user page. But the mask is applied **at the copy boundary only**. It says nothing about a scalar that enters the kernel through `copyin`/`copyout` or through the syscall argument array and is then *stored into a kernel object field* and later *re-typed as a pointer* by a plain load. That second typing step carries no mask at all:

```
mov  r12, [rsi + 0x10]        ; attacker qword, no validation
mov  [obj + 0x190], r12       ; stored as data
...
mov  rax, [obj + 0x190]       ; loaded back
mov  rcx, [rax]               ; <-- raw dereference: kernel reads kernel
```

If the field is reached on a path where the loaded value is dereferenced — as a `mov` base, as a `memcpy`/`copyout` source, or as a call argument — then supplying a kernel address in that argument slot makes the kernel read an attacker-chosen kernel address, and the read can be made user-visible. The same shape used as an *unmasked copy destination* is a kernel write.

**Why the earlier passes miss it.** Each completed audit answers a question about a single operation:

| audit | question asked | why it cannot see this |
|---|---|---|
| copyout source provenance (93 sites) | where does the *source* of each `copyout` come from? | it classifies the source at the call site; it never asks whether a value stored *earlier* into an object is later used as a source. It also only looks at `copyout`, not at raw `mov` dereferences. |
| indexed-load census (176) | is the *index* attacker-controlled and unbounded? | bounds question. Here the index is bounded and legal; the *value* is the problem. |
| indexed-store census (30) | same, for stores | same. It flagged 30 tainted indexed stores; none is a real OOB, but it did not follow the stored value afterwards. |
| lifetime / UAF (0) | is an object freed while still referenced? | orthogonal. |
| double-fetch (0) | is user memory read twice? | orthogonal; here the value is fetched once and stored. |
| uninitialized copyout (0) | is the source uninitialized? | the source here is initialized — with attacker data. |
| `stac`/`clac` (17) | is user access bracketed? | irrelevant to a kernel-to-kernel dereference, which needs no `stac`. |

The gap is a **type** question across a store/load boundary. Formally, a hit needs all four of:

- **S** — a syscall-reachable path stores an attacker-supplied qword into a kernel object field;
- **L** — some reachable code loads that same field from an object of the same type;
- **D** — the loaded value is dereferenced as a kernel address before any call that could re-validate it;
- **V** — the result, or an error distinguishable from the fault-free path, reaches userland.

No previous pass computed S ∧ L ∧ D ∧ V. That is what this census does.

---

## 2. Method

**2.1 Bodies.** 301 distinct bodies from `sysent_index.json` after resolving the `e9` trampolines. Each body is disassembled from its exact start with Capstone (`md.detail = True` set at construction). The decoder stops at `ret`, `ud2` + padding, or an unconditional tail `jmp` — function windows are **not** contiguous, and `0x265760..0x266500` is trampolines, not bodies.

**2.2 Interprocedural taint.** The abstract domain is a small set of origins: `TD` (rdi), `UAP` (rsi), `ARG:k` (`[uap + 8k]`), `RET:fn`, `OBJ:disp` (`[obj + disp]`), and `MASKED` (taint killed by an `and` with a non-address immediate). Transfer rules:

- `mov rX, rsi` / `lea rX, [rsi+d]` → `UAP`; `mov rX, [rsi+d]` → `ARG:d/8` when `d` is a multiple of 8 and `d < 8*narg`;
- a stack slot written from a tainted register and read back keeps the taint (aligned-frame spills are handled explicitly — pitfall 2);
- `call 0x259280` (`copyin`) with `rdi = &slot` marks that slot `ARG:copyin`: its *contents* are attacker data;
- `and rX, imm` with an immediate that is not address-shaped (e.g. `0x0000000fff840fff`) drops the origin to `MASKED`; this alone kills one candidate in §4;
- object provenance: `[rdi+8]` (the proc), `gs:[0]` then `+0x8`, a `RET:malloc`, or an `OBJ:disp` loaded from such an object.

**2.3 Store census.** Every `mov [base+disp], tainted` where `base` is a tainted object pointer and `disp` is constant → 97 raw sites (`stores2.json`). They collapse into four classes: aligned-frame stack spills, `td_retval` writes at `[td+0x408]`, kernel-pointer stores (the value is a `malloc` result), and genuine attacker-qword object stores.

**2.4 Consumer census.** A whole-image *linear* sweep is not usable: Capstone returns `cs_err_mem` on the 15 MB buffer, and a chunked resynchronizing variant decodes garbage (2,097,041 "instructions" in 2 MB, no meaningful hits) — discarded. Replaced by a **function-graph crawl**: start from the 301 body RVAs and follow direct `call` and unconditional `jmp` targets → **2,077 functions, 4,274 call edges**, 1.6 s. In that graph, 2,997–3,030 eight-byte loads carry a displacement in

`D = {0,8,10,18,20,28,30,38,40,48,50,58,60,70,78,90,98,d0,d4,dc,e0,e8,f0,f8,100,108,110,120,130,13c,140,148,160,190..1c0,1e8,1ec,1f0,270,280,408}`

For each load of `rY` the crawler looks up to 10 instructions ahead for a dereference (`mov rZ,[rY]`, `mov rZ,[rY+d]`, `mov [rY+d],rZ`, `lea rZ,[rY+d]`), or for `rY` moved into `rdi`/`rsi`/`rdx` followed by a call; it stops at any `call`, `ret`, or `jmp`. A second pass with an index register present (same displacement set) catches array accesses that the scalar pass misses.

**2.5 Hand pass.** Every surviving candidate was read in full, from its body start, and classified on three questions: (a) is the value really attacker-controlled, (b) is the later use a raw dereference, (c) does any result become user-visible.

**2.6 Pitfalls that produced wrong answers before they were caught** (recorded so the numbers can be audited).

1. **ENOSYS stubs.** `0x265760` is `e9 7b c9 2f 00` = `jmp 0x5620e0`. Bodies `0x3af8e0` (sys 668), `0x3af8f0` (sys 661) and `0x3b1670` (sys 665) are exactly `push rbp | mov rbp,rsp | xor esi,esi | pop rbp | jmp 0x265760`. A sweep that starts at such a stub and does not stop at the `jmp` runs into the *next* function and attributes its stores to the stub.
2. **The `mov rbx, rsp` idiom.** Sony's 66x bodies realign the stack and then use the *old* `rsp` as a base: `and rsp,-32`, `sub rsp,0xa0`, `mov rbx,rsp`, then `mov [rbx+0x60],rcx`. Every one of those is an outgoing argument spill, not an object store. Killing instruction: `0x3af938: mov rbx, rsp`.
3. **Taint mixing.** `or r13, [r15]` (sys 544 helper `0xbaf4d0`) unions the uap pointer with a kernel field; the result is not attacker-chosen data, it is a pointer with bits forced. Any `or`/`add` of a tainted pointer into a known kernel pointer is dropped.
4. **Displacement collision.** The same offset means different fields on different structures: `+0x140` is inside `struct proc` at 18 sites and a pointer at 4 others; `+0x148` is a lock in `proc` and a list head elsewhere. Every candidate below is matched by *object identity*, not by displacement alone.
5. **Index masking.** A tainted index that is `and`-ed with a small immediate before the store is bounded, not arbitrary — sys 565 dies here.

---

## 3. Candidate table

Every surviving store class, with the instructions that matter. "Consumer" = a reachable load of the same field from the same object type followed by a dereference.

| # | syscall (narg) | body | store (RVA + text) | field | value origin | consumer? |
|---|---|---|---|---|---|---|
| A | 44 profil (4) | `0x45e4d0` | `0x45e559 mov qword ptr [r13 + 0xf0], rax`<br>`0x45e564 mov qword ptr [r13 + 0xf8], rax`<br>`0x45e544 mov qword ptr [r13 + 0x100], rax`<br>`0x45e54f mov qword ptr [r13 + 0x108], rax` | 0xf0 base, 0xf8 size, 0x100 off, 0x108 scale | `uap[0]`, `uap[1]`, `uap[2]`, `uap[3]` (dword; `cmp r13d,0x10000; ja`) | **no** in 2,077 functions |
| B | 566 setter (3) | `0x603710` | `0x6037e5 mov qword ptr [r15 + r13*8 + 0x190], r12`<br>`0x603874 mov qword ptr [rbx + r13*8 + 0x190], r12`<br>`0x603897..0x6038dd` six scalar stores `[rax+0x190]..[rax+0x1b8]` | 0x190+8i, or six slots when idx == -1 | `0x603738 mov r12, qword ptr [rsi + 0x10]` — **no validation** | one: C |
| C | 567 getter (3) | `0x6039d0` | (reader) `0x603bc8 mov rax, qword ptr [rax + r13*8 + 0x190]` | same slots | reads B's field | **yes — see §4** |
| D | 637 (2) | `0xabd930` | `0xabda0c mov qword ptr [r12 + 0x280], rax` | `[proc+0x200]+0x280` | `0xabd9fe mov rax, qword ptr [r13 + 8]` = `uap[1]`, gated only by `0xabd93e cmp qword ptr [rsi + 8], 0x11; jl` | **no** |
| E | 565 (3) | `0x6034e0` | `0x603608 mov qword ptr [rbx + r12*8 + 0x160], r13` | 0x160+8i | `[rsi+0x10]`, but **masked** | n/a |
| F | 662/663/664/666/669 | `0x3af900`, `0x3b01f0`, `0x3b0fb0`, `0x3b1680`, `0x3b2060` | `0x3af942 mov qword ptr [rbx + 0x60], rcx`<br>`0x3af946 mov qword ptr [rbx + 0x48], rdx`<br>`0x3b0232 mov qword ptr [rbx + 0x60], r9` | stack | register arguments | n/a (stack) |
| G | 480 (2) / 54 ioctl | `0x4ecf20` / `0x4ecf40` | `0x4ecf9c mov qword ptr [rbx + 8], r14` | writes back into `uap` | `uap[1]` | n/a |
| H | 165 (2) | `0x47b030` | `mov qword ptr [r13 + 0x40], rax` after `0x47b0fd call 0x259280` | 0x40 | `copyin` contents | no (data) |
| I | 196 / 606 / 429 | `0x8fbbe0`, `0xa36b90`, `0x55deb0` | `0x8fbd54 mov qword ptr [r14 + 0x408], r13` | `td_retval` | `uap`-derived | no (return value) |
| J | 488 (5) | `0x83e320` | stub; the store at `0x83e3c8` belongs to fn `0x83e330` | — | — | priv-checked |
| K | 557 (3) | `0xac7240` | `0xac7299 call 0xc08b50` (malloc 0x20) + `0xac72c8 call 0x259900` (`copyinstr`) | buffer | string | no |
| L | 544 helper | `0xbaf4d0` | `0xbaf502 or r13, qword ptr [r15]` | — | mixed | false positive |
| M | 73 munmap | `0x2cb4e0` (internal) | `0x2cb66c mov qword ptr [r12+0x28], r14` | map entry | address scalar | no |
| N | 657 batch (4) | `0x9a9f40` | — no object store — | — | user array, stride 0x20 | n/a |
| O | 655 (3) | `0x9a9e10` | — compare only: `cmp qword ptr [rbx + 0x20], r14` | 0x20 / 0x28 | — | n/a |
| P | 0x444xxx family | many | `mov qword ptr [rax + 0x1e8], rbx` etc., via `0x3d4120` | 0xd0..0x270 | syscall args | **no** (0 hits) |

Supporting instructions for D: the object is fetched at `0xabd9db mov r12, qword ptr [rbx + 0x200]`, the argument at `0xabd9fe mov rax, qword ptr [r13 + 8]`, and the call that follows takes the object: `0xabda1c call 0x691c70` with `rdi = r12`.

Supporting instructions for B: `0x60371e mov r13d, dword ptr [rsi + 8]`, `0x603728 lea eax, [r13 - 6]`, `0x60372c cmp eax, -7`, `0x60372f jb 0x6039b1` → index ∈ [-1, 6]; `0x603735 mov r15d, dword ptr [rsi]` (pid, 0 = self); `0x6037ad call 0xb92420` then `0x6037bb mov r15, qword ptr [rax + 0x3f8]` (thread object); the six-slot path at `0x603897`, `0x6038a5`, `0x6038b3`, `0x6038c1`, `0x6038cf`, `0x6038dd` writing `0x190/0x198/0x1a0/0x1a8/0x1b0/0x1b8`.

Supporting instructions for A: `0x45e4f5 mov r14, qword ptr [rdi + 8]` (proc), `0x45e519 mov rax, qword ptr [r12 + 8]`, `0x45e52e mov r13, qword ptr [rax + 0x58]` (the object), `0x45e505 lea rbx, [r14 + 0x148]` (lock), the four stores, then `0x45e56b call 0x4c7520` (unlock) and `0x45e573 call 0xc66d60` (or `0x45e57d call 0xc66dc0` when scale == 0).

Supporting instructions for P: `0x3d4120: mov rax, qword ptr gs:[0]; mov rax, qword ptr [rax + 0x4b0]; ret`, then e.g. `0x4443a0: mov rbx,rdi; call 0x3d4120; test rax,rax; je ...; mov qword ptr [rax + 0x148], rbx; or byte ptr [rax + 0x35], 1`.

---

## 4. Hand verdicts

**A — sys 44, profil. SURVIVES (weakly).** The four stores are genuine: an attacker qword in `uap[0]` lands unvalidated at `[obj+0xf0]`, `uap[1]` at `+0xf8`, `uap[2]` at `+0x100`, and the zero-extended dword `uap[3]` at `+0x108`. Object = `[proc+0x58]`, field layout `{base, size, off, scale}`, which is the shape of `struct uprof`; `scale` is range-checked to `(0, 0x10000]`, consistent with profil semantics. **But no consumer exists in the crawled graph**: a pair scan over all 2,077 functions for "load `[proc+0x58]`, then load `[obj+0xec..0x110]`" returns **0 hits**. The consumer, if any, is a clock/tick path reached from an interrupt handler, not from a syscall body. On FreeBSD semantics that consumer is `addupc_intr`, which performs `copyout(&pc, prof->pr_base + off, sizeof(pc))` — `pr_base` is a **copyout destination**, so the mask at `0x2591d0` folds a kernel address into user space and nothing is read. That inference is not proven for this image: the function is outside the reachable set. The kill evidence is therefore *absence*, and absence is exactly what probe 5.1 tests.

**B + C — sys 566 store → sys 567 load. DEAD.** This is the closest thing in the image to the thesis shape: 566 stores an unvalidated qword (`0x603738`) into a per-thread array at `+0x190+8*idx`, and 567 loads precisely that slot. The killing instruction is `0x603c10: lea rdi, [rbp - 0x38]` — the `copyout` that follows (`0x603c1c call 0x2591d0`, `edx = 8`) takes the **address of the stack copy** as its source, not the slot's contents. The slot value is first copied to `[rbp-0x38]` at `0x603bd0` and is then treated as pure data. No dereference of the stored value exists anywhere: the indexed scan found `+0x190` read at exactly one site, `0x603bc8`, inside 567 itself. Net effect: an 8-byte value round-trip, i.e. a per-thread scratch slot. If a later firmware drops the stack copy and copyouts from the value, this becomes the primitive — hence probe 5.2.

**D — sys 637. DEAD in 13.60, worth a probe for 14.10.** `0xabda0c` stores `uap[1]` into `[curproc+0x200]+0x280` with only a lower bound (`0x11`). The immediate consumer `0x691c70` takes the object in `rdi` and touches `+0x278` (lock), `+0x289`, `+0x28a` (flags), `+0x260` (0x100-byte buffer, passed to `0xc06260`), `+0x288` — and never reads `+0x280`. The displacement scan for `0x280` across 2,077 functions returns **0** load-then-deref hits. Killed by `0x691c70` never issuing `mov rX, [r12+0x280]`.

**E — sys 565. DEAD by mask, not by use.** `0x6034f6 movabs rcx, 0xfffffff0007b0000`, `0x60350d test r13, rcx`, `0x603515 jne 0x6036f8` rejects any value with a bit in that mask, so the accepted bits are a subset of `0x0000000fff840fff` — a 32-bit flag word. No kernel address survives. The following `and rax, r13` / `cmp` against `0x100000070` and `0x6e` confirms flag semantics.

**F — 662/663/664/666/669. DEAD by base register.** Killing instruction `0x3af938: mov rbx, rsp` (after `and rsp, 0xffffffffffffffe0; sub rsp, 0xa0`). Every subsequent `[rbx+0x48]`, `[rbx+0x60]`, `[rbx+0x68]` is an outgoing stack argument for the call at the end of the body, not an object field. Same idiom at `0x3b0228` and `0x3b2098`. These bodies (aio-shaped, narg 3–5) were the largest single source of false positives in the raw store list.

**G — 480 / 54. DEAD.** 480 is a five-instruction wrapper — `push rbp; mov rbp,rsp; mov eax,[rsi]; mov rdx,[rsi+8]; mov esi,eax; pop rbp; jmp 0x4ecdd0` — and owns no store. The store the sweep attributed to it, `0x4ecf9c mov qword ptr [rbx + 8], r14`, is inside sys 54 with `rbx = rsi = uap`: the kernel *writes back into its own argument array*, zero-extending the ioctl request after logging a non-zero high dword (`0x4ecf93 call 0x25d410`). No object is touched.

**H — sys 165. DEAD by provenance.** The stored register is filled by `0x47b0fd call 0x259280`, so the value came *through* `copyin`: it is data the user already supplied and could already read. Storing it into a field and reading it back adds nothing, and no dereference follows.

**I — 196/606/429. DEAD.** `0x8fbd54 mov qword ptr [r14 + 0x408], r13` writes `td_retval`. That field is copied to user space as the syscall return value and is never used as an address; the other two bodies do the same at their own `[td+0x408]` sites.

**J — sys 488. DEAD twice.** Its body is a stub (`mov edx,1; pop rbp; jmp 0x83de90`); the store belongs to the following function `0x83e330`, whose first act is `mov rsi, 0xce; call 0xadfa30` (`priv_check`). Privileged path, and not 488's.

**K — sys 557. DEAD.** `0xac7299 call 0xc08b50` allocates 0x20 bytes and `0xac72c8 call 0x259900` (`copyinstr`) fills it with the user's name string. The stored pointer is the allocation, not the argument.

**L — sys 544 helper. DEAD (taint artifact).** `0xbaf502 or r13, qword ptr [r15]` merges the uap pointer with a thread field; the union is a pointer with forced bits, not attacker-chosen data.

**M — sys 73 munmap. DEAD.** `0x2cb4e0` is not a syscall body. The taint hit `0x2cb66c mov qword ptr [r12+0x28], r14` stores a map-entry *address* just computed from the entry list; the neighbouring stores (`[rbx+0x50]`, `[rax+0x1a0]`, `[rcx+0x1a8]`) maintain `vm_map` scalars used in comparisons, never as bases.

**N — sys 657 blockpool batch. DEAD, and not a candidate.** `0x9a9f40` validates `[rsi+0x18] != 0` and `[rsi] != 0`, then loops `sub r15, rbx; shr r15, 5` over the user's command array at `[rsi+0x10]` with stride 0x20, calling `0x259790`. The records stay in user memory; the kernel allocates no object and stores no pointer from a record. This was the prime suspect and it is clean: a *batch* interface over user memory, not a stored-command interface.

**O — sys 655. DEAD, validation only.** `cmp qword ptr [rbx + 0x20], r14` / `mov rcx, qword ptr [rbx + 0x28]; sub rcx, r14` compares the argument against the object's `[+0x20, +0x28)` range. The fields are read, never written from `uap`.

**P — 0x444xxx per-thread telemetry. DEAD by absence of readers.** All stores go through `[[gs:0]+0x4b0]` and land at `+0xd0, +0xd4, +0xdc, +0xe0, +0xe8, +0x110, +0x130, +0x13c, +0x140, +0x148, +0x160, +0x1e8, +0x1ec, +0x1f0, +0x270`. Load-then-deref hits for `0xd0`, `0xd4`, `0xdc`, `0x130`, `0x13c`, `0x1e8`, `0x1ec`, `0x1f0`, `0x270`: **0 each**. The non-zero hits at `0xe0/0xe8/0x110/0x140/0x148/0x160` are collision artifacts on other structures — `0x2a8b00` reads `[rax+0xbc]`, `0x3cc7a0` reads `[rax+0xa8]`, `0x2a8d60` dereferences `[rax+8]` as `struct proc`, `0x4a13e0` does `mov rdi, qword ptr [rcx + rdx]` on a list head, `0x58ea90` passes `[rdi+0x110]` to `0x44f8c0`, `0x9a8570` does `lea rbx, [rax + r13*4]` (array base). None is the telemetry object.

**One near miss, not in the table.** `0x500a20: mov rax, qword ptr [r14 + 0xf0]; cmp rax,r15; mov rcx,rax; mov rax, qword ptr [rax]; cmp rax,r15; jne` is a genuine load-then-deref at displacement `0xf0` — the same displacement sys 44 writes. It is **not** the same structure: that function's object has a lock at `+0x110` and the load is a list unlink (`[rax]` is the next pointer). If sys 44's object ever grows a `+0x110` lock this becomes the one site where `pr_base` is dereferenced; as it stands, object identity separates them.

**Summary.** 97 raw stores → 4 genuine attacker-qword object stores (A: 44; B: 566; D: 637; E: 565) → 1 reader (C: 567) → 0 dereferences. The single reader in the entire image takes the value as data. Every other store class dies on a register that is `rsp`, a `copyin`-sourced datum, a `td_retval` slot, a masked flag word, or a writeback into `uap`.

---

## 5. Top three worth a runtime probe

All three are cheap and non-destructive, and all take the kernel base at run time (slide-aware) rather than a hard-coded address. Argument order is the FreeBSD/PS5 ABI: `rax = num, rdi = a0, rsi = a1, rdx = a2, r10 = a3`.

**5.1 — syscall 44, profil. The only candidate whose consumer is unknown.**
Shape: `syscall(44, KADDR, 0x1000, 0, 0x1000)`.
- `a0 = KADDR` — a slid kernel address of a mapped page, `kernel_base + 0x1000` (RVA 0x1000).
- `a1 = 0x1000` size, `a2 = 0` offset, `a3 = 0x1000` scale. `a3` must be non-zero (a zero scale takes the `0x45e57d` branch and skips all four stores) and ≤ `0x10000`, otherwise `0x45e4ef ja 0x45e593` exits early.
- Then let the process run for a few clock ticks and disarm with `syscall(44, 0, 0, 0, 0)` before releasing anything.
Decision: if the consumer is `addupc_intr`-shaped, the kernel executes `copyout(&pc, KADDR + off, 8)`, the destination is masked to `0x7fffff...`, and the call returns `EFAULT` or writes to a user alias — no observable kernel read, no panic. A panic, or a write landing in user memory at the masked address, means the mask is not applied on that path. Record which of the two happens, and the syscall's own return value. This closes the last unterminated path in the census.

**5.2 — syscalls 566 → 567, the store/load round-trip. Sharpest single test of the thesis.**
Shape: `syscall(566, 0, 2, KADDR)` then `syscall(567, 0, 2, &out)`.
- `a0 = 0` means self (`0x603735 mov r15d,[rsi]` plus the `test/jne` path resolving the calling thread); a non-zero pid needs a live target thread.
- `a1` is `[-1..5]` for the getter (`0x6039f9 cmp r13, 5`) and `[-1..6]` for the setter; use `2`.
- `a2 = KADDR` — any slid kernel address; 566 does not validate it at all (`0x603738`).
- `out` is an 8-byte user buffer.
Decision: `out == KADDR` means the getter is a value round-trip (13.60 behaviour, `0x603c10 lea rdi,[rbp-0x38]`) and the class is closed for 14.10 as well. `out` containing 8 bytes equal to `*(uint64_t *)KADDR` means the getter copyouts from the value and the arbitrary-read primitive is confirmed in one call. A panic means the copyout source is the value and KADDR was unmapped — retry against a known-mapped kernel page. Repeat with two different indices to confirm the slot is per-index.

**5.3 — syscall 637, the per-proc `+0x200` object.**
Shape: `syscall(637, 0, KADDR)`.
- `a0 = 0` (pid/selector; the body only tests `[rsi+8]`), `a1 = KADDR` must be ≥ `0x11` (`0xabd93e cmp qword ptr [rsi+8], 0x11; jl`), so any kernel address passes.
- Follow with a second 637 call against the same object and watch for a fault inside `0x691c70`.
Decision: in 13.60 nothing reads `+0x280`; a panic here means 14.10 added a consumer that dereferences the field — i.e. the field became typed. A clean return with no `+0x280` load in the 14.10 image kills the candidate on that firmware too.

Not worth probing: 565 (masked, `0x6034f6`), 480/54 (uap writeback), 657/655 (user-memory batch and range check), the 66x family (stack frames).

---

## 6. What could not be decided

1. **Consumers outside the syscall-reachable graph.** The crawl follows only direct `call`/`jmp` edges from the 301 bodies. Interrupt, clock, taskqueue and timeout handlers are reached through *data* — function pointers in structures, callout entries — and are not among the 2,077 functions. sys 44's profil consumer is exactly such a case: the stores are proven, the reader is not. This is the largest hole, and the reason probe 5.1 exists.
2. **Indirect calls.** The consumer scan recognizes a dereference, or a `mov` into `rdi`/`rsi`/`rdx` followed by a call. It does not model a function pointer stored in the object and later `call`-ed — that is a control-flow hijack, a different bug class, and was not scored. One site of that shape exists (`0xa0bd50 mov rbx,[rax+0x100]`, then `mov rdx,rbx` into an indirect call), on a different object.
3. **Object identity for `[proc+0x58]`.** The layout `{+0xf0 base, +0xf8 size, +0x100 off, +0x108 scale}` matches `struct uprof` and the `scale` range check matches profil, but the allocation site was not located; the type is inferred from shape, not proven.
4. **13.60 vs 14.10 drift.** This census is on the 13.60 image. A field never read in 13.60 can gain a reader in 14.10, and syscall numbering or argument layout can shift. §5 is written against a slid base so the probes survive the difference, but the *static* verdicts do not transfer by themselves.
5. **SMAP status.** This candidate set is kernel-to-kernel and needs no `stac`. The separate class — a raw `mov` through a user-supplied pointer with no `copyin` — was outside this task and is not scored; whether SMAP makes it inert on this platform was not determined.
6. **Completeness of `D`.** The displacement set was seeded from the candidate stores and from `proc`/`thread` shapes; a field at a displacement outside `D` that is both stored and dereferenced would not appear. The crawl evaluated all 8-byte loads whose displacement is in `D` (2,997–3,030 of them), not all 8-byte loads in the image.
7. **The `[proc+0x200]` list aliasing.** `0x350cd0` pops a list and treats `+0x1a0` as a pointer (`0x350d7e mov rdi, qword ptr [r12 + 0x1a0]`, then `0x350dac mov qword ptr [rdi + 8], 0`). sys 566 can overwrite `+0x1a0` — but on the **thread** object at `[thread+0x3f8]`, not on the `[proc+0x200]` object, so the two do not alias in 13.60. If 14.10 merges the layouts, `syscall(566, 0, -1, KADDR)` would plant a pointer in a list head that `0x350cd0` later pops — a **write** primitive. That is the one cross-object aliasing question left open.

---

Machine artifacts (regenerable, deliberately outside the repo): `crawl.json` (2,077 functions / 4,274 edges), `stores2.json` (97 raw tainted stores), `hits2.json` (load-then-deref and arg-to-call), under `%TEMP%\tpc\`.
