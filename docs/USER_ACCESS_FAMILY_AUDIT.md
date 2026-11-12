# The user-access helper family: 17 entries, fully classified (13.60)

Route 3 of `docs/CREATIVE_ROUTES_14_10.md` proposed auditing the "fourteen unaudited copy helpers" on the
theory that one of them validates one operand and dereferences another. This document does that audit and
closes the route. All claims are capstone over `docs/dumps_13.60/kernel_text.bin`
(base `0xffffffff8a9c0000`, file offset == RVA).

## 1. How the family was found

Scan for the onfault-installer idiom `lea r11,[rip + X]` followed by `mov [pcb+0x108], r11`, then walk
back to the enclosing `push rbp; mov rbp, rsp`. That yields 17 entries in a single 0x1000-byte block
(`0xffffffff8ac18ff0` - `0xffffffff8ac19bff`), each with its own private onfault label. Every one of
them is preceded by the same three-step preamble in different orders:

1. a range check against `0x7ffffffffff8 / 0x7ffffffffffc / 0x7ffffffffffe / 0x7fffffffffff` (the
   largest address that still fits the access width below the 47-bit user boundary);
2. a process gate `cmp byte [td_proc+0x591], 0` (the per-process "uaccess allowed" byte; while it is 1
   every user access by that process fails - see `docs/CREATIVE_ROUTES_14_10.md` §0.1);
3. `movabs rax, 0x7fffffffffff; and <reg>, rax` - the 47-bit mask, a no-op for anything that passed (1).

## 2. Classification

| # | RVA | what it does with the user pointer | check constant | checked reg = deref reg |
|---|---|---|---|---|
| 0 | `0x2591d0` | `rep movsq/movsb` `[rdi] <- [rsi]`, len `rdx` - **copyout** (kern->user) | `rsi+rdx <= 0x800000000000` | yes (`rsi`) |
| 1 | `0x259280` | `rep movsq/movsb` `[rdi] <- [rsi]` - **copyin** (user->kern) | `rdi+rdx <= 0x800000000000` | yes (`rdi`) |
| 2 | `0x259360` | `lock cmpxchg dword [rdi], ecx` | `0x7ffffffffffc` | yes |
| 3 | `0x2593d0` | `lock cmpxchg qword [rdi], rcx` | `0x7ffffffffffc` | yes |
| 4 | `0x259450` | `mov r11, [rdi]` - read qword (fueword) | `0x7ffffffffff8` | yes |
| 5 | `0x2594c0` | `mov r11d, [rdi]` - read dword | `0x7ffffffffffc` | yes |
| 6 | `0x259530` | `mov r11w, [rdi]` - read word | `0x7ffffffffffe` | yes |
| 7 | `0x2595a0` | `mov r11b, [rdi]` - read byte | `0x7fffffffffff` | yes |
| 8 | `0x259620` | `movzx eax, word [rdi]` | `0x7ffffffffffe` | yes |
| 9 | `0x259690` | `movzx eax, byte [rdi]` - fubyte | `0x7fffffffffff` | yes |
| 10 | `0x259720` | `mov [rdi], rsi` - write qword to user | `0x7ffffffffff8` | yes |
| 11 | `0x259790` | `mov [rdi], esi` - write dword to user | `0x7ffffffffffc` | yes |
| 12 | `0x259810` | **no memory access** - validate-only (useracc) | `0x7ffffffffffe` | n/a |
| 13 | `0x259880` | `mov [rdi], al` - write byte to user | `0x7fffffffffff` | yes |
| 14 | `0x259900` | `lodsb [rsi] / stosb [rdi]` in an overlap-checked loop (user strlcpy) | `rsi <= 0x800000000000`, mask on `rsi` after `xchg` | yes |
| 15 | `0x259ad0` | no stac window - not a user accessor | - | n/a |
| 16 | `0x259b10` | no stac window - not a user accessor | - | n/a |

The check constants are exactly the largest address from which the access width still fits below
`0x800000000000`: `-8` for qword, `-4` for dword, `-2` for word, `-1` for byte. That consistency is
itself evidence the family is generated from one template.

## 3. The audit question, answered

**15 of 15 user-accessing entries validate the same register they subsequently dereference.** There is no
operand swap, no width/constant mismatch, and no entry that masks one register and reads another. Entry 14
is the only one with a register shuffle (`xchg rdi, rsi` before the mask), and the mask still lands on the
register that `lodsb` reads.

Corollary for the objective: you cannot turn a user-access helper into a kernel read by passing a kernel
address. `0xffffffff8a9c0000` fails step (1) at every entry; the mask in step (3) can never be reached
with a kernel address, and if it were, it would produce `0x7fffffff8a9c0000`, which is still not a valid
user address and would fault.

## 4. What the family *does* give you

Two things, both minor but worth recording because they are cheap and they never panic:

* **Entry 12 (`0x259810`)** is a pure probe: it answers "is this user address readable at this moment"
  without touching the page, because it takes the same range check and process gate and then returns
  without a memory access. Any handler that exposes it gives a page-presence oracle that does not rely on
  signal delivery.
* **Entries 10, 11, 13** are 8/4/1-byte user writes with a kernel-supplied value. They are the *inverse*
  of what an exploit wants, but any handler that passes a caller-controlled address to entry 10 while the
  value comes from kernel memory is, by definition, a kernel read. No such call site was found in the
  depth-4 reachable set (`docs/INTERPROC_COPYOUT_SOURCES.md`, 4,274 edges) - the write variants are
  called with the value already in a register computed from the syscall arguments.

## 5. Route 3 verdict

CLOSED. The "fourteen unaudited helpers" are the `fubyte/fueword/suword/cmpxchg/useracc` family, they are
uniformly correct, and the reason `657` looked interesting (it calls entry 11 with `rdi = [uap+0x10]`) is
that it is a *store* into a user address, which is harmless - see `docs/HANDLER_SHAPE_HUNT_14_10.md` for the
earlier path analysis that showed 657's length argument is always zero.
