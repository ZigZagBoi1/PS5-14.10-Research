# Deep RE: sys 601 — Process Control Multiplexer (16KB, narg=3)

## Entry Point (0x000)
```
Args: eax = cmd_code (0x00–0x27), r15 = arg1, r12 = arg2
Jump table: 40 entries at RIP+0xdb0af5
Stack canary: [0x2c7bce0]
```

## Command Map

| Cmd | Auth | Operation | Severity |
|-----|------|-----------|----------|
| 0x00 | No | Process state query + lock | LOW |
| 0x01 | No | Process init, reads +0x568 state | MEDIUM |
| 0x04 | **2 checks** | Privileged process control | LOW |
| 0x05 | No | 0xb8-byte process info leak | HIGH |
| 0x06 | No | Process status via proc+0x40 | MEDIUM |
| 0x07 | No | BEXTR bitfield extraction | HIGH |
| 0x09 | No | Global byte leak (0x316d0f8) | MEDIUM |
| 0x0a | No | Process +0x568→+0xe8 read | MEDIUM |
| 0x0b | No | Tail-call to 0xffb50dc0 | MEDIUM |
| **0x0c** | **HARDCODED** | **XOR auth: bytes must be 0xCD, 0x41** | **CRITICAL** |
| 0x0d | No | Thread enumeration via linked list | MEDIUM |
| 0x0e | Partial | Checks but may proceed anyway | HIGH |
| 0x0f | Partial | Flag-gated, 2 priv checks | MEDIUM |
| **0x10** | No | **0x1000-byte kernel alloc → copyout** | **HIGH** |
| **0x12** | No | **Write to proc +0x528/+0x578/+0x580** | **CRITICAL** |
| 0x13+ | No | Device state reads | MEDIUM |
| 0x14–0x19 | No | Device name matching + config | HIGH |

## CRITICAL: Command 0x0c — Hardcoded Authentication Backdoor (0x4a0)
```asm
xor al, 0xcd    ; byte[0] XOR 0xCD → must be 0
xor cl, 0x41    ; byte[1] XOR 0x41 → must be 0
or  cl, al      ; combined must be zero for success
```
Send bytes `{0xCD, 0x41}` to pass. Debug/development backdoor in production firmware.

## CRITICAL: Command 0x12 — Unchecked Process Structure Write (0x7b6)
```asm
test eax, 0x400        ; one-shot gate (bit 10)
jne  SKIP
or   rax, 0x1000000    ; set bit 24 in proc flags
mov  [r8+0x528], rax   ; write flags
mov  rax, [rbp-0xf0]   ; user_data[0]
mov  [r8+0x578], rax   ; WRITE arbitrary value
mov  rax, [rbp-0xe8]   ; user_data[8]
mov  [r8+0x580], rax   ; WRITE arbitrary value
```
Zero credential checks. First call always succeeds (one-shot bit only prevents re-execution).

## Device Name Matching (0x17b7–0x19cb) [PAST 4KB]
Compares user 16-byte buffer against 9 hardcoded device name strings (GPU/display/audio identifiers). Returns device type ID 1–9.

## Device Configuration Writer (0x1cf0–0x27f0) [PAST 4KB]
5KB sub-handler. Copyin 0x3c bytes. 9-way config write (0x1a28–0x1bbd): Writes 2-4 QWORDs to device struct per case, sets flag bits in [+0xd4/+0xd5]. NO credential check on any of 9 cases. Ring buffer operations (type 1 at 0x2080): Writes to +0x568→+0x58 ring buffer.

### VULNERABILITY — Signed Comparison Bypass (0x2288)
```asm
movsxd rdi, DWORD PTR [rbx+0x50]  ; SIGNED extend current offset
lea    eax, [rdi+r12*1]           ; offset + new_size
cmp    eax, 0x80001               ; compare against max
jl     WRITE_OK                   ; SIGNED comparison!
```
Negative offset at +0x50 passes this check → heap underflow write.

Ring buffer insertion (0x2670): Allocates 0x58-byte entry, populates from copyin'd data, links into queue at +0x568 via +0x40/+0x48, updates count at +0x30 with consistency check against +0xf8.

## Process Teardown (0x2e80–0x3469) [PAST 4KB]
1. Walks process +0x10 linked list, clears bit 0x400 in each entry's +0x528
2. Frees +0x578/+0x580 pointers (the same fields cmd 0x12 writes to — confirms they're pointers to kernel objects)
3. Walks +0xd0 linked list, freeing chained resources and +0x18 sub-pointers
4. Destroys mutex at +0x28
5. Drains ring buffer queue at +0x40
6. Frees device resources at +0xc0, +0x58, +0xf0, +0x188, +0x190
7. Compares PID against globals at 0x316d278/0x316d27c

**IMPORTANT**: Teardown confirms +0x578/+0x580 are kernel heap pointers freed via `0xfffffffffff687c0` (kfree). Cmd 0x12 writes user-controlled values there without auth → **use-after-free or arbitrary kfree primitive**.

## Init/Shutdown (0x2ab0) [PAST 4KB]
Case 0 (init): Creates device subsystem at 0x316d270, registers 6 event handlers with callbacks, sets up periodic tasks (interval 0x4e20 = 20000), creates 0x78-byte buffer, sets global flag at 0x316d0f0.

## Device Lookup by PID (0x3720) [PAST 4KB]
Iterates global list at 0x28e9850, matches +0x5d0 against PID, checks +0x464 bit 0x1, returns +0xbc (device ID). No auth.

## VFS Path Resolution (0x3800) [PAST 4KB]
Complex path lookup: allocates path buffer, does namei-style VFS lookup with `0xffffffffff95a0b0` (kern_openat analog), checks vnode type (0x1d4 = VDIR for directories), walks up path components stripping trailing `/`.

## Device Control (0x3a60) [PAST 4KB]
Permission bit checks at [r15+0xc] for bits 0x1 and 0x2. Allocates 0x30-byte control block via `0xfffffffffff68520`, iterates device table at [r15+r13*8+0x2b8] and [r15+r13*8+0x2c0].

## Vulnerability Summary
### CRITICAL
1. Cmd 0x0c — Hardcoded auth backdoor: Bytes 0xCD/0x41 pass. STRUCTURAL.
2. Cmd 0x12 — Unchecked process struct write → arbitrary kfree / use-after-free.

### HIGH
3. Ring buffer signed comparison (0x2288): heap underflow.
4. Cmd 0x10 — Kernel page content leak: 0x1000-byte copyout without zeroing.
5. 9-way device config write: All cases without auth.

### MEDIUM
6. Cmd 0x05 — 0xb8 byte process info leak.
7. Cmd 0x07 — BEXTR state extraction.
8. Cmd 0x09 — Global byte leak at 0x316d0f8.

### 14.10 Survivability
- Hardcoded auth (0xCD/0x41): STRUCTURAL
- proc struct writes: STRUCTURAL
- Ring buffer signed comparison: PERSISTENT
