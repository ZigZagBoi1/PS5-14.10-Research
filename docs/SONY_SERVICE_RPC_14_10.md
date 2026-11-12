# Syscall 605 reaches Sony's service RPC dispatcher, and its error codes come back intact

Measured 2026-11-04 22:13 (probe `1207a`, capture
`results/phase17_new_vectors/1207a_605_service_magic_live_20261104_221352.txt`, COMPLETE, loader
alive). Static from the 13.60 dump, base 0xffffffff8a9c0000, offset == RVA.

## 1. The handler

Syscall **605**, narg 1, body RVA 0xa36b00:

```
a36b1c  mov eax,0x16            ; EINVAL by default
a36b21  mov edi,[rsi]           ; uap[0x00] = a 32-bit MAGIC WORD
a36b23  cmp edi,0x780263ff      ; five-entry whitelist, split by a signed compare
a36b2b  cmp edi,0x78026400
a36b33  cmp edi,0x78028a00
a36b3b  cmp edi,0x78028300
a36b45  cmp edi,0x19810000
a36b4d  cmp edi,0x3cc80700
a36b55  lea rsi,[rbp-0x1c]
a36b59  mov dword [rbp-0x1c],0
a36b60  call 0x8b4a70c0         ; the RPC entry
a36b65  movsxd rcx,dword [rbp-0x1c]
a36b69  mov [rbx+0x408],rcx     ; rbx = rdi = struct thread *, so this is td_retval[0]
a36b70  ...canary check, ret
```

So 605 is `service_rpc(magic) -> u64` where the result is written straight into the thread's return
slot. The five magics are **service identifiers**, not arguments.

## 2. The RPC entry is a general dispatcher

`0x8b4a70c0` is a five-instruction shim:

```
ae70c4  mov rdx,rsi        ; rdx = &out
ae70c7  mov esi,edi        ; esi = magic
ae70c9  mov edi,1          ; subsystem 1
ae70cf  jmp 0x8b4a70e0
```

The landing function checks three globals (state, error, mode) and returns **0x800d0201** if the
service layer is uninitialised, **0x800d020d** if it is in a bad state, then calls
`0x8b4ae460(1, 2, magic, 0, 4, &out48, &out44)` and finally `0x8b4adc20`.

`0x8b4acd70` is the command table dispatcher:

```
aecdd6  movzx r11d,word [rip+0x320b062]   ; table entry COUNT  (RVA 0x3cf7e47)
aecdde  mov eax,0x800d0203                ; "no such command"
aecde3  test r11,r11
aecde6  je  return_0x800d0203             ; <-- count == 0 lands here
...
aece0c  lea r15,[r8+r8*4]                 ; entry stride 5*8 = 0x28 bytes
aece10  mov ebx,[r10+r15*8+0x18]          ;   +0x18 dword  command id
aece1e  movzx r15d,byte [r12+0x15]        ;   +0x15 byte   number of sub-commands
aece2f  movzx r13d,byte [r12+0x16]        ;   +0x16 byte   index shift
aece40  shlx r14d,1,r13d ; add r14d,ebx    ;   sub-command = id + (i << shift)
aece7d  cmp rcx,r8 ; ja  return_0x800d0208 ;   output length must cover the table's size
aecf13  mov edx,0x101 ; call 0x8b5c8b50    ;   malloc(buffer size)
```

The table lives at RVA 0x3cf7e38, which is **outside every dump** (text ends at 0xE6E5C0), so its
contents cannot be read statically. Its *size* cannot be read either.

## 3. What the console actually said

| call | result |
|---|---|
| `605(0x78026400)` | **error_code 0x800d0203** |
| `605(0x78028a00)` | **0x800d0203** |
| `605(0x78028300)` | **0x800d0203** |
| `605(0x19810000)` | **0x800d0203** |
| `605(0x3cc80700)` | **0x800d0203** |
| `605(0x00000000)`, `0xFFFFFFFF`, `0x780263fe`, `0x78026401`, `0x7802c500`, `0x78020200`, `0x78020300`, `0x7802a500`, `0x7802b200` | EINVAL 22 |
| `606(anything)`, `605(magic in arg1)` | EINVAL 22 |

0x800d0203 is **2148336131** and the loader printed it verbatim as
`error_code=0x800d0203`. Grepping the dispatch path, the only instruction that materialises that
exact constant is `aecdde mov eax,0x800d0203`, guarded by `test r11,r11`. **The service table for
our process is empty.** All five whitelisted magics pass the front door and die on the same line.

## 4. The real discovery here is the channel

Every Sony handler that returns a status returns a **32-bit code with the top bit set**, and the
loader hands it back whole through `get_error_string()`:

```
0x800d0000 family  service errors
0x800d0201         service layer not initialised
0x800d0203         no entry in the command table      <- measured
0x800d0208         output buffer smaller than the table's declared size
0x800d020d         service in a transient bad state
```

That is a **branch oracle over kernel code we cannot read**. Until now the only feedback a probe
had was a small errno; now any Sony syscall that returns a status will tell us which of its guards
fired. This should be used as the primary instrument for every Sony-range syscall from here on:
call it with controlled arguments, read the code, and map the branch.

## 5. Status

| question | answer |
|---|---|
| Is there an unprivileged path into the Sony service dispatcher? | **Yes, syscall 605, five magic IDs.** |
| Is it usable? | Not on this console: the per-process service table is empty (0x800d0203). |
| Can we populate it? | No writer for the table exists in the reachable syscall set; the table itself is in .data, absent from every dump. |
| Does it leak? | No. The out value is written to `td_retval[0]` and returned; nothing is copied to userland. |
| What is it worth? | Two things: a documented 5-magic gateway for the next firmware, and a 30-bit branch oracle usable on every other Sony syscall. |
