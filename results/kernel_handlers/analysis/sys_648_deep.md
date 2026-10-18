# Deep Analysis: sys 648 (Syscall 0x288) - GPU/Display Context Manager

**Firmware**: 13.60 | **Kernel base**: 0xffffffff8a9c0000 | **Handler size**: ~12KB (0x3000) | **narg**: 1

## 1. Handler Overview

sys 648 manages GPU rendering contexts and display pipeline configuration. It handles context creation, teardown, memory region allocation, display mode switching, and hardware capability probing. The handler operates on a single argument (narg=1) which is a pointer to a user-supplied parameter structure.

### Entry Points
The binary contains multiple distinct functions at different offsets, not a single monolithic handler:
- **0x0000**: Entry gate / mode-switch handler (small, ~0x74 bytes)
- **0x0080**: Accessor helper (returns `[rdi+0x5a0]`, trivial)
- **0x00A0**: Main dispatch handler (~0xA50 bytes) - primary syscall entry
- **0x0AF0**: Context allocation and initialization (~0x420 bytes)
- **0x10A0**: Memory region copyin with scatter-gather (~0x270 bytes)
- **0x1310**: Configuration tree parser (~0x410 bytes)
- **0x1730**: Copyout wrapper (~0x38 bytes)
- **0x1770**: Context teardown/release (~0x290 bytes)
- **0x1A00**: Device tree lookup + address validation (~0xD0 bytes)
- **0x1AD0**: Address range validator (~0x90 bytes)
- **0x1B60**: Memory extent parser + size validation (~0xC0 bytes)
- **0x1C20**: Display pipeline setup / region configuration (~0x400 bytes)
- **0x2020**: Main context configuration dispatcher (~0x480 bytes)
- **0x24A0**: VRAM resize / expansion handler (~0x120 bytes)
- **0x25C0**: Full context setup with display mode handling (~0x7E0 bytes)

### Stack Frame (main handler at 0x00A0)
- `sub rsp, 0x1c8` -- 456-byte stack frame
- Stack canary from `[rip+0x2f24065]` (at 0x2f24120), verified at epilogue (0xAC1: ud2 on mismatch)

## 2. Security Gate (offsets 0xDE-0x11C)

### Four-Layer Privilege Check
The main handler at 0x00A0 performs FOUR sequential privilege checks:
```
offset 0xde:  mov rdi, [rdi+0x140]    ; td->td_proc
              call 0xffffffffff874eb0   ; priv_check #1 (unknown priv code)
              test eax, eax
              jne 0x122                 ; pass -> continue

offset 0xf5:  call 0xffffffffffc10f20   ; priv_check #2
              test eax, eax
              jne 0x122                 ; pass -> continue

offset 0x105: call 0xffffffffffc10ee0   ; priv_check #3
              test eax, eax
              jne 0x122                 ; pass -> continue

offset 0x115: call 0xffffffffffc10eb0   ; priv_check #4
              test eax, eax
              je  0x481                 ; ALL FOUR FAILED -> error path
```

If ANY of the four checks returns nonzero (success), execution proceeds. Only if ALL FOUR fail does it go to the error path at 0x481 (which logs and returns error 1).

**NOTABLE**: This is an OR-based privilege gate, not AND. A process needs only ONE of four different privileges to access the handler.

### Entry Gate (0x0000)
Separate from the main handler:
```
offset 0x07:  mov rdi, [rdi+0x140]     ; td->td_proc
              call 0xffffffffffc10f20    ; single priv_check
              test eax, eax
              je 0x49                    ; success -> return 1
```
If priv_check passes: returns 1 (error/denied). If it fails (0): checks `[r14] == 0x7` (command code 7) and sets a flag `[rax+0x140] |= 0x8` on a global object at `[rip+0x31b5df0]`.

## 3. Main Dispatch Flow (0x00A0 - 0xAC1)

### Phase 1: Copyin User Structure (0x122-0x192)
```
offset 0x122: mov rbx, [rbx]            ; dereference arg[0] -> user pointer
              mov rdi, gs:0              ; curthread
              call 0x2221f0              ; trace/ktrace
              mov edx, 0x178             ; size = 376 bytes
              call 0xffffffffff861090    ; copyin(user_ptr, kern_buf, 376)
```
Copies a 376-byte (0x178) structure from userspace to the stack at `[rbp-0x1a8]`.

### Phase 2: Version/Type Check (0x192-0x21A)
```
offset 0x192: cmp QWORD PTR [rbp-0xf8], 0x0   ; check field at +0xb0 (callback ptr?)
              je  0x209                          ; if null -> return EINVAL (0x16)
offset 0x1c1: cmp eax, 0x20f00                  ; compare type code
              sete dl
```
Validates that the structure contains a non-null callback/reference pointer, and that the type code at `[rbp-0x158]` is valid. Special handling for type 0x20f00.

### Phase 3: Context Resolution (0x21A-0x326)
```
offset 0x225: cmp eax, 0x1000000          ; if type >= 0x1000000
              jb  0x2e8                    ; skip extended path
offset 0x232: call 0x10f730               ; check if extended mode available
              ...
              call 0x10a0                  ; memory region copyin (scatter-gather)
              ...
              call 0x1310                  ; config tree parser
```
For type codes >= 0x1000000 (extended contexts), performs additional memory region setup and configuration parsing.

### Phase 4: Event System Registration (0x337-0x4D1)
Acquires a mutex at `[rip+0x31b5df8]`, looks up an event handler table via `0xffffffffffd460f0`, increments a refcount at `[rax+0xc]`, then iterates through a linked list of event handlers at `[rax+0x40]`:
```
offset 0x3b6: cmp DWORD PTR [r12+0x10], 0xffffffff  ; skip disabled entries
              je  0x3a9
              ...
              mov r13, [r12+0x28]                     ; get handler function ptr
              ror rax, 0x3                            ; pointer authentication
              cmp rax, 0x197                          ; bounds check (407 entries max)
              jbe 0x390                               ; valid -> call handler
```
**Pointer authentication**: Uses `ror rax, 0x3` and bounds check against 0x197 to validate function pointers before calling through them.

### Phase 5: Display Mode Configuration (0x414-0x53C)
```
offset 0x414: cmp DWORD PTR [rbp-0x158], 0xf000   ; type 0xf000 = display reset
              ...
              cmp QWORD PTR [rbp-0xe0], 0xffffffffffffffff  ; mode = -1
              je  0x50c                                       ; force disconnect
              ...
              cmp QWORD PTR [rbp-0xe0], 0x0                  ; mode = 0
              jne 0x522                                       ; specific address
              call 0x1a00                                     ; device tree lookup
```
Handles display mode values:
- `-1` (0xFFFFFFFFFFFFFFFF): force disconnect mode
- `0`: auto-detect via device tree lookup at 0x1A00
- Other: treat as physical address, shifted left by 20 bits (`shl rax, 0x14`)

### Phase 6: Full Context Setup (0x58F-0x806)
Calls 0x1C20 (display pipeline setup), then 0x2020 (main context configuration), then enters the event notification phase with a second set of handler iterations.

### Phase 7: Post-Setup Validation (0x989-0xABF)
For type code 0 contexts:
```
offset 0x989: mov rax, [rip+0x31b5df0]  ; global display object
              mov edi, [rax+0x124]       ; get current display ID
              call 0xffffffffffc1eb50    ; validate display capability
              test al, al
              je  0xa44                  ; not capable -> error 0x58
```
Validates the hardware display capability matches the requested context. On failure, sets the global flag `[rax+0x140] |= 0x200`.

## 4. Sub-function Analysis (Past 0x1000)

### 0x10A0: `memory_region_copyin` (Scatter-Gather Copy)
```
offset 0x10c2: cmp rsi, 0x100001         ; max size 1MB + 1
               jb  0x10eb                 ; ok
               ...                        ; else return 0xc (ENOMEM)
```
Allocates kernel pages via `0xffffffffffa322f0` (vm_page_alloc), then iterates through the allocated page chain:
- Each page has a `flags` field at `+0x1c` with bit 0x100 (direct-mapped) and 0x200 (large-page)
- For direct-mapped: size is `[r13+0x88]`
- For large-page: size is 0xe0 (224 bytes)
- Otherwise: size is 0x88 (136 bytes)
- Copies min(remaining, page_size) bytes from userspace per page
- After copying, calls `0x162960` (page table update/finalize)

**VULNERABILITY**: Size is validated against 0x100001 but the comparison is `cmp rsi, 0x100001; jb` meaning max is exactly 0x100000 (1MB). However, the allocation call at 0xffffffffffa322f0 uses the uncapped size directly. If the allocator returns fewer pages than needed, the copy loop could read past allocated memory.

### 0x1310: `config_tree_parser`
Parses a hierarchical configuration tree from a memory-mapped file/buffer:
```
offset 0x131a: lea rsi, [rip+0x8ee5e8]   ; root key string
               call 0x1628d0              ; tree_lookup(node, key)
               ...
               call 0x162140              ; get_node_type(node)
               cmp eax, 0x2               ; type 2 = dictionary
```
Tree traversal pattern:
1. Look up root key (0x8ee5e8)
2. Expect type 2 (dictionary)
3. Look up nested key (0x8a3381)
4. Expect type 2 (dictionary)
5. Look up next key (0x92a45a)
6. Expect type 2 (dictionary)
7. Allocate 4 bytes, store at `[r15+0x5a0]`
8. Look up multiple sub-keys, each parsed as a 2-byte string comparison:
   - Key at 0x923b77: sets bits in `[rbx+0x2]` -- nibble 0 (values: +1, |2, &0xf0)
   - Key at 0x944bd0: sets bits in `[rbx+0x2]` -- nibble 1 (values: |0x10, &0x0f)
   - Key at 0x9153b2: sets bits in `[rbx+0x2]` -- nibble 2 (values: |0x100, &0xf0ff)
   - Key at 0x8ad564: sets bits in `[rbx+0x2]` -- nibble 3 (values: |0x1000, |0x3000, |0x4000, &0x0fff)

The tree parser decodes display capability flags from a structured configuration, likely a device tree or firmware configuration blob.

### 0x1770: `context_teardown`
```
offset 0x17d1: and eax, 0xfffffffe         ; mask out bit 0
               cmp eax, 0x4                 ; state == 4 or 5?
               jne 0x17fe                   ; if not -> log warning + skip
```
Only tears down contexts in state 4 or 5 (active/suspended). For valid contexts:
1. Unlinks from doubly-linked list (with corruption checks at 0x1957, 0x19BE)
2. Decrements global counter at `[rip+0x31b5e30]`
3. Calls `0xffffffffffcef310` (resource release) then `0xffffffffffceef40` (cleanup)
4. Calls `0xffffffffffbad9a0` with the context's display ID
5. For type 0x2000100: calls `0xffffffffffbad980` (special display teardown)
6. Checks global slot registers at `[rip+0x31b5e44]` and `[rip+0x31b5e4c]` for active display handles
7. Calls `0xffffffffffe62690` to release display handle
8. Calls 0x3E60 for final cleanup

**Linked list integrity checks**:
```
offset 0x17e5: cmp [rax+0x8], r14         ; prev->next must == current
               jne 0x19be                   ; PANIC (ud2)
offset 0x17f2: cmp [rcx], r14             ; next->prev must == current
               jne 0x1957                   ; PANIC (ud2)
```
These are corruption detection assertions -- if the list is corrupted, the kernel panics.

### 0x1A00: `device_tree_address_lookup`
```
offset 0x1a1f: call 0xd4c20               ; check if device tree available
               ...
               call 0x1628d0              ; tree_lookup("...key...")
               ...
               call 0x162140              ; get_node_type -- expect 2 (dict)
               ...
               call 0x162140              ; get_node_type -- expect 3 (integer)
               call 0x162150              ; get_integer_value
               call 0x1ad0               ; validate address range
```
Looks up a physical address from the device tree. The address is validated by 0x1AD0 before use.

### 0x1AD0: `validate_address_range`
```
offset 0x1ad9: test rdi, rdi
               js   0x1aec               ; negative -> reject
offset 0x1ade: call 0x10450              ; get_total_memory_size
               shr  rax, 0x14            ; convert to 1MB units
               cmp  rax, rbx             ; address must be < total memory
               jae  0x1b11               ; ok
```
Validates that:
1. Address is non-negative
2. Address (in 1MB units) is less than total physical memory
3. Address is even (bit 0 must be 0: `test bl, 0x1; jne reject`)
4. If a global flag at `[rip+0x31bbf20]` is set, compares against a stored base address at `[rip+0x31bbec8]`

### 0x1B60: `memory_extent_parser`
```
offset 0x1b9e: call 0xa500               ; parse_extent(buffer, format_str, &size)
               ...
               cmp r8, 0xa00001           ; max extent: 10MB + 1
               jb  0x1bd7                 ; ok
               ...
               shl rax, 0x32             ; check 4KB alignment (shift by 50)
               je  0x1bfc                 ; aligned
```
Parses a memory extent descriptor. Validates:
- Maximum size: 0xA00000 (10MB)
- Alignment: must be 4KB-aligned (bits 0-11 must be zero, checked via `shl rax, 0x32`)
- Adds valid extent to context's memory pool at `[r14+0x5a8]`

### 0x1C20: `display_pipeline_setup`
Very large function (~0x380 bytes). Sets up GPU display pipeline regions based on display type codes.

Key operations:
1. Increments a global counter at `[rip+0x31bbf20]` -- acts as a **reentrancy guard/nesting counter**
2. Calls `0x10450` to get total memory, then computes region offsets
3. Calls `0xffffffffff9d13b0` (memory controller init?)
4. Iterates through 48 (0x30) hardware capability registers via `0xeeed0`:
   ```
   offset 0x1e38: mov edi, r15d          ; register ID (starts at 0x78288001)
                  call 0xeeed0            ; probe_hw_capability(id, &result)
                  add r15d, 0x100         ; next register
                  cmp r13, 0x30           ; 48 registers total
   ```
5. For special register indices (6-13, 14, 19): overrides with fixed values
6. Calls `0xffffffffff9d1380` for each valid capability region

**Display type dispatch table** (based on `[rbx+0x118]`):
| Type Code | VRAM Base | VRAM Size | Description |
|-----------|-----------|-----------|-------------|
| 0x0 / 0x10300 | auto | 0x200000 | Standard context |
| 0xF000 / 0xF100 | auto | 0x4000000 | Display output (with flag 0x20) |
| 0x10000 | auto | 0x200000 | Compute context (flag 0x1) |
| 0x10100 / 0x10200 / 0x20000 / etc. | auto | 0x200000 | Various pipeline configs |
| 0x1F000 / 0x1F100-0x1F500 | auto | 0x1800000 | Extended display |
| 0x20F00 | auto | 0x7000000 | High-bandwidth mode |
| 0x200F100 | auto | 0x1800000 | Extended + overlay |

### 0x2020: `context_config_dispatcher`
Allocates and configures a GPU context object:
```
offset 0x2031: mov eax, [rip+0x31bbf3c]   ; pending context bitmask
               ...
               tzcnt r15d, eax              ; find first free slot
               btr   eax, r15d              ; clear that bit
               mov   [rip+0x31bbf3c], eax   ; update bitmask
```
Uses a bitmask to find an available context slot (BSF/TZCNT). Then:
1. Allocates a primary structure (0x5C0 bytes from zone allocator at 0x1b6bb60)
2. Allocates a secondary buffer (0x3200 or 0x190 bytes depending on `[r13+0x50]`)
3. Acquires an fd from `0xffffffffff9a16f0` (file descriptor allocation)
4. If fd allocation fails: frees all allocations and returns error 0x23
5. Links the context into a global list at `[rip+0x31b5e28]`
6. Sets context state to 5 (active): `mov DWORD PTR [rbx+0xb0], 0x5`
7. Stores context to global at `[rip+0x31b5df0]`

### 0x24A0: `vram_resize`
```
offset 0x24bd: add rbx, 0x1fffff         ; round up to 2MB
               and rbx, 0xffffffffffe00000
               cmp rbx, 0x5000000         ; max 80MB
               ja  0x2591                 ; PANIC
```
Resizes VRAM allocation. Validates:
- Maximum 80MB (0x5000000)
- Available space check: `current_size + 0x63400000` must exceed requested size
- Calls `0xfffffffffffff9d0` (kernel memory allocator) with 2MB alignment

### 0x25C0: `full_context_setup`
The largest function (~0x7E0 bytes). Performs complete display/GPU context configuration:

1. **Display type classification** (0x25FA-0x296F): A massive switch on `[rbx+0x118]` (display type code) that sets region sizes, VRAM limits, and capability flags for each supported display configuration
2. **Memory region allocation** (0x2A17-0x2D96): Another switch on the same type code that computes per-region sizes and allocates them
3. **Physical memory allocation** (0x2DA6-0x2F48): Uses `0xfffffffffffff9d0` and `0xfffffffffffffcb0` to allocate physical VRAM regions
4. **Display configuration** (0x2F48-end): Writes firmware version strings, hardware capability tables, and display timing parameters

## 5. Key Global Data Structures

| Address (RIP-relative) | Description |
|------------------------|-------------|
| 0x31b5dd0 | Primary mutex for context operations |
| 0x31b5de8 | Thread ownership / lock state |
| 0x31b5df0 | Active GPU context pointer |
| 0x31b5df8 | Secondary mutex for event system |
| 0x31b5e10 | Lock owner thread pointer |
| 0x31b5e18 | Cached thread pointer |
| 0x31b5e20 | Context list head (for iteration) |
| 0x31b5e28 | Context list tail (for insertion) |
| 0x31b5e30 | Active context count (DWORD) |
| 0x31b5e40 | Display handle slot A (WORD + DWORD) |
| 0x31b5e48 | Display handle slot B (WORD + DWORD) |
| 0x31b5dc0 | Current display context pointer |
| 0x31b5dc8 | Display memory base address |
| 0x31bbec8 | Configured VRAM base (1MB-shifted) |
| 0x31bbf10 | Hardware capabilities object |
| 0x31bbf20 | Reentrancy counter / nesting depth |
| 0x31bbf28 | Total available VRAM |
| 0x31bbf30 | VRAM region end address |
| 0x31bbf38 | Active display slot ID |
| 0x31bbf3c | Free context slot bitmask |
| 0x2f24120 | Stack canary reference |

## 6. Vulnerability Analysis

### VULNERABILITY 1: OR-Based Privilege Gate (MEDIUM)
**Location**: offsets 0xDE-0x11C
The handler accepts ANY of four different privilege checks. If any one privilege is weaker than the others, an attacker with that single privilege gains full access to all GPU/display context operations. This is a broader attack surface than typical AND-based gates.

### VULNERABILITY 2: Missing Size Validation in Scatter-Gather Copy (MEDIUM-HIGH)
**Location**: sub-function 0x10A0, offset 0x10C2
The size is validated against 0x100001, but the page allocation at `0xffffffffffa322f0` receives the raw size. If the allocator returns a partial allocation (fewer pages than needed for the full size), the copy loop at 0x1130-0x11B0 iterates until `r15` (remaining) reaches zero, but each page's usable size depends on its flags. A carefully crafted size could cause the loop to read past the last allocated page.

### VULNERABILITY 3: Integer Overflow in Display Address Computation (LOW-MEDIUM)
**Location**: sub-function 0x1A00 and main handler at 0x522
User-provided display mode value is shifted left by 20 bits: `shl rax, 0x14`. For values close to the upper limit, this could overflow a 64-bit value. The address validator at 0x1AD0 checks `test rdi, rdi; js reject` (sign check) but only after the shift.

### VULNERABILITY 4: Race Condition in Context Bitmask (MEDIUM)
**Location**: sub-function 0x2020, offset 0x2031-0x204B
The free context bitmask at `[rip+0x31bbf3c]` is read, modified (TZCNT + BTR), and written back without holding a lock. If two threads enter 0x2020 simultaneously, they could both claim the same context slot, leading to a use-after-free or double-free condition.

### VULNERABILITY 5: Refcount Race on Event Handlers (LOW-MEDIUM)
**Location**: main handler, offsets 0x361-0x4B7
Event handler objects are referenced via increment (`lea ecx, [rax+0x1]; mov [rbx+0xc], ecx`) and decremented after iteration (`dec eax; mov [rbx+0xc], eax`). These increments/decrements are NOT atomic. Under concurrent access, the refcount could underflow, leading to premature deallocation.

### VULNERABILITY 6: Linked List Corruption Escalation (LOW)
**Location**: sub-function 0x1770, offsets 0x1957 and 0x19BE
The integrity checks on the doubly-linked list trigger `ud2` (panic) on corruption. While this prevents exploitation of corrupted lists, an attacker who can corrupt the list from another vulnerability can force a kernel panic (denial of service).

### VULNERABILITY 7: VRAM Resize Without Context Lock (LOW-MEDIUM)
**Location**: sub-function 0x24A0
The VRAM resize function reads and writes the global display object at `[rip+0x31b5df0]` and modifies VRAM bounds at `[r14+0x90]` and `[r14+0xc8]` without visible locking. A concurrent resize or context teardown could corrupt the VRAM mapping.

### VULNERABILITY 8: Unchecked Device Tree Parsing (LOW)
**Location**: sub-function 0x1310
The config tree parser traverses nodes without checking for cycles. A malformed configuration tree with circular references could cause an infinite loop in the kernel.

## 7. Summary

sys 648 is the GPU/display context management syscall. It implements:
1. GPU rendering context creation with 0x5C0-byte context objects
2. Display pipeline configuration for 20+ display type codes
3. VRAM region allocation with scatter-gather support
4. Event handler registration with pointer authentication (ror-based bounds check)
5. Doubly-linked list management with corruption detection assertions
6. Device tree parsing for display configuration

The handler has an OR-based four-way privilege gate (any one privilege is sufficient), uses non-atomic refcounting on event handler objects, and has a race condition in the free context bitmask. The most significant vulnerability is the scatter-gather copy size validation gap and the unlocked context bitmask.
