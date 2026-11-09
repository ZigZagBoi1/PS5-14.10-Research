# Deep Analysis: sys 622 (Device Control Multiplexer)
## PS5 Prospero Kernel 13.60 | narg=6 | 24KB (0x6000) | 6194 lines

---

## 1. Handler Overview

sys 622 is the largest Prospero-specific syscall handler analyzed. It functions as a **device control multiplexer** dispatching to dozens of sub-handlers based on command codes. This is a central device management interface covering device queries, state updates, I/O control, tracing, and initialization.

### Arguments (6 total):
| Arg | Register | Purpose |
|-----|----------|---------|
| arg0 | r14d | Command code (device operation type) |
| arg1 | r15d | Sub-command or device index |
| arg2 | [rbp-0x80] | User buffer pointer (input) |
| arg3 | r13 | Secondary user address (copyin source) |
| arg4 | r12 | Buffer size (max 0x40 / 64 bytes) |
| arg5 | stack | Additional parameter |

---

## 2. Entry Point (0x000 - 0x0B5)

```
0x000: Standard prologue, stack canary from gs:0x28 -> [rbp-0x30]
       Global canary at 0x313F5D0
0x020: Arg extraction: r14d=[rsi], r15d=[rsi+8], [rbp-0x80]=[rsi+0x10],
       r13=[rsi+0x18], r12=[rsi+0x20]
0x045: cmp r12, 0x40  ; buffer size check
0x049: ja error        ; > 64 bytes -> return 0x800E0001
```

**NOTE:** The 0x40 size check only applies at the top level. Several sub-handlers use hardcoded copy sizes (0x18, 0x19, 0x30, 0x150) independent of arg4, and some paths bypass this check entirely.

---

## 3. Top-Level Dispatch Architecture (0x0B5 - 0x370)

### Multi-level command range routing:

```
cmd <= 0x270?
  ├─ YES: cmd in [0x100, 0x133]?
  │    ├─ YES: Bitmap auth gate -> Jump Table 1 (0xFA383C)
  │    └─ NO: cmd in [0x200, 0x270]?
  │         ├─ YES: Jump Table 2 (0xFA3D0C)
  │         └─ NO: cmd == 0x12D/0x130? Bitmap auth gate (bits 45,46)
  │              cmd in [0x302, 0x320]? Jump Table 3 (0xFA3ED0)
  │              cmd in [0x400, 0x493]? Jump Table 4 (0xFA3F4C)
  └─ NO: cmd == 0x271/0x372/0x473? Triple auth gate
         cmd == 0x520? Direct call to 0xABD830
         cmd == 0x813? Special path (validates r13, r12 independently)
```

### Jump Tables:
| # | Base Address | Index Range | Command Codes | Entries |
|---|-------------|-------------|---------------|---------|
| 1 | 0xFA383C | 0x00-0x33 | 0x100-0x133 | 52 |
| 2 | 0xFA3D0C | 0x00-0x70 | 0x200-0x270 | 113 |
| 3 | 0xFA3ED0 | 0x00-0x1E | 0x302-0x320 | 31 |
| 4 | 0xFA3F4C | 0x00-0x93 | 0x400-0x493 | 148 |
| 5 | 0xFA419C | 0x00-0x23 | Internal (type 0x10 sub-dispatch) | 36 |

---

## 4. Security / Privilege Checks

### 4.1 Bitmap-Gated Auth (commands 0x100-0x133)
```
0x0CE: movabs rcx, 0xF8FFF000000D5
       bt rcx, eax               ; test if bit (cmd-0x100) is set
       jnc skip_auth             ; if not set, SKIP privilege check
```
Bitmap selects SPECIFIC commands for privilege enforcement. Commands whose bit is 0 proceed **without any check**.

Bits set in 0xF8FFF000000D5: 0,2,4,6,7,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,35,36,37,38,39,40,41,42,43,44,47,48,49,50,51
Commands SKIPPED (no auth): 0x101, 0x103, 0x105, 0x108-0x10F, 0x11B, 0x11C, 0x11D, 0x12C, 0x12E, 0x12F, 0x131, 0x132, 0x133

### 4.2 Auth Check Functions
When triggered, the check is:
```
0x0E2: mov rdi, [rbx+0x140]      ; thread->td_ucred
0x0E9: call 0xE2C3D0             ; is_system_process_check_1()
0x0EE: cmp eax, 1
0x0F3: [fallback] call 0xE2C300  ; is_system_process_check_2()
0x106: cmp ecx, 1
       jne -> return 0x8002004E  ; EPERM equivalent
```

### 4.3 Triple-Check Gate (commands 0x271, 0x372, 0x473)
```
0x1F5: call 0xE2C3D0    ; check 1
0x20A: call 0xE2C300    ; check 2
0x226: call 0xA90360    ; check 3 (additional auth_id/priv_check)
```
These three commands require the STRICTEST authentication.

### 4.4 Bitmap-Gated Auth (commands 0x12D, 0x12E)
```
0x2CB: movabs rax, 0x600000000000   ; bits 45, 46
       bt rax, ecx                  ; select 0x12D and 0x12E only
       call check_1 / check_2
```

> **Correction (2026-10-19).** This section previously named `0x12D` and
> `0x130` as the pair selected by `0x600000000000`. The bitmap and the command
> names contradicted each other: bit 45 is `0x12D` and bit 46 is `0x12E`, while
> `0x130` is bit 48 and is set in the **first** bitmap, not the second.
>
> Resolved from `docs/dumps_13.60/kernel_text.bin` (RVA offsets):
>
> ```
> 0x7dce02  lea eax,[r14-0x100]        ; rax = cmd - 0x100
> 0x7dce09  cmp eax,0x33; ja 0x7dce4f ; only 0x100-0x133 reach either bitmap
> 0x7dce0e  movabs rcx,0xf8fff000000d5 ; first bitmap, 22 bits set
> 0x7dce18  bt rcx,rax; jae 0x7dd00b   ; bit clear -> try the second bitmap
> 0x7dd00b  movabs rcx,0x600000000000  ; second bitmap, bits 45 and 46
> 0x7dd015  bt rcx,rax; jae 0x7dce4f   ; both clear -> rejected
> 0x7dd01f  call 0x609110              ; the gated auth predicate
> ```
>
> First bitmap bits `{0,2,4,6,7,32-43,47-51}` are commands `0x100, 0x102,
> 0x104, 0x106, 0x107, 0x120-0x12B, 0x12F, 0x130-0x133`. The second bitmap
> covers exactly `0x12D` and `0x12E`, and is only consulted when the first
> bitmap's bit is clear. The gate therefore admits the union of both bitmaps
> into the `0x609110` auth path; everything else in `0x100-0x133` falls to
> `0x7dce4f`.
>
> `tools/test_sys622_bitmap.py` pins the bytes and both bit mappings.

### 4.5 Commands with NO Auth Check
| Range | # Commands | Notes |
|-------|-----------|-------|
| 0x200-0x270 | 113 | Direct copyin + dispatch, zero auth |
| 0x302-0x320 | 31 | Direct copyin + dispatch, zero auth |
| 0x400-0x493 | 148 | Direct copyin + dispatch, zero auth |
| 0x520 | 1 | Direct call to 0xABD830, no auth |
| Various in 0x100-0x133 | ~15 | Bitmap bit not set |

**CRITICAL: Over 300 command codes have NO privilege check whatsoever.**

### 4.6 No priv_check() Anywhere
Standard FreeBSD priv_check() is **completely absent** from this handler. All privilege enforcement uses Sony's custom is_system_process checks.

---

## 5. copyin Wrapper (0xE70 - 0xEBF)

```
0xE70: prologue
0xE7D: mov rdi, gs:0x0              ; curthread
0xE89: lea rsi, [rip+string]        ; "prospero_device_ctl"
0xE95: call 0x43D6A0                ; sx_xlock() / critical section enter
0xEAD: jmp 0xA7C540                 ; tail-call copyin()
```

Most dispatch targets use this pattern:
1. `lea rsi, [rbp-0x70]` (64-byte stack buffer)
2. `mov rdi, r13` (user pointer from arg3)
3. `mov rdx, r12` (size from arg4)
4. `call 0xE70` (copyin wrapper)
5. Check return, dispatch to sub-handler

---

## 6. Sub-functions (Past Offset 0x1000)

### 6.1 Device Context Handler (0xEC0 - 0x2437) - LARGEST
- **Stack frame:** 0x2C8 bytes
- **Event ID:** 0x970A (main), 0x1712-0x1716 (sub-events)
- **Sema type:** 0x8001 for device lookup
- **Device lookup mask:** 0x3FFFFFF (very permissive)

**Device Iteration Loop (0x1260-0x1850):**
- Iterates linked list of device entries via mutex-protected list
- PID matching: `[r12+0x4c]` vs `[rdi+0x9c]` (proc->p_pid)
- Timestamp computation via high-resolution timer and multiply constant 0x20C49BA5E353F7CF
- Event notification via function pointer at global 0x3419BE0 (with CFI pointer mangling via `ror rax, 3`)

**Sub-dispatch on device type [r14+0x10]:**
| Type | Handler | Description |
|------|---------|-------------|
| 0x01 | 0x1AA1 | Copyout 0x18 bytes from device+0xB0 |
| 0x10 | 0x1A64 -> 0x4340 | Complex device ioctl (own jump table) |
| 0x20 | 0x19D2 -> 0x4760 | Transfer setup |
| 0x30 | 0x19D2 -> 0x4760 | Transfer setup |
| 0x40 | 0x196B | Secondary device_lookup (type 0x8004, mask 0x7FFFFFF) |
| 0x50 | 0x19D2 -> 0x4760 | Transfer setup |
| 0x60 | 0x19D2 -> 0x4760 | Transfer setup |

### 6.2 Device State Query - 0x2440 (Event 0x4714)
- Sema type: 0x8002
- Checks device flag bit 0x20000
- If set: reads PID from descriptor+0x194
- If not set: returns 0x3020001 (device not ready)
- **No additional privilege check**

### 6.3 Device Property Read - 0x2760 (Event 0x4715)
- Type code: 0x4630000
- Hash table lookup via global 0x2DAD120
- Matches property ID at [r15+0xBC]
- Reads value from [r15+0x460]
- **No bounds check on property ID**

### 6.4 Device Property Read Alt - 0x2B60 (Event 0x4716)
- Type code: 0x4640000
- Similar hash table pattern
- Reads via indirect call to 0xE2C250

### 6.5 Device Status Query - 0x2F60
- Sema type: 0x8002
- Checks flag bit 0x20000
- Secondary device_lookup (type 0x8001)
- Copies 8-byte result to user

### 6.6 Event Counter Read - 0x3300 (Event 0x1718)
- Sema type: 0x8001
- Reads event count from descriptor+0x90
- Copies 8 bytes to user

### 6.7 Device Property Extended - 0x3580 (Event 0x271B)
- Sema type: 0x8004
- Checks flag bit 0x20000000
- Reads 8 bytes from descriptor+0x1B0

### 6.8 Device Feature Query - 0x3860 (Event 0x4718)
- Sema type: 0x8002
- Checks flag bit 0x10000
- Reads 8 bytes from descriptor+0x8F8

### 6.9 Device Capability Query - 0x3B50 (Event 0x271A)
- Sema type: 0x8004
- Checks flag bit 0x4000000
- Reads 4 bytes from descriptor+0x3C

### 6.10 Device Name Copy - 0x3E30 (Event 0x1719)
- Sema type: 0x8001
- Hardcoded copy of 0x19 (25) bytes
- **Potential info leak if source < 25 bytes**

### 6.11 Device Descriptor Copy - 0x4090 (Event 0x271C)
- Sema type: 0x8004
- Checks byte at descriptor+0x23 bit 0x20
- If not set: copies 0x19 bytes
- If set: returns 0x46B0001 (busy)

### 6.12 Complex Device I/O Control - 0x4340 (Type 0x10 handler)
- **Contains internal jump table at 0xFA419C with 36 entries**
- Dispatches via call to 0xBC43D0 (device_ioctl_dispatch)
- **Buffer size computation vulnerability at 0x444C:**
  ```
  r15 = [rax+0x10]        ; buffer limit
  add r15, -0x18           ; subtract header
  cmp rbx, r15             ; check user size vs limit
  ```
  If `[rax+0x10] < 0x18`, the subtraction **underflows** to ~0xFFFFFFFFFFFFFFE8, bypassing the bounds check completely.
- Code 0x59: Calls 0x38AE70 (release_device)
- Path 0x44A0: Extended ioctl via 0x4A60

### 6.13 Device Transfer Setup - 0x4760 (Types 0x20/0x30/0x50/0x60)
- Sema type: 0x8002
- Reads function pointer table at descriptor+0x468
- Flag check: `and ecx, 0x20020; cmp ecx, 0x20000`
- If ioctl 0x900 pending: sets flag 0x200
- Copies 0x18 bytes to user

### 6.14 Extended Ioctl Handler - 0x4A60
- Multi-step: copyin 0x18 bytes, then device buffer write (0xBC27A0)
- Uses 0x3FFFFFF mask for device operations
- Error handling calls 0x38AE70 (release_device)
- Sets result flags 0xA0020320

### 6.15 Event Writer - 0x4BE0 (Events 0x970D, 0x970E)
- Device lookup with type 0x8002
- Flag check: `0x4000320 & [rdi+0x20] == 0x4000000`
- Two layout paths:
  - Path 0x970E (flag 0x53 | 0x10): 5-element stride at device+0x5F8
  - Path 0x970D (default): 3-element stride at device+0x478
- Increments counter at [device+0x900]
- Reads linked descriptor at device+0x460 and device+0x198

### 6.16 Linked List Scanner - 0x4F90
- Iterates global list from [0x1D60D68 + 0x38]
- Flag filtering: bit 0x1 required, bits 0x500 must be clear
- Matches on 3 fields: [rbx+0x18], [rbx+0x1c], [rbx+0x48]
- Also checks [rbx+0x4c] == -1 (unbound entry)
- Copies 0x150 bytes via 0xA7C370 (kernel memcpy)
- Sets PID at [rbx+0x4c] from proc->p_pid ([r11+0x9c])

### 6.17 Initialization/Registration - 0x5060
- Creates device entries via 0xF61000 (device_create)
  - Entry 1: name at 0xB88ADE, dispatch table at 0xA8AB60, name at 0xAD0B86, timeout 10000
  - Entry 2: name at 0xB0A95E, dispatch table at 0xA8AB68, name at 0xB04D16, timeout 10000
- On failure: returns 0x800E0040
- On success: calls 0x5330 (module init)

### 6.18 Device Reset - 0x5120
- Simple: zeroes [rsi+0x540] (8 bytes) and [rsi+0x548] (4 bytes)

### 6.19 Bulk Device Enumeration - 0x5140
- Allocates 0x4000 (16KB) buffer
- Enumerates all device types sequentially:
  - Type 0x8002: calls per-device handler 0xABBC00
  - Type 0x8004: calls per-device handler 0x28EB60
  - Type 0x8001: calls per-device handler 0x28DF60
  - Type 0x8008: calls per-device handler 0xBC2C30 (with property ID from [rbx+0xBC])
- Frees buffer via 0x42C0B0

### 6.20 Module Initialization - 0x5330
- Creates device subsystem via 0xBBCAA0 -> global 0x1D60D60
- Allocates global state table at 0x1D60D68 (size 0x48)
- Creates ring buffers:
  - Size 0x908 at 0x1D60D70 (name: "babe2f")
  - Size 0x1C8 at 0x1D60D78 (name: "e2c1")
  - Size 0x20 at 0x1D60D80 (name: "3aca")
- Calls init chain: 0xE32150, 0xBC4CF0, 0x38B350, 0x4229E0, 0x423DB0, 0x425E10

### 6.21 Data Parser - 0x5540
- Reads aligned data: `(size + 3) & ~3` alignment
- Returns DWORD at offset `aligned_size + 0xC`

### 6.22 Timestamp Parser - 0x5560
- If type field == 3: computes `(hours * 100000) + (minutes * 1000) + seconds`
- Returns 1 on success, 0 on type mismatch

### 6.23 Callback Registration - 0x55A0
- 8 global callback slots at 0x32582B0-0x32582E8
- Scans for first NULL slot, stores function pointer
- If all 8 full: logs error, returns -1
- **No validation of the function pointer stored**

### 6.24 Trace Event Builder - 0x5660
- Constructs structured trace records from device state
- Iterates device tree reading fields in order: types 2-9, 0xF, 0x10-0x13, 0x14-0x17
- Calls 0xA7C9E0 (store_trace_value) for each field
- Reads nested device tree (device+0xB0 linked list)
- Checks flag at [r15+0x9D]: skips types 3 and >4
- Frees trace buffer, writes event record

### 6.25 Core Device Dump/Snapshot - 0x59E0
- **0xB8 stack frame** (largest of tail functions)
- Reads thread->td_ucred at [rdi+0x140]
- Iterates device tree: [rax+0x200] (proc->p_fd?)
- Filters by flags at [r14+0x60] (not 0x402) and [r14+0x64]
- Constructs multi-segment snapshot records with type IDs 1-11
- Segment sizes: 0x78, 0xE0, 0x200, 0x18 (device data)
- Allocates via 0x42BE10 with zone 0x241F340
- Calls two serialization functions:
  - 0xF525C0 (data type 0x570)
  - 0xD61470 (data type 0x488)
- Builds linked list of segments via [rax+0x28] / [rdx]

---

## 7. Tracing / Telemetry System

### Global State:
| Address | Purpose |
|---------|---------|
| 0x24D32C0 | Trace enable flag |
| 0x3419BE0 | Trace function pointer (CFI-protected) |
| 0x32AB90 | is_tracing_enabled() |

### CFI Protection on Trace Function:
```
0xFD5: r15 = [0x3419BE0]
0xFDC: lea rax, [0xA8C6A8]        ; expected base
0xFE3: sub rax, r15
0xFE6: ror rax, 3                  ; pointer authentication
0xFEA: cmp rax, 1
0xFEE: ja crash                    ; if not valid, ud2
```

### Event IDs Used:
| ID | Location | Context |
|----|----------|---------|
| 0x970A | 0xEC0 | Main device context handler entry |
| 0x970D | 0x4F16 | Device event write (3-element) |
| 0x970E | 0x4DEA | Device event write (5-element) |
| 0x1712 | 0xEC0 region | Device context result |
| 0x1713-0x1714 | 0xEC0 region | Device notification events |
| 0x1715-0x1716 | 0xEC0 region | Per-device events |
| 0x170C | 0x49EB | Event type 3 marker |
| 0x170F | 0x49FC | Event type 0xA0 marker |
| 0x1718 | 0x3300 | Event counter read |
| 0x1719 | 0x3E30 | Device name copy |
| 0x271A | 0x3B50 | Device capability query |
| 0x271B | 0x3580 | Device property extended |
| 0x271C | 0x4090 | Device descriptor copy |
| 0x4714 | 0x2440 | Device state query |
| 0x4715 | 0x2760 | Device property read |
| 0x4716 | 0x2B60 | Device property alt read |
| 0x4718 | 0x3860 | Device feature query |

---

## 8. Key Global Data Structures

| Address | Type | Purpose |
|---------|------|---------|
| 0x313F5D0 | QWORD | Stack canary (global) |
| 0x3419BE0 | QWORD | Trace function pointer |
| 0x24D32C0 | DWORD | Trace enable flag |
| 0x2DAD120 | ptr | Device hash table base |
| 0x2DAD0D0 | DWORD | Hash table mask |
| 0x2DAD0D8 | ptr | Hash table buckets |
| 0x1D60D60 | ptr | Device subsystem handle |
| 0x1D60D68 | ptr | Device state table |
| 0x1D60D70 | ptr | Ring buffer 1 (size 0x908) |
| 0x1D60D78 | ptr | Ring buffer 2 (size 0x1C8) |
| 0x1D60D80 | ptr | Ring buffer 3 (size 0x20) |
| 0x32582B0-0x32582E8 | 8 QWORDs | Callback function pointer slots |
| 0x1A1D700 | DWORD | Serialization flag 1 |
| 0x1A1D768 | DWORD | Serialization flag 2 |

---

## 9. Semaphore Usage Pattern

| Sema Type | Hex | Usage |
|-----------|-----|-------|
| 0x8001 | Device lookup | General device access, name copy, event counter |
| 0x8002 | Device state | State queries, property reads, feature queries, transfers |
| 0x8004 | Device descriptor | Capability queries, descriptor copies, extended properties |
| 0x8008 | Device extended | Bulk enumeration only |

---

## 10. Vulnerability Summary

### V1: CRITICAL - Missing Auth on 300+ Commands
- **Location:** Dispatch at 0x10F-0x370
- **Commands:** 0x200-0x270, 0x302-0x320, 0x400-0x493 (292 total)
- **Impact:** Any unprivileged process can invoke device control operations
- **Exploitation:** Direct syscall with any command in these ranges reaches device manipulation code without any credential check

### V2: HIGH - Integer Underflow in Buffer Size Check (0x4340)
- **Location:** Offset 0x444C-0x4455
- **Code:** `add r15, -0x18; cmp rbx, r15`
- **Condition:** If `[rax+0x10] < 0x18`, the subtraction wraps to ~0xFFFFFFFFFFFFFFE8
- **Impact:** Bypasses bounds check, allows arbitrary-length copy into kernel buffer
- **Exploitation:** Requires reaching type 0x10 device ioctl path with a crafted device descriptor where the buffer limit field < 0x18

### V3: HIGH - TOCTOU in Device List Iteration (0xEC0)
- **Location:** Offset 0x1380-0x189D
- **Pattern:** mutex_lock -> read device fields -> mutex_unlock -> use device data
- **Impact:** Device can be freed/modified between unlock and use
- **Exploitation:** Race condition between two threads - one iterating devices, one destroying a device

### V4: MEDIUM - Unvalidated Hash Table Lookup (0x2760, 0x2B60)
- **Location:** Sub-functions at 0x2760 and 0x2B60
- **Issue:** User-controlled property ID used directly as hash table key without bounds validation
- **Impact:** Could access out-of-bounds hash buckets or cause excessive chain traversal

### V5: MEDIUM - Permissive Device Access Mask
- **Location:** 0x115D (0x3FFFFFF), 0x4AE8 (0x3FFFFFF), 0x4C06 (0x3FFFFFF)
- **Issue:** Device lookup uses 26-bit permission mask allowing access to nearly all device types
- **Impact:** Overly broad device access for any caller reaching these paths

### V6: MEDIUM - Information Leak via Fixed-Size Copy (0x3E30)
- **Location:** Offset 0x3E30 (device name copy)
- **Issue:** Always copies 0x19 (25) bytes regardless of actual name length
- **Impact:** Leaks uninitialized kernel memory to userspace if name < 25 bytes

### V7: MEDIUM - Unvalidated Callback Function Pointer Storage (0x55A0)
- **Location:** Offset 0x55A0 (callback registration)
- **Issue:** Stores user-provided function pointer into global slot without validation
- **Impact:** If reachable from userspace, allows writing arbitrary pointer to kernel global

### V8: LOW - Bitmap Auth Bypass for Adjacent Commands
- **Location:** 0x0CE (bitmap 0xF8FFF000000D5)
- **Issue:** ~15 commands in 0x100-0x133 range skip auth check due to bitmap bit being 0
- **Impact:** These specific commands accessible to unprivileged processes

### V9: LOW - Missing Stack Buffer Initialization
- **Location:** Multiple sub-handlers using `[rbp-0x70]` as copyin target
- **Issue:** Stack buffer not zeroed before partial copyin (if size < 0x40)
- **Impact:** Sub-handlers may read stale stack data for unused buffer portions

---

## 11. Key External Function Addresses

| Function | Call Target | Purpose |
|----------|------------|---------|
| is_system_check_1 | 0xE2C3D0 | Primary privilege check |
| is_system_check_2 | 0xE2C300 | Fallback privilege check |
| auth_check_3 | 0xA90360 | Third privilege gate |
| device_lookup | 0xE31ED0 | Device handle lookup |
| device_release | 0xE31F90 | Device handle release |
| copyin | 0xA7C540 | Kernel copyin |
| copyout | 0xA7C370 | Kernel copyout (memcpy in some paths) |
| sx_xlock | 0x43D6A0 | Exclusive lock acquire |
| mutex_lock | 0x46EDE0 | Mutex lock |
| mutex_unlock | 0x46F770 | Mutex unlock |
| release_device | 0x38AE70 | Device descriptor release |
| device_create | 0xF61000 | Device registration |
| device_subsys_create | 0xBBCAA0 | Subsystem creation |
| device_enumerate | 0xBBCAB0 | Bulk device enumeration |
| device_ioctl_dispatch | 0xBC43D0 | Type 0x10 ioctl dispatch |
| alloc | 0x42BE10 | Kernel zone allocation |
| free | 0x42C0B0 | Kernel zone free |
| log/printf | 0xA806D0 | Kernel logging |
| panic | 0x4BDCD0 | Kernel panic |
| store_trace_value | 0xA7C9E0 | Trace record field write |

---

## 12. Exploitation Potential Assessment

**Highest-value targets:**

1. **V1 + V2 combo:** An unprivileged process can reach the type 0x10 ioctl path (via unauthenticated cmd 0x200-0x270), and if a device descriptor can be crafted with buffer_limit < 0x18, the integer underflow bypasses the bounds check, potentially enabling a kernel heap overflow.

2. **V1 + V3 combo:** The TOCTOU in device iteration (reachable without auth) could allow use-after-free if timed with device destruction.

3. **V6 (info leak):** Can be used to defeat KASLR by leaking kernel heap contents through the device name copy path.

4. **V7 (callback storage):** If the callback registration at 0x55A0 is reachable via any unauthenticated command, it provides a write-what-where primitive for kernel global memory.
