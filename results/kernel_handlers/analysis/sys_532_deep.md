# Deep Analysis: sys 532 (Syscall 0x214) - First Sony Syscall

**Firmware**: 13.60 | **Kernel base**: 0xffffffff8a9c0000 | **Handler size**: ~16KB (0x4000) | **narg**: 5

## 1. Handler Overview

sys 532 is the primary Sony-proprietary multi-command dispatch syscall. It accepts 5 arguments and implements a massive command routing system with ~70+ distinct sub-operations covering GPU/compute resource management, buffer operations, memory mapping, and device state management.

### Stack Frame
- `sub rsp, 0x858` -- Very large stack frame (2136 bytes), local buffer at `[rbp-0x850]` of size 0x818 (2072 bytes)
- Stack canary loaded from `[rip+0x2e2c2b5]` (at 0x2e2c2d0) and verified at epilogue

### Arguments (from `rsi` struct):
- `arg0` (r14d) = `[rsi+0x0]` -- Command code (DWORD)
- `arg1` = `[rsi+0x8]` -- Sub-command / secondary parameter (DWORD, stored at `[rbp-0x864]`)
- `arg2` (r15) = `[rsi+0x10]` -- User output pointer (QWORD, stored at `[rbp-0x860]`)
- `arg3` = `[rsi+0x18]` -- User input pointer (QWORD, stored at `[rbp-0x870]`)
- `arg4` = `[rsi+0x20]` -- Size / buffer length (QWORD, stored at `[rbp-0x878]`)

### Thread Context (from `rdi`):
- `td` = `rbx` = rdi (thread descriptor)
- `td->td_proc` at `[rbx+0x140]` -- process pointer
- Process context at `[rdi+0x8]` = r13 -- likely `td_ucred` or `td_proc`

## 2. Security Gate (offset 0x56 - 0xDC)

### Primary Privilege Check
```
offset 0x9e:  mov esi, 0x2aa     ; priv_check privilege code 682
              call [rbp-0xfef9f0+rip]  ; priv_check(td, 682)
```
**priv_check(td, 682)** -- Sony-specific privilege number 0x2AA. This is a PS5-custom FreeBSD privilege.

- If priv_check **succeeds** (returns 0): goes to offset 0xDC for further auth checks
- If priv_check **fails** (returns nonzero): only a subset of "safe" command codes are allowed (0x18-0x1F, 0x2F, 0x20)

### Secondary Auth Check (offset 0xDC-0xF5)
When priv_check passes:
```
offset 0xdc:  mov rdi, [rbx+0x140]     ; td->td_proc
              call 0xffffffffffb19040    ; get_authinfo / process_auth_id
              cmp eax, 0x1               ; check if auth_id == 1
              jne 0x266                  ; if not 1, allow
```
If auth_id == 1 (kernel/system), commands > 0x20 go through a secondary range check against bitmask `0x800003d4` (allowing bits 2,4,6,7,8,9,31).

### Command Code Whitelisting (Unprivileged Path)
Commands 0x18-0x1F (range check `[r14-0x18] < 7`), 0x2F, and 0x20 are accessible without full priv_check. All others jump to error 0x11e3 (stack canary check + return).

## 3. Global Registration Table Lookup (offsets 0x10D-0x25C)

A global registration table at `[rip+0x3207df8]` with entry count at `[rip+0x3207e00]` is used extensively. Each entry is 40 bytes (5 QWORDs) with structure:
- `+0x18`: command ID (DWORD)
- `+0x15`: range count byte
- `+0x16`: shift value byte
- `+0x20`: flags word
- `+0x22`: additional byte
- `+0x35`: permission bit 0x1 (type A commands), bit 0x2 (type B commands)

The lookup implements a **hash table with power-of-2 probing**: for each entry, if the base ID doesn't match, it generates `count` additional IDs via `base + (i << shift)` and checks each.

Two permission categories:
- **Type A** (bitmask 0x800003d4): checks `[entry+0x35] & 0x1`
- **Type B** (bitmask 0x2a): checks `[entry+0x35] & 0x2`
- **Type C** (bitmask 0x100001000): unconditional pass at 0x266

Error 0x800d0218 when entry not found or permission denied.

## 4. Main Jump Table (offsets 0x2A4, 0x31C)

Two jump tables based on command code (r14d):
1. **Pre-copyin table** at `[rip+0xdee1f0]` -- for commands 0x00-0x46, dispatches WITHOUT requiring user input copyin first
2. **Post-copyin table** at `[rip+0xdee30c]` -- same command range but AFTER copyin of user data to kernel buffer

### Size Validation (offsets 0x2B4-0x303)
Before copyin, size is validated:
- Default max: 0x801 bytes
- Commands 0x1A-0x1D: max 0x819 bytes (slightly larger)
- Commands 0x20, 0x28, 0x30, 0x40: max from bitmask `0x150409101`
- Error 0x800d0208 if size exceeds limit

### Copyin (offset 0x305-0x311)
```
offset 0x305: lea rdi, [rbp-0x850]     ; kernel buffer
              mov esi, 0x818            ; max size
              call 0xffffffffff768fb0    ; bzero / memset(buf, 0, 0x818)
```
Buffer is zeroed before copyin. Then command-specific copyin sizes are used.

## 5. Command Dispatch Map (Past 0x1000)

### Sub-function at 0x1300: `copyin_wrapper`
```
offset 0x1300: push rbp
               ...
               call 0x12a3a0            ; trace/audit log (ktracing with "copyin" string at 0x8a7efd)
               jmp 0xffffffffff769240   ; actual copyin(user_ptr, kern_buf, len)
```
This is `copyin()` wrapped with ktrace auditing.

### Sub-function at 0x1350: `copyout_wrapper`
```
offset 0x1350: push rbp
               ...
               call 0x12a3a0            ; trace/audit log (different string at 0x85f257)
               jmp 0xffffffffff769190   ; actual copyout(kern_buf, user_ptr, len)
```
This is `copyout()` wrapped with ktrace auditing.

### Sub-function at 0x13A0: `validate_and_resolve_handle`
Complex validation function taking 6 arguments:
- `edi`: handle type/mode
- `rsi`: packed handle value (64-bit, decomposed into byte fields)
- `edx`: secondary parameter
- `rcx`: process pointer (from td->td_proc)
- `r8d`: operation type (1=read, 2=write)
- `r9`: output pointer

**Handle validation logic** (offsets 0x13A0-0x16E5):
1. Decomposes 64-bit handle into byte fields using bit shifts and extracts
2. Computes checksum: `byte[3] + byte[0] + byte[1] + bextr(val,0x810) + byte[5]*byte[4]`
3. Compares lower 16 bits of checksum against bytes [6:7] -- **integrity check**
4. XORs byte[4] with 0x6b and validates result <= 0xC -- **type index**
5. Uses type index to select between two key tables at `[rip+0x8c9cc0]` and `[rip+0x8c9f90]`
6. XOR-decodes 4 additional bytes from the table to reconstruct a **registration entry ID**
7. Looks up the reconstructed ID in the global registration table
8. Performs **permission checks**: read (0x10/0x1) or write (0x20/0x2) based on operation type
9. Validates auth context via two calls at `0xffffffffffb19290` and `0xffffffffffb192d0`
10. Returns resolved index through `[r9]`

**Error codes**:
- 0x800d0204: checksum mismatch
- 0x800d0203: type index out of range / table not found
- 0x800d0205: decryption variant mismatch
- 0x800d0206: decoded value validation failed
- 0x800d0216: insufficient permission for operation
- 0x800d0214: insufficient base permission
- 0x800d021f: auth context mismatch

## 6. Sub-function at 0x16F0: `do_buffer_operation`
Takes (edi=mode, rsi=user_src, rdx=user_dst, rcx=process_ptr).
- Validates global enable flag at `[rip+0x3207bc0]`
- Checks secondary enable at `[rip+0x3207bc4]`
- If both enabled, performs handle lookup via `0x118b10` (object lookup by name/type from global pool at `0x1dddfa0`)
- Copies data between userspace and kernel objects using `copyin`/`copyout` wrappers
- On error, logs via `0xffffffffffbba4c0` with type=5

## 7. Sub-function at 0x1920: `do_transfer_operation`
Similar structure to 0x16F0 but for a different command class (type 6/9 operations).
- Uses `0xffffffffffffe420` -- likely `vm_map_lookup` or similar for address validation
- Validates result against mask 0x800d00f0 to ensure valid region type
- Calls `0xffffffffffffdbe0` for secondary resolution
- Then performs transfer via copyin/copyout

## 8. Sub-function at 0x1B50: `init_subsystem_worker` (Thread Worker)
```
offset 0x1b50: push rbp
               lea rdi, [rip+0x885a30]  ; name string at 0x887595
               mov esi, 0x44            ; flags
               mov edx, 0x22000000      ; priority
               call 0xffffffffffe36420  ; kthread_create
```
Creates a kernel worker thread. Initializes:
- Mutex at `[rip+0x3207c48]`
- Condition variable at `[rip+0x3207c50]`
- Worker loop that:
  1. Acquires mutex, sleeps on condvar
  2. Reads time via `[rip+0x2e30390]` (timecounter, multiplied by 500)
  3. Calls `0xffffffffffc4e9c0` with data from condvar
  4. Loops up to 999 (0x3e7) iterations
  5. On state==2: suspends; state==3: terminates

## 9. Sub-function at 0x1CC0: `parse_named_key_value`
String parser for "key=value" format configuration data from a global buffer at `[rip+0x321ca20]+0x1408`.
- Scans for '=' separator (max 0x7FF bytes)
- Key limited to 255 bytes
- Parses value as decimal or hex (0x prefix)
- Looks up result in the global registration table
- Validates entry flags against specific conditions
- Calls sub-function at 0x2100 for further processing

## 10. Sub-function at 0x2100: `parse_colon_separated_descriptor`
Large (~0x600 bytes) parser for colon-delimited descriptor strings. Format:
```
field1:field2:field3:field4:field5:field6:field7:field8:field9:field10:field11:field12:data
```
Each field is parsed as decimal or hex, with specific validation rules.

**Parsed structure** (at `[rbp-0x30]`, the output descriptor):
- `+0x00`: base ID (DWORD) -- from registration table lookup
- `+0x04`: version (WORD) -- 1-3
- `+0x06`: primary size (WORD) -- validated against 0x801-0xFFFF
- `+0x08`: secondary size (WORD)
- `+0x09`: flags byte
- `+0x0A`: mode byte (0x01, 0x02, 0x10, 0x200)
- `+0x0B`: initialized flag
- `+0x0C`: base offset (DWORD)
- `+0x10`: count (WORD)
- `+0x12`: capability flags (WORD) -- bits: 0x1 (type1), 0x2 (sparse), 0x4 (verified), 0x8 (encrypted), 0x10 (compressed), 0x20 (streaming), 0x40 (tiled), 0x80 (HW-accel), 0x100 (extended), 0x200 (auto), 0x300 (auto+ext)
- `+0x14`: format byte -- validated: must be in {0,1,4,6,8,9} via bitmask 0x253
- `+0x15`: shift count
- `+0x16`: granularity (8 or 16)
- `+0x18`: encryption mode byte -- validated: {1,2,3,4,0x13,0x23,0x43,0x52,0x53,0x83}
- `+0x1A`: extra flags
- `+0x1C`: feature flags (DWORD) -- read/write/execute for two categories
- `+0x1D`: capability extension byte
- `+0x20`: hash type (WORD)
- `+0x22`: data size (WORD)
- `+0x24`: data offset (DWORD)

**Global resource accounting**:
- Total resource count capped at 0x64000 (409,600)
- Tracked at `[rip+0x3207e04]` with per-entry size accounting
- Statistics updated at `[rip+0x3207b50]+0xA8` through `+0xC4`

## 11. Sub-function at 0x3770: `lookup_command_handler`
Searches the registration table for a specific command ID, then dispatches:
- If found with `entry[0x22] != 0`: calls `0x1c4380` (full handler)
- If found with `entry[0x22] == 0`: calls `0xffffffffffc6b640` (default handler)
- If not found: returns error 0x800d0203

## 12. Sub-function at 0x38A0: `subsystem_init_deinit`
Three-state initialization/deinitialization (arg esi: 0=init, 1=deinit, 2=reinit).

### Init (state 0, offsets 0x38DA-0x3C4E):
1. Creates 3 named kernel objects via `0xffffffffffc4dd00`:
   - Object 1: name at 0x78ff1b, callback at 0xffffffffff77ad80, config at 0x7981ff, data at 0x1dde0e0
   - Object 2: name at 0x800e74, callback at 0xffffffffff7749a0, config at 0x852a14, data at 0x1dde0f0, param=0x4e1f
   - Object 3: name at 0x7a4425, callback at 0xffffffffff7749a0, config at 0x7e0474, param=1
2. Zeros statistics area at `[rip+0x3207b50]`, size 0x2A8
3. Initializes registration table at `[rip+0x3207df8]`, size 0x14028 (max ~2048 entries at 40 bytes each)
4. Zeros global data areas 0x321ca20 (0x1d0c bytes), 0x321be20 (0xc00 bytes)
5. Queries 8+ device capabilities via calls to 0xffffffffffab4c50-0xffffffffffab5420 (setting flags at 0x3207b84-0x3207bac)
6. Checks hardware compatibility (0x17900, 0x17920, 0x178e0) and optionally calls `priv_check(td, 0x6d)` = 109
7. Initializes mutex/condvar and creates buffer allocation pool (0xa00 entries, each 0x101 bytes from pool at 0x1dddfa0)
8. Allocates main data pool: 0x64000 entries

### Deinit (state 1, offset 0x3C83):
Calls `0xffffffffffa7a240` with args 4,3,2,1,0 (releasing 5 priority levels), then `0xfffffffffffcf420`.

### Reinit (state 2, offset 0x3CBC):
1. Calls `0xffffffffff9d6520` (lock/sync)
2. Calls `0xffffffffffbba5a0` (flush)
3. Destroys all 4 named objects via lookup + destroy
4. Falls through to deinit path

### Obfuscated Auth Token (offset 0x3E13-0x3E51):
Uses magic constant `0x2004112419990816` (appears to encode a date: 2004-11-24 / 1999-08-16) with byte-shifting XOR to derive an auth/session token from process name string (9 bytes max).

## 13. Common Command Handlers (by command code)

| Cmd | Copyin Size | Handler Call | Description |
|-----|------------|--------------|-------------|
| 0x00 | 0x4 | 0xffffffffffff8ca0 | Get status (4-byte param) |
| 0x01 | 0x8 | internal branch | Set mode with r12 validation |
| 0x02 | varies | 0xffffffffffff8e30 | Query info |
| 0x03 | 0x818 | 0x13a0 (type=1) + 0xffffffffffff7960 | Create resource (read) |
| 0x04 | 0x818 | 0x13a0 (type=2) + 0xffffffffffff71c0 | Create resource (write) |
| 0x05 | 0x4 | 0xffffffffffff8a80 | Delete resource |
| 0x06 | 0x4 | 0xffffffffffff7af0 | Query resource |
| 0x07 | 0x800 | 0xffffffffffb1ad20 | Bulk operation |
| 0x08 | 0x18 | 0xffffffffff854530 | Get properties |
| 0x09 | 0x18+obj | 0xffffffffff8559f0 | Set properties |
| 0x0A | 0 | 0xfffffffffffceab0 | Toggle mode |
| 0x0B | size | 0xffffffffffb1abc0 | Transfer data |
| 0x0C | 0 | (internal) | Status check with r12 |
| 0x0D | 0 | 0xffffffffffb1ada0 | Sync |
| 0x0E | 0 | 0xffffffffffff8d30 | Reset |
| 0x0F | varies | 0xffffffffffff71c0 | Alternate resource create |
| 0x10 | 0x10 | 0x13a0 (type=1) + 0xffffffffffff70a0 + copyout | Map/query with resolve |
| 0x11 | 0x4 | 0xffffffffffff6f50 | Unmap |
| 0x12 | varies | 0xffffffffffff7c40 | Alternate query |
| 0x13 | 0x818 | 0x13a0 (type=1) + 0xffffffffffff7410 | Extended create (read) |
| 0x14 | 0x4 | 0xffffffffffff6f50 | Extended unmap |
| 0x20 | 0x30 (special) | 0x1300 copyin only | Config query (fixed 0x30 size) |
| 0x27 | 0x18+obj | 0xffffffffff856370 | Named object operation |
| 0x2C | via parser | 0x1c47f0 | Parse-and-execute |
| 0x31 | 0x8 | table lookup | Version/capability query |
| 0x35 | 0x18+obj | 0xffffffffff8559f0 | Named set properties |
| 0x36 | 0x18 | 0xffffffffffb1ac60 | Config set (via arg1) |
| 0x41 | 0x18 | 0xffffffffff854580 | Obj handle query |
| 0x42 | 0x18+obj | 0xffffffffff8545f0 | Obj handle create |
| 0x43 | 0x18+obj | 0xffffffffff854550 | Obj handle write |
| 0x44 | 0x4 | 0xffffffffffff8180 | Obj handle delete |
| 0x45 | 0 | 0xffffffffffff9160 | Obj list/enumerate |
| 0x46 | varies | 0xffffffffffe17340 | Extended query/config |

## 14. Vulnerability Analysis

### VULNERABILITY 1: Integer Overflow in Size Validation (MEDIUM)
**Location**: offset 0x2B4-0x303
The size validation uses `cmp rcx, 0x801` for most commands but allows 0x819 for commands 0x1A-0x1D. The size is a user-controlled QWORD at `[rsi+0x20]`. While the comparison is unsigned, the value is later truncated to 32-bit in some paths (e.g., offset 0x7D0: `mov edx, [rbp-0x848]`), potentially causing integer truncation.

### VULNERABILITY 2: TOCTOU in Handle Validation (MEDIUM-HIGH)
**Location**: sub-function 0x13A0
The handle validation at 0x13A0 performs a multi-step decode of the 64-bit handle value, then looks up the entry in the registration table, then checks permissions. The registration table entry could be modified between the lookup and the permission check if another thread is concurrently modifying entries. The table appears to have no explicit locking in the validation path.

### VULNERABILITY 3: Missing Bounds Check on Registration Table Index (LOW-MEDIUM)
**Location**: offsets 0x22F-0x24B, 0x36B-0x38D
After finding a matching entry, the index `edx` is masked with `0x7fffffff` and used as `lea rdx, [rdx+rdx*4]` followed by `test BYTE PTR [rcx+rdx*8+0x35], 0x1`. If the table entry count `[rip+0x3207e00]` were corrupted or if the lookup returned a negative-but-valid-looking index, the access at `+0x35` could go out of bounds.

### VULNERABILITY 4: Unchecked Object Pointer from 0x118b10 Lookup (MEDIUM)
**Location**: offsets 0x441, 0x576, 0x6F3, 0xD79, 0x1043, 0x10A3
The function at `0x118b10` (object lookup from pool) returns a pointer that IS null-checked but NOT bounds-checked. If the pool at `0x1dddfa0` is corrupted, this could return a pointer to arbitrary kernel memory.

### VULNERABILITY 5: Missing Auth Check on Deinit Path (MEDIUM)
**Location**: offset 0x3C83 (state=1) and 0x3CBC (state=2)
The init/deinit function at 0x38A0 does NOT perform a priv_check for the deinit (state=1) or reinit (state=2) paths. If a user process can trigger these states (via the command routing), it could tear down the subsystem.

### VULNERABILITY 6: Race Condition in Worker Thread State Machine (LOW)
**Location**: offset 0x1BC5-0x1C94
The worker thread at 0x1B50 reads a state variable at `[rip+0x3207c24]` without holding the mutex in the outer check (offset 0x1C07-0x1C15). While it does acquire/release the mutex around the condvar wait, the state transition from 1->2->3 can race with the main thread modifying it.

### VULNERABILITY 7: No Rate Limiting on Registration Table Writes (LOW)
**Location**: sub-function 0x2100 (descriptor parser)
The descriptor parser can add entries to the global registration table (updating counters at 0x3207e02, 0x3207e04). There is a cap at 0x64000 total resources and 0xA00 entries, but no per-process rate limiting.

## 15. Error Code Summary

| Code | Meaning |
|------|---------|
| 0x800d0201 | Subsystem not initialized |
| 0x800d0202 | Null pointer / missing argument |
| 0x800d0203 | Command not found in table |
| 0x800d0204 | Handle checksum mismatch |
| 0x800d0205 | Handle type/decryption error |
| 0x800d0206 | Handle decoded value invalid |
| 0x800d0208 | Invalid size / parameter |
| 0x800d020d | Subsystem in error state |
| 0x800d020f | Copyin/copyout failed |
| 0x800d0210 | Copyout failed |
| 0x800d0211 | Object lookup failed |
| 0x800d0212 | Resource limit exceeded |
| 0x800d0213 | Initialization failed |
| 0x800d0214 | Insufficient base permission |
| 0x800d0216 | Insufficient operation permission |
| 0x800d0218 | Permission entry not found |
| 0x800d0219 | Mode restriction / sandboxed |
| 0x800d021f | Auth context mismatch |

## 16. Key Global Data Structures

| Address (RIP-relative) | Description |
|------------------------|-------------|
| 0x3207df8 | Registration table base (40-byte entries) |
| 0x3207e00 | Registration table entry count (WORD) |
| 0x3207e02 | Data entries count (WORD) |
| 0x3207e04 | Total resource size counter (DWORD) |
| 0x3207b50 | Statistics area (0x2A8 bytes) |
| 0x3207b70 | Hardware config flags (multiple DWORDs) |
| 0x3207bc0 | Subsystem enabled flag |
| 0x3207bc4 | Subsystem status/error code |
| 0x3207b80 | Extended mode flag |
| 0x3207c24 | Worker thread state (1=run, 2=suspend, 3=terminate) |
| 0x3207c48 | Worker mutex |
| 0x3207c50 | Worker condvar |
| 0x321be10 | Buffer pool pointer (0xA00 entries) |
| 0x321be18 | Data pool pointer (0x64000 entries) |
| 0x321ca20 | Global config/parse buffer (0x1D0C bytes) |
| 0x321e62c | Temp string buffer (256 bytes) |
| 0x321e730-0x321e748 | Named kernel object pointers |
| 0x1dddfa0 | Pool allocator descriptor string |
| 0x2e2c2d0 | Stack canary reference |

## 17. Summary

sys 532 is the primary Sony GPU/compute resource management syscall. It implements:
1. A registration-table-based command routing system with ~2048 possible entries
2. Handle-based resource management with XOR-obfuscated integrity checksums
3. A worker thread for asynchronous operations
4. Complex colon-separated descriptor parsing for resource creation
5. Multiple levels of privilege checking (priv_check 682, auth_id, per-entry permissions)

The handler is well-structured but has several potential vulnerabilities, primarily around race conditions in the registration table and handle validation, integer truncation in size parameters, and missing privilege checks in the deinit path.
