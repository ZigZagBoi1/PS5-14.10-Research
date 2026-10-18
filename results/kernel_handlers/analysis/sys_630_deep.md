# Deep RE: sys 630 — Jail/Mount Companion Handler (12KB, narg=1)

## Function Map

| Offset | Size | Function |
|--------|------|----------|
| 0x000 | 0x0d0 | **Syscall entry**: allocates 0x400 buffer, copyinstr + copyin from user, checks td->0x140 jailed status, 12-byte path whitelist for jailed processes, falls through to mount function |
| 0x0d0 | 0x114 | **Mount tree enumerator**: locks tree at 0x3259ce0, walks binary tree extracting +0x28 values into user array. NO priv_check |
| 0x1f0 | 0x114 | **Mount tree lookup**: finds node by +0x28 match, copies 0x20 bytes + 0x400 bytes of mount data to caller. NO priv_check |
| 0x310 | 0x132 | **Filesystem entry scanner**: iterates mount points from global list at 0x2c6d210, locks per-mount at +0x48, scans entry table (48-byte stride), filters by type==0x10 (directory). NO priv_check |
| 0x450 | 0x172 | **Cross-process mount lookup**: takes PID, finds process, scans mounts for handle match, copies 0x20 bytes of name + mount serial from +0xbc. NO priv_check |
| 0x5d0 | 0x030 | **Pool initializer**: creates UMA zone for 0x20-byte tree nodes |
| 0x600 | 0x052 | **Tree initializer**: creates RB-tree + UMA zone for 0x30-byte mount entries |
| 0x660 | 0x020 | **Mount type validator**: bitmask 0x1ffbff on types 0-20, returns size from table |
| 0x6c0-0x79f | var | **4 disabled stubs**: all return ENOSYS (0x2d) |
| 0x7a0 | 0x082 | **Mount info query**: returns page_count * 0x4000 (16KB pages), raw count, mount flags. NO priv_check |
| 0x830 | 0x041 | **Handle release**: `lock xadd` refcount at +0x14, frees backing on zero |
| 0x8b0 | 0x09a | **Mount operation**: validates flag bit 0x2, derives permissions from +0x24, calls mount setup at 0x19d2c0. NO ucred check |
| 0x950 | 0x2dd | **Jail-aware mount setup**: iterates mount entry linked list from 0x567110, resolves names, 9-type jump table at 0xf00894 for entry processing, installs callbacks |
| 0xc30 | 0x3d8 | **Path resolver**: increments counter at 0x30ac9e4, handles '\\'/'^'/'.'/'/' path components, '^' traverses up mount tree, calls VOP_ACCESS for symlink handling, full vnode lookup chain |
| 0x1010 | 0x108 | **Statistics calculator**: gathers counts for types 0xd7/0x110/0x4/0x9e/0x2/0x1/0x42/0xcb, returns aligned buffer size |
| 0x1120 | 0x222 | **Mount table builder**: populates segmented buffer from ROM data at RIP-relative addresses |
| 0x1350 | 0x0ec | **Optimized memchr**: 8-byte word scan with replicated byte pattern |
| 0x1440 | 0x074 | **Mount ID lookup**: scans 128-entry table at 0x325b390 for pointer match |
| 0x14c0 | 0x0d2 | **Module init/destroy**: arg=0 creates module (alloc, init tree, 0x808 buffer, 20s timer), arg=1 tears down |
| 0x15a0 | 0x051 | **Periodic callback**: runs every 20s, calls core processor 0x17e0 with stored config |
| 0x1600 | 0x01b | **Jail check helper**: reads td->0x140, returns inverted jail status |
| 0x1630 | 0x1af | **ioctl handler**: dispatches on 0xc0305201/0xc0305202/0xc0305203, allocates config buffer (8KB or 1MB+), validates size bounds, copyin user data, calls core processor |
| 0x17e0 | 0x3bc | **Core mount processor**: 0x148-byte frame, 16-qword state, locks tree, calls 0xd1ae00/0xc87590, creates connection records with AF_INET/AF_UNIX, validates and copies output |
| 0x1ba0 | 0x03e | **Copyout wrapper**: creates kernel path + tail-calls copyout |
| 0x1bf0 | 0x090 | **Mount chain modifier**: walks +0xb8 list, clears flag bits 0x200000/0x100000 in +0x1c, accumulates +0x18 counts |
| 0x1c80 | 0x07e | **Mount node insertion**: adds to chain at +0xb8, updates +0xc8/+0x94 high watermark |

## Security Analysis

### 1. Jail bypass confirmed and extended (CRITICAL)
- Entry at 0x000: if `ce_is_jailed(td->0x140)` returns 0 → direct mount, no restriction
- For jailed processes: ONLY a 12-byte `memcmp` against hardcoded path at 0xf00831
- After sys 629 arg0=1 bypasses jail, this handler becomes completely unrestricted
- Confirmed chain: `sys 629 (jail escape) → sys 630 (unrestricted mount)`

### 2. Zero privilege checks on all enumeration functions (HIGH)
- `enumerate_mounts()` at 0x0d0 — list all kernel mount points
- `lookup_mount()` at 0x1f0 — read 0x420 bytes of any mount's data
- `scan_fs_entries()` at 0x310 — list all filesystem directory entries
- `mount_info()` at 0x7a0 — get page counts and flags for any mount
- Any process can call these to map the entire filesystem topology

### 3. Cross-process mount lookup by PID (HIGH)
- Function at 0x450 takes arbitrary PID
- Calls `pfind()` at 0xc1f500 to locate target process
- Only checks if PID exists (ESRCH=3 if not)
- NO check that caller has any relationship to target process
- Returns mount names, handles, and serial numbers

### 4. Unprotected ioctl interface (HIGH)
- The ioctl handler at 0x1630 accepts three commands without credential checks:
  - `0xc0305201`: configure with up to 0x8800 bytes of user data
  - `0xc0305202`: configure with up to 0x100800 (~1MB) of user data
  - `0xc0305203`: read current status
- Core processor at 0x17e0 processes with network socket operations
- Only validation is buffer size bounds — no authentication

### 5. Timer-based kernel processing of stored config (MEDIUM-HIGH)
- Periodic callback at 0x15a0 fires every 20 seconds
- Processes stored config from 0x325b7c8 using core processor
- If attacker can manipulate stored config (via unprotected ioctl), timer handler processes it with full kernel privilege

### 6. Four disabled functions could be re-enabled (MEDIUM)
- Stubs at 0x6c0, 0x6d0, 0x780, 0x790 all return ENOSYS
- If sysent table is patched (possible after kernel R/W), these could be restored

## Notable Implementation Details
- **Tree structure**: Sony uses custom RB-tree (not FreeBSD's standard) with comparator at 0xa23b00
- **Path separator**: Uses '\\' (0x5c) — Windows heritage or obfuscation
- **Parent traversal**: '^' (0x5e) in paths traverses up mount tree — non-standard, exploitable if path validation doesn't account for it
- **Mount types**: 21 valid types encoded in bitmask 0x1ffbff (types 0-20, excluding 10 and 14)
- **16KB page size**: Confirmed by 0x4000 constant in mount_info
- **128-entry mount table**: Fixed-size table at 0x325b390 limits total mounts

## Exploitation Chain
```
Step 1: Information Gathering (no privileges needed)
  sys 630 enumerate → list all mount points and their data
  sys 630 cross-PID lookup → map system daemon mount topology
  sys 630 mount_info → get page counts and memory layout

Step 2: Jail Escape
  sys 629 arg0=1 → bypass jail entirely

Step 3: Unrestricted Mount
  sys 630 entry → mount arbitrary filesystem paths

Step 4: Persistence
  sys 630 ioctl 0xc0305201 → inject config processed every 20s by kernel

Step 5: Combine with sys 653
  Use unrestricted mount to access GPU device
  sys 653 → modify page attributes for GPU R/W primitive
```

**14.10 survivability**: STRUCTURAL for both the jail bypass chain and the missing privilege checks on read operations.
