# Heap Spray Candidates for AIO Double-Free Reclaim — PS5 14.10

## Status: ANALYSIS (2026-10-25)

## The Target: What 662 Frees

From the 13.60 decompile of `_aio_multi_delete` (sys_662.c) and `_aio_submit_cmd`
(sys_669_deep.md), the delete path frees multiple kernel objects per AIO request.
The zone identifiers (`func_0x00c08df0(ptr, zone)`) from the 662 decompile are:

| Object | Zone ID | Allocation Size | Content |
|--------|---------|-----------------|---------|
| Queue entry | `0x1ab5a50` | **0x30 (48B)** and `count * 8` array | List links, descriptor ptr, saved context, completion header, file object ptr, state |
| AIO object | `0x1ab5a50` | **0x30 (48B)** | Group counts, queue class, base id, completion header, AIO context ptr, descriptors ptr, entry ptr array |
| Saved context | `0x1ab5970` | **0x58 (88B)** or `count * 0x58` | Thread/process values, held credential reference |
| Completion header | `0x1ab59e0` | var | Linked to `lVar5+0x10` pointer, freed before context |
| Descriptor copy | `0x1a7d800` | **0x28 × count** (40–5120B) | Copied user descriptors |
| Feature context | `0x1a7d800` | `count * 0x18` (24B/ID) | Only allocated on certain feature paths |

**Critical observation:** The queue entry (0x58B) and AIO object (0x30B) use the
same zone `0x1ab5a50`. The saved context uses zone `0x1ab5970`. The descriptor copy
uses zone `0x1a7d800`. The double-free frees objects from **multiple zones** in one
pass — the TOCTOU window lets both threads free the same sub-objects.

**The most likely double-freed objects are:**
1. The **saved context** at `lVar5` (freed via `func_0x00c08df0(lVar5, 0x1ab59e0)`)
2. The **queue entry** slot pointers
3. The **AIO object** itself (freed via `func_0x00c08df0(psVar6, 0x1ab5a50)`)

The richest target is the **queue entry** (0x58 bytes): it contains `+0x40` a
referenced file object pointer (kernel address), `+0x18` saved context (kernel
address), `+0x20` completion header (kernel address), and `+0x48/+0x50` list links
(kernel addresses). Reclaiming this slot with controlled data and reading it back
through a dangling pointer leaks kernel addresses → KASLR defeat.

---

## Ranked Spray Candidates

### Tier 1: Best Fit (working, controllable content, matching sizes)

| # | Primitive | Syscall | Alloc Size | Content Control | Create Rate | Cleanup | Zone Match | Score |
|---|-----------|---------|------------|-----------------|-------------|---------|------------|-------|
| 1 | **Socket option buffers** | setsockopt(105) | 4–256B | Full (user buffer copied in) | High (per socket) | close(fd) | Unknown | **5/10** ⚠ |
| 2 | **evf_create name+attrs** | 538 | ~64-80B (struct) | Partial (32B name + attrs) | High (fast handle alloc) | 539 delete | Unknown | **4/10** ⚠ |
| 3 | **namedobj_create** | 557 | ~48-64B (struct) | Partial (32B name) | High (fast handle alloc) | 558 delete | Unknown | **3/10** ⚠ |
| 4 | **AIO request descriptors** | 669 | 0x28×count (40–5120B) | Full (user-supplied desc) | Medium (queue limited) | 662 delete | `0x1a7d800` ✓ | **8/10** |
| 5 | **osem_create** | 549 | ~48-80B (struct) | Partial (32B name + init/max) | **BLOCKED** | 550 delete | Unknown | **2/10** ⚠ |

### Tier 2: Viable (working, partial control or size mismatch)

| # | Primitive | Syscall | Alloc Size | Content Control | Create Rate | Cleanup | Score |
|---|-----------|---------|------------|-----------------|-------------|---------|-------|
| 6 | **kqueue knote** | kevent(363) | ~64-96B (struct knote) | Partial (filter, flags, fflags, data, udata) | High (2000+ proven) | EV_DELETE | **7/10** |
| 7 | **ktimer_create** | 235 | ~128B (struct itimer) | Minimal (clock ID) | Low (cap 27) | ktimer_delete | **5/10** |
| 8 | **Socket creation** | socket(97) | ~512-1024B (struct socket + inpcb) | Minimal (type/proto) | Medium | close(6) | **5/10** |
| 9 | **sendmsg ancillary** | sendmsg(28) | variable | Full (cmsg data) | High | consumed on send | **5/10** |
| 10 | **blockpool_open** | 653 | unknown | None | Very low (cap 3) | close(fd) | **3/10** |

### Tier 3: Blocked or Unsuitable

| # | Primitive | Syscall | Status | Reason |
|---|-----------|---------|--------|--------|
| 11 | pipe buffers | 42 / 542 | **BLOCKED** | pipe/pipe2 both return -1 |
| 12 | shm_open metadata | 482 | **WORKS** but struct is large | shm_open works via make_syscall; kernel struct is ~256-512B, too large for 0x30/0x58 targets |
| 13 | mmap vm_map_entry | 477 | Works | Kernel struct ~128-192B; no content control, only address/size |
| 14 | UMTX structures | 454 | Partial | ops 5/21 work, but kernel allocation is implicit and size unknown |
| 15 | netcontrol register | 99 | Works | Allocates a queue entry but takes a socket reference; spent for the boot on ifindex -1 |
| 16 | fork/rfork | 2/251 | **BLOCKED** | No process creation |
| 17 | jitshm/osem create | 533/549 | 533 blocked, 549 works | jitshm returns -1 for all sizes |

---

## Detailed Analysis of Top Candidates

### 1. Socket Option Buffers (setsockopt — syscall 105)

**VERIFICATION UPDATE (Session 4):** Score downgraded 9→5. Key problems:
- `SO_LINGER` writes 8 bytes to the socket's inline `so_linger` field — it does
  NOT allocate a kernel heap buffer. Any reference to SO_LINGER as spray is wrong.
- Standard BSD options (TCP_NODELAY, SO_SNDBUF, etc.) write to inline socket fields.
- No probe has ever verified that setsockopt triggers a variable-size kernel heap
  allocation. The `getsockopt` readback round-trip was never tested.
- Sony custom options (0x2000 etc.) accepted 256-byte writes (rv=0) but may just
  validate-and-discard without heap allocation.

**Options that DO allocate heap buffers in FreeBSD:**
- `IP_OPTIONS` — up to 40 bytes copied to `inp->inp_options` mbuf
- `TCP_CONGESTION` — string copied to `cc_algo` (typically 8-32B)
- `SO_ACCEPTFILTER` — allocates `accept_filter_arg` (256B struct)

**Key question:** Do the Sony custom options actually `copyin` the full buffer
into a kernel heap allocation, or do they just read a flag? Probe needed.
Specifically: use sys 624 (VM-op counter) before/after mass setsockopt to
detect page allocations from slab exhaustion.

**Spray pattern:**
```
for i = 1, N do
    local fd = socket(AF_INET, SOCK_DGRAM, 0)
    setsockopt(fd, 0xFFFF, 0x2000, controlled_data, target_size)
end
```

### 2. Event Flags (evf_create — syscall 538)

**Why it's strong:** evf objects are fast to create, individually deletable,
and share the same object table as AIO requests. The kernel struct includes a
32-byte name buffer that we control.

**What we know:**
- `538(name_ptr, initial_bits)` creates an evf and returns a handle
- Names up to 31 characters accepted (NUL-terminated)
- Handles are from the shared object table (same namespace as AIO)
- `539` deletes by handle; `544` sets bits; `543` polls bits
- 1000+ objects created in a single process (probe 443a)
- LIFO reuse: freed slots are immediately reissued

**Spray pattern:**
```
-- After double-free, spray evf objects to reclaim the freed AIO slot
for i = 1, N do
    local name = string.rep("A", 31)  -- 31 bytes of controlled content
    evf_create(name, 0xDEADBEEF)       -- initial bits = controlled
end
```

**Limitation:** Only ~32 bytes of the struct are caller-controlled (the name).
The rest is kernel-initialized. If the target freed object is 0x58 bytes and
the evf struct is a different size, zone mismatch prevents reclaim.

### 3. Named Objects (namedobj_create — syscall 557)

**Why it's strong:** Same object table as evf and AIO. Four calls on one name
return four distinct objects, so spray is straightforward. Individually
deletable via `558`.

**What we know:**
- `557(name_ptr)` returns a handle
- Same shared table as evf (handles 0x208-0x20B seen)
- Names up to 31 characters, NUL-terminated
- Not deduplicated: same name creates separate objects
- `558` frees by handle, slot immediately reusable

**Limitation:** Same as evf — only the name portion is controlled. Kernel struct
size unknown but likely ~48-64 bytes (different zone than the 0x58B queue entry).

### 4. AIO Descriptors (aio_submit_cmd — syscall 669)

**Why it's uniquely valuable:** The descriptor copy uses the **same zone**
(`0x1a7d800`) as the AIO feature context freed by 662. The user controls all
40 bytes of each descriptor. And the size is `0x28 × count`, so `count=1` gives
exactly 0x28 (40B), `count=2` gives 0x50 (80B), etc.

**What we know:**
- `669(cmd=1, reqs, count=1..128, class=1..3, ids)` submits
- User request stride is 0x28: offset(8B), byte_count(8B), data_ptr(8B),
  result_ptr(8B), fd(4B), padding(4B) — ALL caller-controlled
- Up to 128 requests per call
- Queue slots are limited but new ones can be created after deleting old ones
- 24 concurrent requests measured

**Spray pattern:**
```
-- Submit many AIO requests with controlled descriptors
-- Each descriptor is 0x28 bytes of attacker-controlled kernel heap data
for i = 1, N do
    local req = memory.alloc(0x28)
    -- Fill with controlled pattern including fake kernel pointers
    safe_wq(req + 0x00, target_offset)
    safe_wq(req + 0x08, target_count)
    safe_wq(req + 0x10, target_data_ptr)
    safe_wq(req + 0x18, target_result_ptr)
    safe_wd(req + 0x20, target_fd)
    sc669(cmd, req, 1, class, ids_out)
end
```

### 5. Kqueue Knotes (kevent — syscall 363)

**Why it's useful:** Each `kevent` registration allocates a `struct knote` in
the kernel. The knote contains user-controlled fields: `ident`, `filter`,
`flags`, `fflags`, `data`, and `udata`.

**What we know:**
- kqueue(362) creates a kqueue fd
- kevent(363) registers events; 2000+ knotes in one process (probe 21)
- Each knote is ~64-96 bytes (FreeBSD `struct knote`)
- EVFILT_USER, EVFILT_READ, EVFILT_TIMER all work
- EV_DELETE removes individual knotes

**Limitation:** `udata` is only 8 bytes of controlled content at a known offset.
The rest is kernel-initialized. `struct knote` size may not match the freed AIO
object sizes.

---

## Cross-Subsystem Spray Strategy

The optimal approach combines multiple primitives:

1. **Determine freed object size** — use sys 624 (VM op counter) as a side
   channel: count operations before and after the double-free to see if the
   free is visible, then spray different-sized objects and check if 624's delta
   matches an allocation
2. **Primary spray: AIO descriptors** (zone `0x1a7d800` match) — if the
   descriptor copy is the double-freed object, use 669 to reclaim with fully
   controlled 0x28-byte payloads
3. **Secondary spray: setsockopt** — for unknown zones, socket option buffers
   offer the most flexible size and content control
4. **Tertiary spray: evf/namedobj** — for the object table zone (`0x1ab5a50`),
   evf and namedobj allocations may land in the same slab

## Readback Mechanisms

After reclaiming the freed slot, we need to read back through the dangling
pointer. Candidates:

| Method | Syscall | What it reads | Works? |
|--------|---------|---------------|--------|
| AIO poll (664) | 664 | Per-item status (4 bytes at known offset) | Yes — but only status word |
| AIO wait (663) | 663 | Status + timeout (more fields) | Yes |
| evf poll (543) | 543 | Bit mask (from the reclaimed struct) | If evf reclaimed |
| getsockopt (118) | 118 | Socket option value | If sockopt reclaimed |
| sysctl (202) | 202 | Sysctl output | Indirect |

The most promising readback is **664 (aio_multi_poll)**: if the dangling pointer
still points at a freed-then-reclaimed slot, polling through the old AIO ID
reads fields from whatever now occupies that memory. The `state` field at queue
entry `+0x38` would read attacker-controlled data if the reclaim placed controlled
bytes there.

## Untested Critical Questions

1. **What is the exact FreeBSD UMA zone for each freed object?** The zone IDs
   (`0x1ab5a50`, `0x1ab5970`, `0x1a7d800`, `0x1ab59e0`) are data-segment
   addresses of `uma_zone_t` pointers, not zone sizes. The actual slab bucket
   size determines which allocations can reclaim a freed slot.

2. **Does 664/663 read through a dangling pointer after double-free?** The
   delete sets the slot pointer to NULL after free. If the second thread's
   delete reads the pointer before the first thread NULLs it, the second
   thread frees the same object. But does any AIO operation still hold a
   reference to the freed memory? The 669 publish happens before queue setup,
   so an ID might still resolve to the freed queue entry.

3. **Is the 662 TOCTOU a use-after-free or only a double-free?** The analysis
   says both threads "free the same sub-objects." If the second thread also
   *uses* (reads pointers from) the freed sub-object before freeing it, that's
   a UAF with information disclosure. If it only frees, we need a separate
   reclaim+readback step.

4. **Can setsockopt with Sony custom options spray arbitrary sizes?** The
   256-byte acceptance (Finding 32) may be a copyin into a fixed field rather
   than a variable-size heap allocation.
