# Deep RE: sys 653 — GPU/Display Page Table Attribute Modifier (8KB, narg=1)

## Function Map

| Offset | Size | Function |
|--------|------|----------|
| 0x000 | 0x218 | **Syscall entry**: reads arg0, validates against mask 0xffafffff (only bits 20,22 allowed), gets proc fields +0x5d0/+0x5c4, allocates tracking object, links into global list at 0x31fe168, atomic refcount at +0x58 |
| 0x220 | 0x14c | **2MB page iterator**: walks address range in 0x200000 (2MB) steps, calls VM mapping functions per large page |
| 0x370 | 0x1d6 | **3-slot allocator**: manages 3 slots at struct+0x168/0x174/0x180 (12-byte stride each). Sleeps if none available (flags 0x100) |
| 0x550 | 0x310 | **Core privilege page op**: checks struct+0x244 bit 0x1 as feature gate; allocates pages from bitmap at 0x31fe1c8 using TZCNT+BLSR; processes entries in batches of 0x800. Has CFI check (ROR+CMP 0x6ff) on function pointer |
| 0x860 | 0x14e | **Entry type scanner**: extracts type from bits 28-29 of entries. Type 0=skip, type 1=process+clear+output, type >=2=panic. Decrements per-group byte counters |
| 0x9b0 | 0x10c | **Bitmap page release**: three-level radix bitmap at +0x70/+0x90 (level 0), +0x20000 (level 1), +0x20800 (level 2). Uses BTS instructions. Distinguishes large (bit 0x800000 set) vs normal pages |
| 0xac0 | 0x2cf | **Large page attribute modifier**: validates +0x244 flag 0x2, dispatches by page type, modifies PTE attributes with mask 0xf0ffffff |
| 0xd90 | 0x4d0 | **Full PTE attribute handler**: 10 page types via jump table at 0xf25e7c, BEXTR-based bitfield extraction, handles tagged/untagged modes, inner loops modify attributes in 32-entry chunks |
| 0x1270 | 0x2e8 | **Page chain manager**: creates/modifies page entries in linked lists at +0x68, sets entry->0x5c=1 as valid marker |
| 0x1560 | 0x2f0 | **Range query**: finds contiguous pages with matching attributes using XOR compare on bits 0x3ff00000 |
| 0x1850 | 0x240 | **Direct page modification entry**: validates address bounds, page type via bitmask 0x409, flag consistency, then delegates to PTE modifier |
| 0x1a90 | 0x5a0+ | **Core PTE modifier**: 0x138-byte frame, processes in 32-entry batches, validates entries are zero before writing, manages buddy allocator byte counts |

## Security Analysis

### 1. NO priv_check in syscall entry (CRITICAL)
- Entry at 0x000 reads proc->0x5d0 and proc->0x5c4 but stores them as metadata only
- Zero calls to priv_check, zero ucred accesses for permission decisions
- The only "gate" is mask 0xffafffff on arg0 — trivially satisfied

### 2. Page attribute modification without privilege check (CRITICAL)
- Function at 0x1850 (direct page modifier) checks:
  - Address bounds against proc->0x200 (just bounds, not permission)
  - Page type against bitmask 0x409 (types 0, 3, 10)
  - Flag consistency: `(arg_flags & 0xcc) | extra_flags == 0`
  - Object type at +0x9d must be 0xb
- NO priv_check, NO ucred, NO auth ID anywhere in this path

### 3. Feature flag is not a security check
- `test BYTE PTR [rdi+0x244], 0x1` at 0x581 is a feature gate on the mapping structure
- Not checked against the caller's credentials
- If mapping was created with this bit set (normal for GPU contexts), the operation proceeds

### 4. GPU memory security implications
- Page type 0xa (bit 0x800000) controls "large page" vs "normal page" classification
- Bits 28-29 (0x30000000) control cacheability/protection attributes
- Bits 20-23 (0xf00000) encode the page type (10 different types)
- Modifying attributes on shared GPU memory could:
  - Change R/O pages to R/W (if attribute encoding permits)
  - Alter cache coherency (bypass GPU cache isolation)
  - Reclassify page types to gain different access patterns

### 5. Three-level bitmap exposes allocation metadata
- Bitmap at +0x70/+0x20000/+0x20800 reveals which pages are allocated
- Combined with sys 639 (memory region info), provides precise GPU memory layout

## Exploitation Potential
```
1. Obtain GPU context handle (normal game/app operation)
2. Call sys 653 with arg0 targeting specific GPU memory
3. Modify PTE attributes to change page protection
4. Write to previously read-only GPU command buffer
5. Inject GPU commands for arbitrary memory access
```

**14.10 survivability**: STRUCTURAL — the handler architecture lacks privilege checks by design, not by oversight of a single path.
