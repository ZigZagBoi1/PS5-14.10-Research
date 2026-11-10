# Debug Settings Enablement Chain -- PS5 14.10

**Status:** all kernel offsets identified; kernel R/W is the single remaining prerequisite
**Last updated:** 2026-11-09

## The Write

With kernel read/write, enabling Debug Settings requires writing 3 bytes in the
kernel `.data` segment. All offsets are from `DATA_BASE` (the kernel data segment
base, derived from the kernel image base measured by the fault oracle + the
image's known data segment offset).

| Target | Offset from DATA_BASE | Write | Effect |
|--------|----------------------|-------|--------|
| `target_id` | `+0x0DA406D` | `0x82` (TestKit) | Makes `sceSblAIMgrIsTestKit` return true |
| `qa_flags[0]` | `+0x0DA4088` | `0x01` (bit 0 set) | Enables Debug Settings menu visibility |
| `utoken_flags` | `+0x0DA40F0` | `0x01` | Enables update token bypass (optional) |

**Source:** ps5-payload-dev/sdk commit a7685ce8 (2026-10-12), cross-referenced with
every PS5 jailbreak offset table from 1.00 through 13.60. See
`docs/agent-work/debug-settings/agent2/SYMBOL_REFERENCE_MAP.md`.

## The Chain (current state to Debug Settings)

```
CURRENT STATE                    REMAINING GAPS                    GOAL
                                                                    
  Lua TCP loader (9026)            1. WebProcess text base          Debug Settings
  + KASLR defeat (fault oracle)    2. Kernel read primitive         menu visible
  + FontFace UAF (192B reclaim)    3. Kernel write primitive        in System Settings
  + VP leaked (0x80f4b9b28)                                         
  + Canvas2D UAF (CVE-2026-43720)                                   
```

### Gap 1: WebProcess text base

**Status:** VP leaked but RVA unknown. `KERN_PROC_AUXV` is confirmed dead
on 14.10 (ret=-1, tested by 56i2/56g3/42h2/43j). Remaining routes:
- 13.60 kernel dump to extract WebProcess binary and compute static RVA (payload 06)
- Delta invariance validation across boots (probe p693) to confirm VP-RVA model
- Probe 1400a tests `open("/proc/self/auxv")` (stat fails but open might not) and
  cross-process auxv -- low probability but costs nothing

**What it unblocks:** with text base known, the walk chain's vtable slots
become resolved function addresses. Combined with the Canvas2D UAF write
primitive, this gives a code-reuse chain entry point.

### Gap 2: Kernel read primitive

**Status:** no kernel pointer has been leaked from any syscall on 14.10.
The fault oracle gives presence (mapped/unmapped) but cannot read content.

**Candidate routes:**
- WebKit heap corruption to redirect a kernel copyin/copyout
- Forged vtable dispatch to call a kernel read gadget
- `sysctl` with controlled MIB pointing into kernel (needs kernel pointer first)

**What it unblocks:** reading `allproc` (`DATA_BASE + 0x28D9EA0`) to find our
own `proc` structure and `ucred`, enabling targeted credential writes.

### Gap 3: Kernel write primitive

**Status:** no kernel write demonstrated. The Canvas2D UAF gives a userland
write-what-where, but converting that to kernel writes requires either:
- Redirecting a kernel `copyout` to write kernel memory
- Corrupting a kernel object that has a write path
- Using the WebKit code-reuse chain to invoke a kernel write syscall with
  controlled arguments

**What it unblocks:** writing `target_id`, `qa_flags`, and optionally `ucred`
fields to enable Debug Settings and sandbox escape.

## Kernel offsets needed (all from DATA_BASE)

| Symbol | Offset | Use |
|--------|--------|-----|
| `security_flags` | `+0x0DA4064` | Base of security flag region |
| `target_id` | `+0x0DA406D` | Device type byte (0x82=TestKit) |
| `qa_flags` | `+0x0DA4088` | QA flag word (bit 0 = debug menu) |
| `utoken_flags` | `+0x0DA40F0` | Update token bypass |
| `allproc` | `+0x28D9EA0` | Process list head (for ucred walk) |
| `rootvnode` | `+0x315B510` | Root vnode (for sandbox escape) |

## Kernel image layout (measured on 14.10)

| Segment | Address (this boot) | Notes |
|---------|-------------------|-------|
| Stub | `0xFFFFFFFFC0000000` | 2 MB, measured by fault oracle |
| Image start | `0xFFFFFFFFD4000000` | 102 MB, 2 MB aligned both edges |
| Image end | `0xFFFFFFFFDA5FFFFF` | |
| ASLR slide | `+0x54000000` | Varies per boot |

DATA_BASE is within the image but its exact offset from image start requires
either: (a) reading the ELF headers from the image, or (b) using the 13.60
kernel dump to measure the text-to-data segment offset (which should be
identical or very close on 14.10).

**Payload 07** (`tools/jailbreak-host/research_payloads/07_kernel_segment_offsets.lua`)
reads the kernel ELF program headers on 13.60 to extract DATA_OFFSET =
data_vaddr - text_vaddr. This is a link-time constant that should match (or
nearly match) across firmware builds from the same source tree. Once measured:

    DATA_BASE (14.10) = IMAGE_BASE (fault oracle) + DATA_OFFSET (13.60 measurement)

The payload also validates by reading `allproc` and `security_flags` at their
SDK-published offsets.

## What the user sees

After writing `target_id=0x82` and `qa_flags[0]=0x01`:
1. Navigate to Settings
2. A new "Debug Settings" entry appears at the bottom of the menu
3. Debug Settings contains: package installer, process viewer, memory viewer,
   network debugging, and other developer/QA tools
4. No reboot required -- the settings UI re-reads the flags on navigation

## Prior art on PS4/PS5

Every existing PS5 jailbreak (1.00 through 13.60) enables Debug Settings by
writing these same 3 bytes. The offset table drifts between firmware versions
but the mechanism is identical. The ps5-payload-dev/sdk maintains the offsets
for each firmware, and the 14.10 values were published in commit a7685ce8.

## Summary

The distance from current state to Debug Settings is:
1. One info leak (WebProcess text base -- VP already leaked, RVA in progress)
2. One exploitation chain (WebKit UAF -> code-reuse -> kernel R/W)
3. Three byte writes in kernel memory

The kernel offsets are known. The kernel image location is known. The UAF
primitives are confirmed. The single blocking question is: how do we get from
the WebKit UAF write primitive to kernel memory access?
