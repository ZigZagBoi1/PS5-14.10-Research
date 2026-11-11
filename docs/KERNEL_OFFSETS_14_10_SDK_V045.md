# PS5 14.10 Kernel Offsets — SDK v0.45

Extracted from `ps5-payload-dev/sdk` v0.45, file `crt/kernel.c`.
Released 2026-10-21. Same offsets for 14.00 and 14.10.

## Per-Firmware Offsets (relative to DATA_BASE)

All addresses computed as `KERNEL_ADDRESS_DATA_BASE + offset`.

| Symbol | Offset from DATA_BASE | Purpose |
|--------|----------------------|---------|
| TEXT_BASE | DATA_BASE - 0x0CE0000 | Kernel .text segment start |
| ALLPROC | DATA_BASE + 0x28D9EA0 | Process list head |
| SECURITY_FLAGS | DATA_BASE + 0x0DA4064 | Security flags word |
| ROOTVNODE | DATA_BASE + 0x315B510 | Root filesystem vnode |
| BUS_DATA_DEVICES | DATA_BASE + 0x20A8878 | Bus/device tree |

Derived from SECURITY_FLAGS (shared across all firmwares):
| Symbol | Offset | Purpose |
|--------|--------|---------|
| TARGETID | SECURITY_FLAGS + 0x09 | Target ID byte |
| QA_FLAGS | SECURITY_FLAGS + 0x24 | QA flags word |
| UTOKEN_FLAGS | SECURITY_FLAGS + 0x8C | Utoken flags |

## VM Space Offsets (per-firmware, same for 13.60+)

| Symbol | Value | Purpose |
|--------|-------|---------|
| VMSPACE_P_ROOT | 0x1D0 | VM map root |
| VMSPACE_VM_PMAP | 0x2E8 | Physical map pointer |

## Structure Field Offsets (shared across all firmwares)

### proc structure
| Field | Offset | Purpose |
|-------|--------|---------|
| p_ucred | 0x40 | Credential pointer |
| p_fd | 0x48 | File descriptor table |
| p_pid | 0xBC | Process ID |
| p_vmspace | 0x200 | VM address space |

### ucred structure
| Field | Offset | Purpose |
|-------|--------|---------|
| cr_uid | 0x04 | Effective UID |
| cr_ruid | 0x08 | Real UID |
| cr_svuid | 0x0C | Saved UID |
| cr_rgid | 0x14 | Real GID |
| cr_svgid | 0x18 | Saved GID |
| cr_prison | 0x30 | Jail/prison pointer |
| cr_sceauthid | 0x58 | Sony auth ID (8 bytes) |
| cr_scecaps | 0x60 | Sony capabilities (16 bytes) |
| cr_sceattrs | 0x80 | Sony attributes (32 bytes) |

### filedesc structure
| Field | Offset | Purpose |
|-------|--------|---------|
| fd_rdir | 0x10 | Root directory vnode |
| fd_jdir | 0x18 | Jail directory vnode |

## How the SDK Gets Kernel R/W

The SDK does NOT find these addresses itself. The **kernel exploit** passes them in:

```c
// kernel_init() requires these args from the exploit:
args->rwpair[0]       // MASTER_SOCK - IPv6 socket for write target
args->rwpair[1]       // VICTIM_SOCK - IPv6 socket for write data
args->rwpipe[0]       // Pipe fd for read
args->rwpipe[1]       // Pipe fd for read
args->kpipe_addr      // Kernel address of the pipe buffer
args->kdata_base_addr // Kernel data segment base address
```

The R/W primitive uses `IPV6_PKTINFO setsockopt`:
1. **Write**: Set MASTER_SOCK pktinfo to target kernel address, then
   set VICTIM_SOCK pktinfo with the data — kernel copies data to the target.
2. **Read**: Similar pipe-based technique using the kernel pipe buffer address.

## What This Means for 14.10 Research

**We have:** The exact structure layout (where allproc, rootvnode, ucred fields
are relative to DATA_BASE).

**We still need:**
1. **KERNEL_ADDRESS_DATA_BASE** — the runtime address of the kernel data segment.
   Our fault oracle gives TEXT_BASE. SDK says DATA_BASE = TEXT_BASE + 0x0CE0000.
   So if fault oracle reads TEXT at 0xFFFFFFFFD4000000, then
   DATA_BASE = 0xFFFFFFFFD4000000 + 0x0CE0000 = 0xFFFFFFFFD4CE0000.
   **This is computable from our existing KASLR oracle!**

2. **A kernel R/W primitive** — the socket pair + pipe technique requires
   a kernel vulnerability to set up (corrupted pipe buffer address, controlled
   socket options). The offsets tell us WHERE to read/write, not HOW.

3. **The kernel exploit itself** — "Gezine" (the private 14.10 KEX) presumably
   provides the corrupted socket/pipe primitives. Without it, offsets alone
   cannot read or write kernel memory.

## Comparison: 13.60 vs 14.10

| Symbol | 13.60 | 14.10 | Delta |
|--------|-------|-------|-------|
| TEXT delta | -0x0CC0000 | -0x0CE0000 | +0x20000 |
| ALLPROC | +0x28C9E80 | +0x28D9EA0 | +0x10020 |
| SECURITY_FLAGS | +0x0D9C064 | +0x0DA4064 | +0x8000 |
| ROOTVNODE | +0x314B510 | +0x315B510 | +0x10000 |
| BUS_DATA_DEVICES | +0x2098228 | +0x20A8878 | +0x10650 |

The offsets shifted by ~64KB between 13.60 and 14.10, consistent with
a kernel rebuild adding a few pages of code/data.
