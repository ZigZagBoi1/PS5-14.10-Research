# PS5 Kernel 14.22 — Extracted Offsets

## Firmware
- Build: `14.22 Oct 27 2026 02:17:44`
- Kernel base (without KASLR): `0xFFFFFFFF80210000`

## ELF Segments
| Segment | VA | File Offset | Size | Flags |
|---------|----|-----------| -----| ------|
| .text | 0xFFFFFFFF80210000 | 0x10000 | 0xCE0000 | RX |
| .rodata | 0xFFFFFFFF80EF0000 | 0xCF0000 | 0xDA5000 | R |
| .data | 0xFFFFFFFF81C95000 | 0x1A95000 | 0x12DCC28 | RW |

## Syscall Table
- Location: `kernel+0x1A91FB0` (VA `0xFFFFFFFF81CA1FB0`)
- Entries: 685+
- Each entry is an 8-byte pointer to a `sysent` struct

### Key Syscall Handlers
| Syscall | Number | Handler VA | Kernel Offset |
|---------|--------|-----------|--------------|
| socket | 97 | 0xFFFFFFFF80469200 | +0x259200 |
| setsockopt | 105 | 0xFFFFFFFF8046D280 | +0x25D280 |
| mmap | 477 | 0xFFFFFFFF80468FB8 | +0x258FB8 |

## String Addresses (in .rodata)
| String | VA | File Offset |
|--------|----|-------------|
| allproc | 0xFFFFFFFF81509E54 | 0x1309E54 |
| ip6_ctloutput | 0xFFFFFFFF814B77B1 | 0x12B77B1 |
| pktopts | 0xFFFFFFFF8157371C | 0x137371C |
| in6p_outputopts | 0xFFFFFFFF814F2E0C | 0x12F2E0C |
| setsockopt | 0xFFFFFFFF8159729F | 0x139729F |

## IPv6 Vulnerability Status
- `ip6_ctloutput` string: PRESENT
- `pktopts` string: PRESENT  
- `in6p_outputopts` string: PRESENT
- setsockopt handler uses Sony CFI jump table (50 entries)
- IPv6 code path exists — further analysis needed to confirm if overflow is patched

## Critical Kernel Variables
| Variable | VA | Kernel Offset |
|----------|----|--------------|
| **allproc** | 0xFFFFFFFF81D12300 | +0x1B02300 |
| **prison0** | 0xFFFFFFFF81CD6808 | +0x1AC6808 |

## IPv6 Vulnerability Analysis (14.22)
- **ip6_ctloutput function**: kernel+0x630825
- **Sony added bounds check**: CMP optlen, 0xC0 (192 bytes) before each copyin
- **in6_pktinfo allocation**: 20 bytes (0x14)
- **ip6_pktopts allocation**: 208 bytes (0xD0) 
- **VERDICT**: in6_pktinfo path STILL VULNERABLE — 20-byte allocation with 192-byte copyin limit = **172-byte overflow**
- The ip6_pktopts path is NOT vulnerable (208-byte alloc > 192-byte limit)

## prison0 Structure (from file dump)
```
+0x00: pr_list.tqe_next = 0 (no next prison in file)
+0x08: pr_list.tqe_prev = 0
+0x10: pr_id = 0 (root prison)
+0x14: pr_ref = 1 (initial refcount)
+0x18: pr_uref = 0
+0x1C: pr_flags = 0
+0x28: pr_childmax = 100
+0x30: pr_childcur = 100 (?)
```

## Jailbreak Strategy
1. Use in6_pktinfo overflow (20B alloc, 192B copyin) for kernel heap corruption
2. Overwrite adjacent object to get kernel R/W
3. Read allproc at kernel+0x1B02300 → walk proc list → find current process
4. current_proc->p_ucred->cr_uid = 0 (root)
5. current_proc->p_ucred->cr_prison = &prison0 (kernel+0x1AC6808) (escape jail)

## Structure Offsets (FreeBSD 13-based PS5 kernel)

### struct proc
| Field | Offset | Description |
|-------|--------|-------------|
| p_ucred | +0x40 | pointer to ucred |
| p_fd | +0x48 | pointer to filedesc |
| p_pid | +0xBC | process ID |

### struct ucred
| Field | Offset | Description |
|-------|--------|-------------|
| cr_ref | +0x00 | reference count |
| cr_uid | +0x04 | effective UID → SET TO 0 |
| cr_ruid | +0x08 | real UID → SET TO 0 |
| cr_svuid | +0x0C | saved UID → SET TO 0 |
| cr_ngroups | +0x10 | number of groups |
| cr_rgid | +0x14 | real GID → SET TO 0 |
| cr_svgid | +0x18 | saved GID → SET TO 0 |
| cr_prison | +0x30 | prison ptr → SET TO &prison0 |

### struct thread
| Field | Offset | Description |
|-------|--------|-------------|
| td_proc | +0x08 | pointer to proc |

## Jailbreak Algorithm
```
1. curthread = read(kernel_base + curthread_offset)  // need KASLR bypass
2. curproc = kread64(curthread + 0x08)
3. ucred = kread64(curproc + 0x40)
4. kwrite32(ucred + 0x04, 0)   // cr_uid = 0
5. kwrite32(ucred + 0x08, 0)   // cr_ruid = 0
6. kwrite32(ucred + 0x0C, 0)   // cr_svuid = 0
7. kwrite32(ucred + 0x14, 0)   // cr_rgid = 0
8. kwrite32(ucred + 0x18, 0)   // cr_svgid = 0
9. kwrite64(ucred + 0x30, kernel_base + 0x1AC6808)  // cr_prison = &prison0
10. Process is now root + jail-escaped
```

## TODO
- [ ] Find curthread / PCPU offset for KASLR
- [ ] Map 14.22 offsets to 14.10 (binary diff)
- [ ] Build kernel R/W payload using IPv6 overflow
- [ ] Determine kernel heap layout for targeting the overflow
