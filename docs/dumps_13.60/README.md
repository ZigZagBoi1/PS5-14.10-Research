# PS5 Firmware 13.60 - Kernel Dumps

Raw kernel data extracted from a jailbroken PS5 on firmware **13.60** via [Relapse](https://github.com/nicholatian/relapse) + [Byepervisor](https://github.com/Cryptogenic/Byepervisor). These dumps feed directly into the [V14.10 research](../../README.md) — every offset found here narrows what we probe blind on 14.10.

> **Purpose:** Map the full Sony syscall table and handler code on a firmware we control, then diff against 14.10 to find exploitable changes.

## Extraction Method

```mermaid
graph LR
    A["PS5 13.60<br/>10.0.0.30"] -->|browser exploit| B["Relapse<br/>Kernel R/W"]
    B -->|HV bypass| C["Byepervisor"]
    C -->|elfldr :9021| D["Native ELF<br/>kernel_copyout()"]
    D -->|TCP| E["Dump Files<br/>sysent + handlers"]

    style A fill:#2d5016,stroke:#4a8c2a,color:#fff
    style B fill:#2d5016,stroke:#4a8c2a,color:#fff
    style C fill:#2d5016,stroke:#4a8c2a,color:#fff
    style D fill:#2d5016,stroke:#4a8c2a,color:#fff
    style E fill:#2d5016,stroke:#4a8c2a,color:#fff
```

A native PS5 ELF payload uses `kernel_copyout()` to read kernel memory directly, then sends the data over TCP to a receiving host. No browser JS, no crashes, no size limits.

## Kernel Layout

| Field | Value |
|-------|-------|
| Firmware | 13.60 |
| Kernel base (KASLR) | `0xffffffff8a9c0000` |
| Sysent RVA | `+0xe6e5c0` |
| Sysent entries | 679 (48-byte stride) |
| Active handlers | 311 (368 are `nosys` stubs) |
| Sony syscalls (532–676) | 145 entries, 117 with real handlers |

## Files

| File | Size | Description |
|------|------|-------------|
| `sysent_raw.bin` | 32,592 B | Complete sysent table — 679 entries x 48 bytes |
| `sysent_index.json` | ~100 KB | Parsed sysent: syscall number, narg, sy_call address + RVA |
| `kernel_base.txt` | 50 B | KASLR base for this dump session |
| `ucred.bin` | 256 B | Process credential structure |
| `handler_532.bin` – `handler_676.bin` | 4,096 B each | First 4KB of each Sony syscall handler's code |

### sysent_index.json Format

Each entry in the `entries` array:

```json
{
  "num": 532,
  "narg": 3,
  "sy_call": "0xffffffff8b5f1a00",
  "sy_call_off": "0xc31a00"
}
```

- `num` — syscall number
- `narg` — argument count
- `sy_call` — absolute handler address (session-specific, KASLR'd)
- `sy_call_off` — offset from kernel base (stable across boots)

### Handler Bins

Each `handler_NNN.bin` is the first 4,096 bytes of raw x86-64 machine code at `sy_call` for that syscall. Disassemble with:

```bash
objdump -D -b binary -m i386:x86-64 handler_532.bin
```

## Cross-Firmware Diffing

The sysent RVA (`+0xe6e5c0`) matches across 13.60 and 14.10, confirming the table location is stable. Handler offsets differ — that's where the bugs are.

To diff a specific handler between firmware versions:

```bash
# Mask relocation-sensitive bytes, then compare
python3 tools/differ.py docs/dumps_13.60/handler_572.bin docs/dumps_14.10/handler_572.bin
```

Key things to look for:
- **New bounds checks** — Sony patching a vulnerability we can still hit on 14.10
- **Removed code paths** — features disabled between versions
- **Changed argument validation** — looser checks on 14.10 = potential attack surface

## Known Offsets (13.60)

These are confirmed via `kernel_copyout()` with full kernel R/W:

| Symbol | RVA | Notes |
|--------|-----|-------|
| sysent table | `+0xe6e5c0` | 679 entries, 48B stride |
| nosys handler | `+0x265760` | Stub for unimplemented syscalls |

## Next Steps

1. **Run the full kernel dumper** — `.text`, `.data`, and loaded module list (ELF is built, not yet deployed)
2. **Diff every Sony handler** against 14.10 probing results to identify patched vulnerabilities
3. **Update to 14.00** and validate whether bugs found on 13.60 survive the intermediate firmware
4. **Build a complete symbol table** from the full `.text` dump via signature matching

## Related

- [V14.10 Research README](../../README.md) — the main research targeting current firmware
- [Attack Surface Map](../ATTACK_SURFACE.md) — complete syscall status for 14.10
- [Findings](../FINDINGS.md) — detailed technical findings from probing
- [Strategy](../STRATEGY.md) — exploit strategy and dead ends
