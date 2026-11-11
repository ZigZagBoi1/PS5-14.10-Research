# WebProcess .text is Execute-Only (XO) on PS5 14.10

> **Grade:** [S] — derived from p807 scan behavior (crash on read into .text region)
>
> **Date:** 2026-11-10

## Discovery

Probe p807 (`p807-base-discovery.html`) scanned backward from VP (a CSSFontFaceSet
vtable pointer in `.rodata`) in 4 MiB coarse steps, then refined to 16 KiB. Reads
succeeded throughout `.rodata` and crashed at the `.text` boundary. The ELF header
at RVA `0x0` IS readable (p807 found magic `7F454C46`), confirming the image base.

The crash boundary is the `.text` section: execute-only pages with no read permission.
All vtable function addresses (S0–S8 from p691) point into `.text` and are unreadable.

## WebProcess Memory Map (14.10)

| Region | RVA range | Protection | Evidence |
|--------|-----------|------------|----------|
| ELF headers | `0x0` – `~0x4000` | RO (`R--`) | p807: read ELF magic `7F454C46` at base |
| `.text` | `~0x4000` – `0x6AD7000` | XO (`--X`) | p807: crash on first read into region |
| `.rodata` + vtables | `0x6AD7000` – `0x724DB28`+ | RO (`R--`) | p807: read VP; p691: walk chain |
| Heap / data | various | RW (`RW-`) | Standard bmalloc / data segments |

`.text` size: ~107 MiB (`0x6AD3000` bytes). `.rodata` begins where reads succeed.

## Comparison Across PS5 Binaries

| Binary | `.text` prot | Readable? | Evidence |
|--------|-------------|-----------|----------|
| **eboot** (game) | RX (`R-X`) | YES | 56d: gadget bytes read from eboot `.text` |
| **System .sprx** | XO (`--X`) | NO | CLAUDE.md: reading .sprx .text crashes past pcall |
| **WebProcess** | XO (`--X`) | NO | p807: crash on read at `.text` boundary |

WebProcess `.text` matches system libraries, NOT eboot. The eboot exception
(RX instead of XO) is specific to the game executable loaded by the Lua loader.

## Impact on Exploitation

1. **ROP gadget scan by reading `.text` is impossible.** p808 (gadget-scan probe)
   was fundamentally flawed — Phase D (scan around S0–S8) and Phase E (scan from
   base) would crash on the first `forgeRead` into `.text`.

2. **S0–S8 are valid dispatch targets but unreadable.** The 9 vtable function
   pointers leaked by p691 are executable code addresses at known offsets from
   base. Their instruction bytes cannot be inspected from JS.

3. **`.rodata` CAN be scanned** for additional vtable pointers, expanding the set
   of known dispatch targets without reading code bytes.

4. **Exploitation must use COOP** (Counterfeit Object-Oriented Programming): forge
   C++ objects whose vtable pointers redirect virtual dispatch to known function
   addresses analyzed from WebKit source code — not from runtime gadget scanning.

## Consequence for p808

p808 (`p808-gadget-scan.html`) attempted to read WebProcess `.text` for `syscall; ret`
and stack-pivot gadgets. The entire approach is dead. Superseded by COOP: source-code
analysis of CSSFontFaceSet vtable functions + `.rodata` vtable enumeration.

## See Also

- `docs/FAULT_CODE_ORACLE_14_10.md` — kernel KASLR defeat (separate oracle)
- `docs/EXPLOITATION_STATUS.md` — chain status and next actions
- `probes/phase13_webkit/p807-base-discovery.html` — the base-search probe
- `probes/phase13_webkit/p808-gadget-scan.html` — the dead gadget-scan probe
