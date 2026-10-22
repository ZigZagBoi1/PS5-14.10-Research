# 14.10 device mmap pointer review — 2026-10-21

## Live observations

Probe `122a` opened `/dev/gc`, mapped one 16 KiB page at offset zero with `PROT_READ|PROT_WRITE, MAP_SHARED`, and read the first 256 bytes without writing. All 32 qwords were `0xffffffffffffffff`; the mapping and fd were closed, and the process canary ran. This gives no pointer candidate.

Probe `122b` opened `/dev/dmem1`, mapped one 16 KiB page at offset zero with `PROT_READ, MAP_SHARED`, and read the first 256 bytes. The first three qwords match the earlier `/dev/dmem0` GPU-aperture header (`0x80000000c0012800`, `0xc000120080000000`, `0xc005580000000000`). Offset `+0x18` was `0xffffffff2ec47fc0`. It was already printed at the same offset in `results/phase2_kernel_objects/17_dmem_kptr_20261015_192017.txt`, from a different loader process six days earlier. This is a repeated **address-shaped value**, not a verified kernel pointer: no backing kernel object, valid kernel mapping, dereference, or KASLR movement has been shown. The surrounding data looks like GPU aperture registers or command words, and the value lies below the 13.60 dump's kernel-text band. Do not use it as a kernel base.

The `122b` pointer classifier excluded every value with high dword `0xffffffff`, so its printed `kernel_shaped_count=0` is **not** a valid scan result for the PS5 kernel address band. The raw qwords above are the evidence. It correctly completed the `/dev/dmem1` mapping, read, unmap, and close before proceeding.

For `/dev/dmem2`, `mmap` printed an all-ones failure value. The probe's failure predicate did not recognize the loader's returned object representation, then attempted to read that invalid address. The capture ends before the dmem2 canary or cleanup, and a subsequent ping was `CONNECTION_REFUSED`. The sender's `COMPLETE` transport label does not mean the Lua probe completed. This is a probe bug, not evidence of a kernel pointer, kernel crash, or dmem2 memory content. Do not rerun `122b` unchanged. The exact captured source and SHA-256 are retained with the raw result for attribution.

## Evidence

- `results/phase21_kernel_leak/122a_gc_mmap_pointer_slice_20261021_151058.txt` and `.json`
- `results/phase21_kernel_leak/122b_dmem12_pointer_slices_20261021_151130.txt` and `.json`
- `results/phase5_buffer_io/32e_ping_20261021_151143.txt` and `.json`
- `results/phase2_kernel_objects/17_dmem_kptr_20261015_192017.txt`

No 14.10 kernel pointer or kernel R/W is verified by these captures.
