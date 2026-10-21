# Private printed-address audit — 2026-10-21

An offline scan of every `results/**/*.txt` capture found no additional **verified 14.10 kernel pointer**. This audit searched printed hexadecimal qwords with a `0x` prefix, both contiguous and `high32_low32` forms, in the canonical high-address ranges. It does **not** inspect unprinted buffer bytes, binary files, or encrypted PUP data. It is a candidate search, not proof that no leak exists.

## Address-shaped values that need context

| Capture | Candidate | Why it is not a verified pointer |
| --- | --- | --- |
| `phase14_final_push/56i4_vm_region_dump_20261018_120109.txt` and `56i5_kptr_investigate_20261018_120505.txt` | `0xfffffffe_082e0057` | A value inside a user mapping, with no source identity or KASLR behavior. The later `56i8` eboot/module scan reports zero true candidates outside the known module table. |
| `phase14_final_push/56i6_kaslr_pivot_20261018_121034.txt` | 2,828 “KPTR” module data matches | `56i7` shows ascending small low dwords paired with `0xffff....` high dwords. `56i8` observes the same first five values in another process and identifies the module table pattern. These are packed module metadata candidates, not demonstrated runtime kernel VAs. |
| `phase17_new_vectors/100a_kernel_table_modlist_20261019_184946.txt` | `0xfffffffffdc7bb70` | Labeled as a **signed key** in a table record. It repeats for several distinct lookup inputs and is accompanied by a small offset/correction. No dereference or relocation evidence. |
| `phase2_kernel_objects/17_dmem_kptr_20261015_192017.txt` | `0xffffffff2ec47fc0` | Below the expected `0xffffffff8.......` kernel-text band, and the capture's proposed slides are arithmetic hypotheses, not kernel reads. |
| `47b_cclosure_hijack_20261016_200432.txt` | `0xffffffff91......` | Printed after `mod0.text+` as an unsigned negative **relative offset**; the raw CClosure values are userland `0x00000003_........` addresses. |
| `56i9_kaslr_bruteforce_20261018_121926.txt`, `56j_timing_kaslr_20261018_122158.txt`, `13_nwake_oracle_20261015_190841.txt` | kernel-band addresses | Probe-supplied *input addresses* for timing/oracle attempts, not returned bytes. |

Most other high-hex matches in the corpus are all-ones syscall failure returns. The scan's result agrees with the existing individual capture reviews but cannot certify any unprinted region. A future positive result must retain the raw output bytes, exact syscall/output-buffer provenance, and same-boot/cross-boot checks before it is promoted to a pointer finding.
