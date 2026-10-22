# 14.10 recovery PUP extraction: offline findings

## Source and saved output

The official recovery PUP is stored privately on `marwanserver` as `/var/lib/ps5-research/pup-source/PS5UPDATE_14.10_RECOVERY.PUP`, SHA-256 `9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de`. The completed run is `/var/lib/ps5-research/pup-runs/manual-sdk-updaterid-20261020/`.

The PS5 payload's log ends with `RESEARCH EXTRACTION SUCCESS` after a successful credential restore. The two decrypted PUP entries are 1,261,406,781 and 157,481,653 bytes. The server kept both `.dec` files, the payload log, `status.json`, extracted files, and `extraction_report.json`. No installation or firmware write was performed by this collector.

The PC-side `pup_unpacker_linux` returned SIGSEGV (`-11`) while processing entry 1 and returned 0 for entry 2. It wrote 40 files. Its entry-1 crash occurred after starting the nested `515_ssd0.system_b` image; this file is only 73,924,608 bytes versus the PUP table's 479,789,056-byte uncompressed size. The following `516_ssd0.system_ex_b` image was never written. Entry 2's `519_ssd0.preinst` is 146,538,496 bytes versus the table's 146,735,104 bytes. Do not treat these nested image files as complete.

## Kernel candidate

The table identifies segment index 16, ID 5, as `kernel.bin`, offset 24,276,117, compressed and uncompressed length 32,689,664 bytes. The extracted `5_kernel.bin` has exactly that length. Its SHA-256, `8cb90195948273cd0cf3bf2cb69897be190304c6dbf1d23b2da9879c15c91905`, **matches the same byte range in the decrypted PUP**. The unpacker therefore copied this candidate correctly.

A full-file byte histogram gives 7.999994 bits/byte entropy; zero bytes are 0.3889% (close to the random 0.3906% expectation). There is no ELF magic, `FreeBSD`, or `SceKernel` string in the entire file. Five distributed 64 KiB samples each have about 7.997 bits/byte entropy and no ELF magic. These observations are consistent with an encrypted or otherwise opaque inner payload. They do not prove the exact encryption method. This file is **not a verified plaintext 14.10 kernel image**, and it yields no kernel RVA or pointer.

## Block and container checks

The first offset audit mistakenly assumed 16-byte padding for every compressed segment. Segment flag `flags2 & 1` selects 512-byte padding. Recomputing with the correct mask shows **zero sequential-read drift across every blocked segment in both PUP entries**. No payload change or server redeployment was made from that false lead. `check_block_offsets.py` records this check.

Sampled compressed blocks of the nested system images `515`, `516`, and `519` fail zlib/gzip header checks after the outer PUP decryption. Their first bytes are high entropy. The upstream unpacker [labels `ssd0.system_b` and `ssd0.system_ex_b` as impossible to handle without keys](https://github.com/zecoxao/ps5-pup-unpacker/blob/005cccc908142c35ab7280e7f9eef8d5203c21e0/PUP.cpp). This supports an additional protected layer inside the PUP; it does not establish where the keys live. The precise cause of the unpacker's SIGSEGV is not yet proven.

The upstream [PUP decryptor README](https://github.com/zecoxao/ps5-pup-decrypt) explicitly limits decryption of `system`, `system_ex`, and `wlan` to PUPs from the same firmware version or a newer version with the same `.XX` family. Our console is 13.60 and the PUP is 14.10, outside that stated range. The source does not state that the same rule applies to `kernel.bin`; its opacity is established here from the bytes, not inferred from that README.

Readable metadata includes `version_name.xml` with prefix version `26.06`, `bd_firm_info.json` with BD firmware records, a valid ZIP font archive, and a 15-entry `titania.bls` plus smaller nested BLS firmware containers. `updatemode.self` has a FreeBSD x86-64 ELF header at offset 224 inside a Sony wrapper, while sampled body regions are high entropy. These are component identities and headers, not readable 14.10 kernel code.

## Reproduce the checks

- `tools/pup14/inspect_extracted.py`: PUP segment table and distributed byte samples.
- `tools/pup14/check_block_offsets.py`: table offsets versus the collector's sequential reads, including 512-byte padding.
- `tools/pup14/check_nested_blocks.py`: bounded zlib/gzip checks of selected nested-image blocks.
- `tools/pup14/verify_kernel_candidate.py`: full kernel candidate hash, entropy, and signature scan.
- `tools/pup14/inspect_containers.py`: BLS member inventory and SELF wrapper header.

The next kernel-image step needs a verified way to remove the **inner** protection or a live 14.10 kernel memory dump. Repeating the completed outer PUP decryption will reproduce the same opaque `kernel.bin` and cannot establish a 14.10 kernel pointer by itself.
