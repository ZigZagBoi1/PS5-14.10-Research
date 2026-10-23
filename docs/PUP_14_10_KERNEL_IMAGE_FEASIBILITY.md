# Can the 13.60 PS5 expose the 14.10 kernel from a PUP?

**Outcome on 21 October 2026:** The 13.60 console successfully decrypted the *outer* 14.10 recovery PUP into two `.dec` entries. The extracted `kernel.bin` is complete but opaque, with 7.999994 bits/byte whole-file entropy and no ELF magic or kernel strings. Its hash matches the source range in the decrypted PUP, ruling out unpacker damage to that file. This route has not yielded a plaintext 14.10 kernel or a kernel pointer. See [the extraction analysis](PUP14_EXTRACTION_ANALYSIS_2026-10-21.md). The remainder of this document records the earlier feasibility reasoning and should be read as pre-test context.

Status: offline source review and payload build, 2026-10-20. No PS5 was contacted.

The official 14.10 recovery PUP is saved locally at `artifacts/pup14/PS5UPDATE_14.10_RECOVERY.PUP` (SHA-256 `9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de`). Guarded USB and LAN ELFs plus unpack/inventory tools are documented in [`tools/pup14/README.md`](../tools/pup14/README.md). The LAN route was deployed to `marwanmohamed.ca/ps5/`. Hardware later confirmed outer decryption; the inner kernel component remained opaque.

## Short answer

This is a credible extraction experiment, not a brute-force problem. A jailbroken 13.60 PS5 can potentially act as a decryption oracle for the *outer* 14.10 PUP container. The public [`ps5-pup-decrypt`](https://github.com/zecoxao/ps5-pup-decrypt) payload opens `/dev/pup_update0` and invokes the console's verification/decryption ioctls on a PUP supplied from USB, writing `PS5UPDATE1.PUP.dec` (and sometimes `PS5UPDATE2.PUP.dec`) to USB. Its source has no explicit firmware-version comparison. The README limits cross-version decryption for `system`, `system_ex`, and `wlan`; it does not state that `kernel.bin` is subject to that same limit. None of this proves a 13.60 console accepts a 14.10 PUP.

The [PS5 Developer Wiki PUP page](https://www.psdevwiki.com/ps5/PUP) identifies `kernel.bin` as an update component. However, outer PUP decryption and unpacking may leave `kernel.bin` in an encrypted or signed inner format. A file named `kernel.bin` is not automatically analyzable x86-64 kernel text. The usable artifact must be checked for format, decryptability, code content, and firmware provenance.

## Evidence from the public payload source

- `source/decrypt.c`: validates the SLB2 outer header, opens `/dev/pup_update0`, calls `encsrv_verify_blsheader`, calls `encsrv_decrypt_header`, then decrypts individual PUP segments. It writes `.dec` output. It does **not** call an update/install function in the reviewed path.
- `source/encryptsrv.c`: the relevant ioctl wrappers use `0xC0104401` for BLS verification, `0xC0184402` for header decryption, `0xC0184405` for segment decryption, and `0xC0284406` for segment-block decryption.
- `README.md`: explicitly reports that `ssd0.system`, `ssd0.system_ex`, and `wlan` are only decrypted on the same firmware or a higher version within the same major `.XX` family. It does not report a 13.60-to-14.10 success.

## Offline validation sequence before any console run

1. Obtain an official 14.10 update or recovery PUP and record its SHA-256 and source. This step is complete for the 14.10 recovery PUP. A recovery PUP may contain more complete components; an update PUP may suffice for `kernel.bin`.
2. Parse the plaintext SLB2 header and record the inner PUP entry names and lengths. This can be done on a PC without keys. Do not interpret this as decryption.
3. Review the exact payload revision to be used, its write targets, output bounds, logging, and error behavior. The public source's `decrypt_pup_data()` returns `0` even after some `goto end` failures, so a file's existence or final “Complete” notification is not proof of successful decryption. Per-segment logs and output validation are required.
4. If physical testing is later authorized, keep the 13.60 console on 13.60. Supply the 14.10 PUP as *input data* to the decryptor; do not enter the system updater. Capture the complete ioctl/segment log and resulting `.dec` files.
5. Unpack the `.dec` PUP and inspect `kernel.bin`. Check for an ELF header, parsable executable segments, plausible x86-64 code and strings, and consistency with the PUP firmware. If it remains an encrypted SELF or opaque blob, outer-container decryption has not produced the needed kernel image.
6. Only a verified 14.10 code image supports static comparison against 13.60 or upstream FreeBSD. Preserve the original PUP hash, decryptor commit, console firmware, output hashes, and extraction log.

## What brute force cannot establish here

The public PUP format reveals headers, not the necessary secret key material. Trying candidate keys against ciphertext is only useful with a grounded key derivation or validation oracle; exhaustive search of a modern symmetric key is not a realistic route. A community PC decryptor report tested many public key candidates against 14.00 and 14.10 without a valid PUP header; its claims about a universal missing key remain unverified. The on-console decryptor instead asks the PS5's own security service to process the PUP.

Even a successful 14.10 kernel image extraction would accelerate vulnerability research and offset discovery; it would **not itself provide kernel R/W on the 14.10 console** or turn on Debug Settings.
