# PS5 14.10 recovery PUP research package

Status (2026-10-21): The SDK-built LAN collector completed outer decryption of both 14.10 recovery PUP entries on the jailbroken 13.60 PS5. The saved run is `manual-sdk-updaterid-20261020`; the website serves the SDK ELF (SHA-256 `087f9828971478efe2e665b58ee1cae7380cbab1ff64a6e771a22ed62968eff0`). The unpacker wrote 40 components but crashed while processing one nested image. The extracted `kernel.bin` is complete and hash-matched to the decrypted PUP segment, yet remains opaque rather than plaintext kernel code. See [the extraction analysis](../../docs/PUP14_EXTRACTION_ANALYSIS_2026-10-21.md) for measured results and limits.

## Primary path: automatic LAN extraction, no USB

The 14.10 recovery PUP is stored privately on `marwanserver` at `/var/lib/ps5-research/pup-source/PS5UPDATE_14.10_RECOVERY.PUP` with its official SHA-256 checked. The [SDK LAN ELF](../../artifacts/pup14/PS5_1410_RESEARCH_LAN_SDK.elf) is private at `/var/www/ps5-research/private/pup14/`.

On the jailbroken 13.60 PS5, open `https://marwanmohamed.ca/ps5/` and leave **Automatically extract the 14.10 recovery PUP after Relapse** checked. Select **Start Relapse** once. If Relapse reports payload loading and cleanup complete, the site asks its server to send the research ELF to the existing ELF loader on port 9021. The ELF connects to `10.0.0.80:9028`, requests random-access ranges of the official PUP, uses `/dev/pup_update0` to verify/decrypt both inner PUP entries, and streams `.dec` data plus a full log back to the server. No PUP is placed on the console's internal storage or in `PS5/UPDATE`; the payload has no updater/install API call.

The server saves each run privately under `/var/lib/ps5-research/pup-runs/<relapse-session-id>/`. On a reported successful extraction it runs the pinned unpacker and writes `extraction_report.json`, hashes, first-byte/entropy hints, every extracted component, and any `kernel.bin` candidate. The website polls receiver status. The plain `.dec` files and log are preserved even when later unpacking fails. The `pup_bridge.py` listener accepts only the console IP tied to the Relapse session and only while that one run is active.

## Resume support for new runs

The SDK ELF and receiver built after the October 20 live run record a durable SHA-256 receipt for each output write. A resumed run verifies the saved bytes before skipping a block; a missing or changed block is decrypted again. The site automatically selects the most recent failed run with matching source hash and console IP after a new Relapse session. The PS5 must be running and its ELF loader must be ready for the new launch. The receiver keeps the original PUP read-only and does not install firmware.

The already-running `manual-sdk-updaterid-20261020` session started with the earlier ELF and receiver, so its partial output has no block receipts. That session continues unchanged, but it cannot use the new block-skip logic if interrupted. Its partial `.dec` and log remain saved on the server.

The page's checkbox is on by default for this research flow. Turn it off to use the normal etaHEN button. The optional syscall-table dump mode is separate. Do not start another Relapse run in the same boot.

The completed live run proves outer decryption of both entries. It does not yield a plaintext kernel image or a live kernel pointer. Do not repeat the same 13.60 outer-decryption run expecting the inner `kernel.bin` protection to disappear.

## Fallback path: USB

The USB fallback ELF below uses the older startup code and is not validated with this Relapse loader. Use the SDK LAN path above for the current session. The USB instructions are retained as a historical staging reference until the fallback is rebuilt and verified.

## Files ready

- `artifacts/pup14/PS5UPDATE_14.10_RECOVERY.PUP`: official 14.10 recovery PUP, 1,418,890,240 bytes, SHA-256 `9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de`.
- `artifacts/pup14/PS5_1410_RESEARCH.elf`: USB fallback ELF built from `zecoxao/ps5-pup-decrypt` commit `290f5dd216b6878223457f51b32127acc480964a` with local USB input/output, persistent logging, and corrected failure status.
- `artifacts/pup14/PS5_1410_RESEARCH_LAN_SDK.elf`: current website ELF built from that pinned revision with the PS5 Payload SDK, SHA-256 `087f9828971478efe2e665b58ee1cae7380cbab1ff64a6e771a22ed62968eff0`.
- `artifacts/pup14/pup_unpacker_linux`: PC-side unpacker built from `zecoxao/ps5-pup-unpacker` commit `005cccc908142c35ab7280e7f9eef8d5203c21e0`.

## What happens, in order

1. On the **PC**, connect one USB drive with at least 4.3 GB free. Run `tools/pup14/STAGE_USB.cmd`. It detects the single mounted USB disk volume and copies the verified PUP and ELF to its **root**. It does not create `PS5/UPDATE`.
2. Safely eject the USB and connect it to the **jailbroken 13.60 PS5**. Start the existing jailbreak/ELF loader, then launch `PS5_1410_RESEARCH.elf` from the USB. Plugging in the USB does not launch anything automatically. This ELF is a research payload, not an installable PS5 app.
3. The ELF reads the 14.10 PUP from USB. It opens `/dev/pup_update0` on the **13.60** console, asks the console to verify/decrypt PUP entries, and writes `.dec` files plus `PS5_1410_RESEARCH.log` to the same USB. It does not use the PS5 system updater.
4. Back on the **PC**, connect the USB and run `tools/pup14/ANALYZE_USB.cmd`. The PC unpacks every available decrypted component and inventories the files, including any `kernel.bin` candidate.

Windows and the PS5 do not automatically execute this package when a USB is inserted. The current LAN method reads the PUP from the server and does not require the USB.

## Stage a USB drive on this PC

Double-click `tools/pup14/STAGE_USB.cmd`. It refuses to choose if there is no mounted USB disk volume or more than one. Alternatively, with the intended drive mounted as `E:`, run:

```powershell
python tools/pup14/prepare_usb.py E:\
```

The script checks the PUP SHA-256 and size, verifies each copy, requires ample free space, refuses the Windows system drive, and refuses to overwrite a different file. It puts `PS5_1410_RESEARCH.PUP` and `PS5_1410_RESEARCH.elf` at the USB root. The PUP uses a research filename and is outside the PS5 updater's `PS5/UPDATE` folder.

## Console run when physical testing is permitted

On the jailbroken **13.60** PS5, use its existing ELF loader to launch `PS5_1410_RESEARCH.elf` from the USB root. The payload reads the research PUP, asks `/dev/pup_update0` to verify and decrypt its PUP entries, and writes `PS5_1410_PS5UPDATE1.PUP.dec`, possibly `PS5_1410_PS5UPDATE2.PUP.dec`, and `PS5_1410_RESEARCH.log` to the USB root. The 14.10 console is not part of this experiment.

The reviewed payload has no updater/install API call and no console storage output path. This is a code-level finding, not a hardware guarantee: `/dev/pup_update0` behavior and cross-version acceptance cannot be established without a console run. A `.dec` file may be partial if the log says extraction failed. Do not infer success from file presence alone.

## Analyze after the console run

Reconnect the USB to this PC and double-click `tools/pup14/ANALYZE_USB.cmd`, or run:

```powershell
python tools/pup14/analyze_output.py E:\
```

This invokes the pinned unpacker under WSL, extracts every component available from each decrypted PUP, and writes `artifacts/pup14/extraction_report.json` with file paths, sizes, SHA-256 hashes, first bytes, sample entropy, type hints, and `kernel.bin` candidates. It preserves output in `artifacts/pup14/extracted/`. The analyzer refuses to overwrite an existing extraction folder.

If a `kernel.bin` appears, its name alone does not mean it contains usable plaintext kernel code. Inner encryption/signing may remain. A 13.60 console may reject the 14.10 PUP or fail to decrypt some entries. A usable 14.10 kernel image would support offline analysis, but does not itself grant kernel R/W or expose Debug Settings on 14.10.

## Rebuild and audit

```powershell
python tools/pup14/build_payload.py
python tools/pup14/build_network_payload.py
```

The builders pin the upstream commit, apply exact source replacements, check forbidden updater symbols, build with WSL GCC, and copy modified source to `artifacts/pup14/build-audit/` and `artifacts/pup14/network-build-audit/` for review. The builds have not been run on PS5 hardware.
