# SDK collector status (2026-10-21)

The 13.60 SDK collector completed both entries of the official 14.10 recovery PUP in `manual-sdk-updaterid-20261020`. The PS5 log ended with `Privilege restore: 0` and `RESEARCH EXTRACTION SUCCESS`. The server preserved both decrypted PUPs and the original PUP; no updater/install call was made.

The offline unpacker extracted 40 files, then crashed with SIGSEGV while processing the nested `ssd0.system_b` image. The run's `status.json` therefore says `unpack_failed`; this refers to nested unpacking, not the console's PUP decryption. See [PUP14 extraction analysis](../../docs/PUP14_EXTRACTION_ANALYSIS_2026-10-21.md) for byte-level verification of the kernel candidate and encrypted inner images.

The startup fix uses the SDK runtime's `dlsym` for imported functions. The decrypt device `/dev/pup_update0` is a root-owned character device. Its open initially returned `EPERM`. The collector saves its own credentials, temporarily applies the running `SceUpdatePupUtil` process's auth ID/caps/attrs plus UID 0, and restores the saved values on normal return. The receiver log confirmed `Temporary privilege setup: 0 updater_identity=1`.

The current website payload is the SDK ELF with SHA-256 `e94b04204021cf6e2c97f85d1523c1bde50e84c7e8885964e66f5610812c8994`. It adds durable range receipts for new runs and has been tested offline; the completed October 20 manual run used the prior ELF and has no range receipts. The USB fallback ELF still uses the older startup path and is not validated with this loader.
