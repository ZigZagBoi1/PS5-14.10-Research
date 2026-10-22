# Upstream 14.00/14.10 kernel landmarks — private research note

Status: **public upstream offsets, not a local live kernel pointer or R/W primitive.** This note records version-matched landmarks useful for validating a future leak or read. No console test was run.

## Primary-source provenance

- `ps5-payload-dev/sdk`, commit [`a7685ce8e97c`](https://github.com/ps5-payload-dev/sdk/commit/a7685ce8e97ce1f8a4f38253a41d54241c9124f1) (2026-10-12), adds cases `0x14000000` and `0x14100000` to `crt/kernel.c`.
- `ps5-payload-dev/ftpsrv`, commit [`35bae1312b14`](https://github.com/ps5-payload-dev/ftpsrv/commit/35bae1312b14840c0f95fab93be73d6daaa93bae) (2026-10-20), adds cases `0x1400` and `0x1410` to `self-prospero.c`.

Let `D` be the **live 14.10 kernel data base**, which we do not have. The SDK's `__kernel_init` assigns `KERNEL_ADDRESS_DATA_BASE = args->kdata_base_addr`, so it receives `D` from an existing payload/exploit. The FTP code calls `kernel_getlong`/`kernel_setlong`, which already require kernel read/write access.

| Symbol/region | Upstream expression |
| --- | --- |
| Kernel text base | `D - 0x0CE0000` |
| `allproc` | `D + 0x28D9EA0` |
| `security_flags` | `D + 0x0DA4064` |
| `rootvnode` | `D + 0x315B510` |
| `bus_data_devices` | `D + 0x20A8878` |
| Pager table used by FTP SELF mapper | `D + 0xE13E00` |
| `vmspace.p_root` field | `+0x1d0` |
| `vmspace.vm_pmap` field | `+0x2e8` |

## How this changes the research

The local docs' statement that no 14.10 offsets are available is now stale **for these specific symbols**. A verified KASLR disclosure still must establish `D` or a text address with a justified relation to `D`. A verified kernel read could then compare several independent landmarks and structure fields against the upstream offsets. Do not infer `D` from a random canonical-looking qword, and do not perform a kernel write merely because an offset is published.

The upstream commits do not publish the 14.10 exploit, a live kernel-base value, the plaintext kernel image, or a proof that these offsets work on this user's console. Preserve that boundary when reporting progress.
