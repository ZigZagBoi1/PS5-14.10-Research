# Private static triage: IPv6 source filter path in the labeled 13.60 capture

This is an offline reading of `docs/dumps_13.60/kernel_text.bin` (SHA-256 `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`). The accompanying 16 KiB-chunk failmap marks the chunks containing RVAs `0x8ff8c0`, `0x900940`, `0x901230`, and `0x259280` as successful (zero). The dump is labeled firmware 13.60; its acquisition authenticity and relationship to 14.10 are not independently established here. It cannot settle the 14.10 CVE question.

## Structural match and order

The function at RVA `0x900940` has a strong structural match to an IPv6 source-filter setter:

| RVA | Observed instruction or call | Narrow inference |
|---|---|---|
| `0x900968`–`0x90097d` | request size `0x98`, call `0x50b030` | Copy a 152-byte socket-option request into the stack frame. |
| `0x90098d` | compare source count at stack offset `-0xc0` to `0x80` | Maximum of 128 entries on this path. |
| `0x9009a3`–`0x9009b5` | validate mode against two accepted values | Consistent with INCLUDE/EXCLUDE modes. |
| `0x9009bb`–`0x9009dc` | validate `0x1c` address family and multicast byte `0xff` | Consistent with an IPv6 multicast group. |
| `0x900a2b`–`0x900a63` | allocate `nsrcs * 0x80` then call `0x901230` | Copy the source array to a kernel buffer. `0x901230` tail-jumps to the general copyin routine at `0x259280`. |
| `0x900a88`–`0x900aa3` | call `0x9007d0`, then `0x8fde70` | Membership setup/lookup occurs **after** source-list copyin along this path. `0x9007d0` starts by acquiring a lock on the inpcb-like object at `+0x180`. |
| `0x900b51`–`0x900b5e` | call `0x901280` with the copied source buffer | This later helper traverses and allocates source-filter nodes; it is not another userland `copyin`. |

The general socket-option path reaches a protocol-specific function pointer (`0x50b2ff`). A nearby IPv6-looking setter at `0x8ff8c0` dispatches through a jump table for option values 9–85 (`0x8ff90c`–`0x8ff929`). That jump table is at RVA `0x181ca00`, outside the saved 15,132,096-byte range, so this capture does **not** directly prove which option selects `0x900940`. The 152-byte layout, 128-source cap, mode checks, IPv6 group check, and source-array copy make the identification strong but still inferential.

If this is the 13.60 `IPV6_MSFILTER` setter, its observed sequence is consistent with copying sources before obtaining the membership pointer. It does not show the upstream vulnerable lookup → unlock → copyin → relock sequence. The 14.10 live tests prove option 74 is reachable and that membership changes affect its return values; they cannot reveal this internal order. Do not call the CVE present or absent on 14.10 from this older capture.

Next evidence gate: authenticated 14.10 handler bytes or a repeatable memory-safety effect that distinguishes stale-pointer use from ordinary membership loss. More return-code-only race trials cannot answer that question.
