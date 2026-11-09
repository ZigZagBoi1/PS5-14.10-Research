# 48-byte AIO object: small-allocation spray reassessment

**Date:** 2026-10-25  
**Status:** 56-byte `IPV6_RTHDR` set/get and 64-object spray confirmed on 14.10; exact backing zone and AIO overlap unverified.  
**Scope:** The AIO R object allocated at 13.60 `sys_662.c:2607`, not every AIO sub-object.

## Finding

`IPV6_RTHDR` (IPv6 socket option 51) with a **valid 56-byte type-0 routing header** is the best size-controlled, readable candidate found. FreeBSD 11's `ip6_setpktopt` validates the header, then calls `malloc(rthlen, M_IP6OPT, M_NOWAIT)` and copies all `rthlen` bytes into it. `ip6_getpcbopt` reads the stored header through `getsockopt` using its encoded length. A public Lapse implementation uses this same set/get interface with 120-byte headers targeting a 128-byte malloc class on earlier PS5 firmware. A 56-byte header would conventionally use the same 64-byte malloc size class as the AIO R object's 48-byte request. **On 14.10, the set/get interface and 64-object spray work; the actual size table, malloc subzone choice, and AIO overlap remain unmeasured.**

- [FreeBSD 11 routing-header validation, allocation and copy](https://raw.githubusercontent.com/freebsd/freebsd-src/stable/11/sys/netinet6/ip6_output.c#L2780-L2815)
- [FreeBSD 11 routing-header getter](https://raw.githubusercontent.com/freebsd/freebsd-src/stable/11/sys/netinet6/ip6_output.c#L2195-L2290)
- [Public Lapse routing-header set/get and size builder](https://github.com/rezaadi0105/PSFree/blob/main/lapse.mjs#L2929-L2999)
- [13.60 AIO R allocation](../../results/kernel_handlers/decompiled/sys_662.c) (`0x30` bytes, malloc type `0x1ab59e0`, flags `0x102`)

The setter copies **all 56 input bytes**, so a normal set/get round trip cannot reveal stale R pointers. A readback of R contents would require a proven alias or later overwrite of the routing-header allocation. No such 14.10 overlap is demonstrated here.

## Allocator correction

The 13.60 function at `kernel_text.bin` RVA `0xc08b50` takes `(size, type, flags)`, uses the requested size to index a global size-class table, then chooses a backing zone from a global array. The corresponding free function at RVA `0xc08df0` takes `(pointer, type)` and recovers the backing zone from the pointer's slab metadata. Type registration at RVA `0xc090b0` initializes a per-type internal subzone byte to zero. This behavior matches FreeBSD kernel `malloc(size, struct malloc_type *, flags)` and `free(ptr, type)`, **not** `uma_zalloc(zone, flags)` and `uma_zfree(zone, ptr)`.

Therefore `0x1ab59e0` is a malloc-type descriptor, not proof of a dedicated R-only UMA zone. Different type addresses do not prove cross-subsystem isolation. They also do not prove sharing: the type's subzone byte and the size-class tables determine the actual backing zone. The relevant tables (RVA `0x2bfb8d0` and `0x3dcb460`) are outside the retained 13.60 data ranges, and there is no verified 14.10 kernel image. The statement “R is confirmed to be in a 64-byte zone” should be read as a FreeBSD-based inference.

- [13.60 dump scope](../dumps_13.60/README.md)
- [FreeBSD kernel malloc signature and M_ZERO behavior](https://man.freebsd.org/cgi/man.cgi?query=malloc&sektion=9)
- [FreeBSD 11 size-class allocation](https://raw.githubusercontent.com/freebsd/freebsd-src/stable/11/sys/kern/kern_malloc.c)

The AIO R allocation uses flags `0x102`, consistent with `M_WAITOK | M_ZERO`, so a new zeroing allocation would erase stale bytes. A useful leak candidate needs the right backing class and subzone, an alias that survives a later overwrite, and a getter that exposes the overwritten bytes.

## What earlier tests establish

| Surface | Evidence | Assessment for the 48-byte R object |
|---|---|---|
| `IPV6_RTHDR` 56B | Public Lapse code and FreeBSD set/get path | Best candidate. The old [09_ipv6_stress.lua](../../probes/phase2_kernel_objects/09_ipv6_stress.lua) classified a non-throwing `pcall` as “ACCEPTED” without checking the syscall return. [396c_ipv6_verify.lua](../../probes/phase21_next_vectors/396c_ipv6_verify.lua) passed a malformed 4-byte header and got `-1`. Neither establishes a valid 56-byte round trip on 14.10. |
| `IP_OPTIONS` 40B | [74a capture](../../results/phase16_kwrite/74a_ipoptions_proper_20261025_200005.txt) | Set/get works, but FreeBSD stores options in an mbuf, not a 44-byte malloc object. The 44-byte getter output is a zeroed 4-byte prefix plus 40 caller bytes; 126-socket spray returned no pointers. |
| EVF 538 | [13.60 decompile](../../results/kernel_handlers/decompiled/sys_538.c) | Direct allocations are 0x20 and 0x58, rather than a 0x30 request. Other indirect allocations are not excluded. |
| namedobj 557 | [13.60 decompile](../../results/kernel_handlers/decompiled/sys_557.c) | Direct allocations are 0x20 and 0x18. The “48-byte name” proposal confuses user input length with kernel allocation size; the name allocation copies at most 0x20 bytes. |
| AIO queries 663/664/666/667 | [72d output-size capture](../../results/phase16_kwrite/72d_663_qword_output_20261025_192827.txt) | The working queries return status dwords, not raw R contents. |

The `69l` EVF/namedobj “objects per page” estimates do not establish an object's slab size or shared zone. Syscall 624 reads a current-process VM-map field at `+0x1c4`; its meaning and units are not established by the [handler review](../../results/kernel_handlers/analysis/sys_624.md). Each create/submit also causes more than one allocation and may change userland VM state.

## 14.10 checks and outcome

[Probe 76a](../../probes/phase16_kwrite/76a_ipv6_rthdr_64b_roundtrip.lua) uses the known raw syscall ABI, an IPv4 `IP_OPTIONS` control, and valid 24/40/56-byte type-0 routing headers. It checks the actual return values and getter lengths. [Probe 76b](../../probes/phase16_kwrite/76b_ipv6_rthdr_pattern_readback.lua) tests all 56 patterned bytes and the buffer boundary. [Probe 76c](../../probes/phase16_kwrite/76c_ipv6_rthdr_volume.lua) keeps 64 headers on 64 sockets and verifies each pattern. All three passed Lua syntax parsing and perform no AIO race.

The first 76a attempt and a separate loader health run returned no bytes and timed out ([76a timeout](../../results/phase16_kwrite/76a_ipv6_rthdr_64b_roundtrip_20261025_212543.json), [health timeout](../../results/phase17_new_vectors/80w_loader_health_20261025_212603.json)). A later minimal ping succeeded, so 76a was rerun once. Its [successful capture](../../results/phase16_kwrite/76a_ipv6_rthdr_64b_roundtrip_20261025_212858.txt) records `set=0`, `get=0`, and matching lengths 24, 40 and 56. The [76b capture](../../results/phase16_kwrite/76b_ipv6_rthdr_pattern_readback_20261025_212943.txt) records `matching=56/56` with the 24-byte output sentinel tail untouched. The [76c capture](../../results/phase16_kwrite/76c_ipv6_rthdr_volume_20261025_213024.txt) records 64 retained sockets and 64/64 exact readbacks. These establish a working, repeatable 56-byte set/get spray from the game process. They do **not** expose a kernel pointer or identify the backing UMA zone.

## Decision points

1. Establish the 13.60 or 14.10 size-class table entry for requests of 48 and 56 bytes and the R / `M_IP6OPT` subzone indices. A bounded capture of the missing table and malloc-type metadata would settle the static bucket question.
2. If those match, test aliasing with distinct per-socket routing-header patterns and a bounded getter buffer. A positive cross-socket pattern or a later AIO overwrite would establish physical overlap. The old 65l result is **double success**, not proof that the allocator freed the same slot twice; a negative alias probe would be inconclusive. Normal get-after-set only returns caller bytes, so a kernel-pointer leak requires evidence that AIO writes into a still-referenced routing-header buffer.

**Conclusion:** A valid 56-byte `IPV6_RTHDR` is a confirmed 14.10 size-controlled spray with full readback. Its placement in the same 64-byte backing zone as AIO R remains **unconfirmed**.
