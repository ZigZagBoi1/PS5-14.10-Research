# IPv4 multicast and the source-filter surface on 14.10

Measured 2026-11-09. Everything below is a console measurement unless marked `[S]`
(read from the 13.60 dump) or `[I]` (inference). Captures are in
`results/phase36_realargs/`.

## Why this was worth a probe

`docs/DEAD_ENDS.md` recorded the whole RFC 3678 source-filter API as removed on
14.10, citing 50e2/50e3: `IPV6_MSFILTER(74)`, `MCAST_MSFILTER(72)`,
`MCAST_JOIN_GROUP(42)` and `MCAST_BLOCK_SOURCE(43)` all returned `-1`. Those
probes passed **one fixed 148-byte struct to every option**. 50f later showed
that `IPV6_MSFILTER` works with the correctly aligned 152-byte `__msfilterreq`,
and 1427a made the reply readable. The lesson generalises: an option answering
`-1` to a struct of the wrong shape is not evidence that the option is absent.

Nothing had ever retested the **IPv4** side with correct structs.

## The v4 surface is live

`1434a` — `struct ip_mreq` is `{ in_addr imr_multiaddr; in_addr imr_interface; }`.
The second field is an interface **address**, not an index. Passing `1` (an
index) is `EADDRNOTAVAIL(49)`; passing `0` (INADDR_ANY) or `127.0.0.1` joins.

```
join 224.0.0.1 if_addr=0x00000000 -> rv=0
join 224.0.0.1 if_addr=0x0100007F -> rv=0   (127.0.0.1)
join 224.0.0.1 if_addr=0x00000001 -> rv=-1  EADDRNOTAVAIL(49)
join 224.0.0.1 again              -> rv=-1  EADDRINUSE(48)
drop 224.0.0.1                    -> rv=0
```

The option sweep at `IPPROTO_IP` over 0..90 with a zeroed 264-byte buffer also
finds `IP_BINDANY(24)` answering `EPERM(1)` — the privilege gate on that option
is intact — and `IP_OPTIONS(1)` answering `EMSGSIZE(40)`.

## IP_MSFILTER on v4 needs ifindex 3

`__msfilterreq` (152 bytes) has `msfr_ifindex` at `+0`, `msfr_fmode` at `+4`,
`msfr_nsrcs` at `+8`, the group `sockaddr_storage` at `+16` and `msfr_srcs` at
`+144`. Source entries are **128 bytes** each, `struct sockaddr_in` at the front
(`sin_len 16` at `+0`, `sin_family 2` at `+1`, address at `+4`).

`1435a` sweeps the index on a joined group. The v6 socket accepts `1`; the v4
group created through INADDR_ANY resolves to **index 3**:

```
ix=0 set=-1 (49)  get=-1 (22)
ix=1 set=-1 (49)  get=-1 (49)
ix=2 set=-1 (49)  get=-1 (49)
ix=3 set=0        get=0        <-- the joined interface
ix=4 set=-1 (49)  get=-1 (49)
ix=5..8 set=-1    get=-1 (22)
```

Note `get` and `set` disagree about *why* a wrong index fails (`EINVAL` vs
`EADDRNOTAVAIL`), so the two directions take different paths to the same lookup.

With the right index the round trip works and the reply length is exact:

| sources set | `numsrc` returned | dwords written | first dword |
|---|---|---|---|
| 1 | 1 | 32 | `0x00000210` |
| 2 | 2 | 64 | `0x00000210` |
| 8 | 8 | 256 | `0x00000210` |
| 128 | 128 | 4096 | `0x00000210` |

`0x00000210` is `sin_len 16, AF_INET` little-endian, i.e. the kernel writes real
`sockaddr_in` headers. The reply is `min(claim,128) * 0x80` bytes and nothing
beyond it — the same clamp the v6 side has.

## The reply tail is a kernel zero-fill

`1435a` [C]: arm a 1-source filter, then read back with `claim=128` into a page
prefilled with `0xA5A5A5A5`. All 4096 dwords change and only **2** of them are
non-zero (the header dword and the address dword of entry 0). So the 16 KiB the
kernel writes is mostly zeros *that the kernel produced*, not our pattern left
in place and not heap residue.

This matches what 1432a established on the v6 side by churning the 16 KiB
allocation size class with tagged blocks and finding zero sibling headers.

`MsfilterAudit` (reviewer) adds the caveat that matters for reading any of this
work: a `changed == scan_size` result is also the signature of a **failed
pattern fill**, so a run has to carry a fill self-check or an internal control
row (`claim=0` → `changed=0`) before a count means anything. 1428a carries one;
the first run of 1428a did not and its numbers are void.

## The v4 set path validates before it swaps

`1439a` sets a deliberately wrong list and then reads the group back, so the
observable is the group's state *after a rejected request*:

| shape | set result | group after |
|---|---|---|
| 2 good sources | `0` | `numsrc=2`, tags intact |
| 1 source, family 28 | `EAFNOSUPPORT(47)` | `numsrc=2`, unchanged |
| 1 source, family 0 | `EAFNOSUPPORT(47)` | `numsrc=2` |
| 1 source, family 255 | `EAFNOSUPPORT(47)` | `numsrc=2` |
| 1 source, `sin_len 0` | `EINVAL(22)` | `numsrc=2` |
| 1 source, `sin_len 128` | `EINVAL(22)` | `numsrc=2` |
| 1 source, `sin_len 17` | `EINVAL(22)` | `numsrc=2` |
| 64 good + 64 bad | `EAFNOSUPPORT(47)` | `numsrc=2` |
| 64 bad + 64 good | `EAFNOSUPPORT(47)` | `numsrc=2` |
| 1 good, byte at `+24` = 0xAA | `0` | `numsrc=1` (the byte is ignored) |

A rejected request never installs a partial list, and the previously armed list
survives it — 1439a [D] re-reads tag `0x21` from the good 2-source set after the
following set failed. That is the "allocate / copy / validate / swap" ordering
the v6 fix introduced, not a free-then-fail ordering.

## v4 and v6 share one handler

`[S]` In the 13.60 text there is exactly **one** caller of the wrapper that
`bzero`s a 0x98 stack block and tail-jumps to `copyin`
(`0xffffffff8ac19280`): the call at `0xffffffff8b2c0a5f`, inside the function at
`0xffffffff8b2c0940` that `docs/PRIVATE_IPV6_MSFILTER_1360_STATIC_2026-10-22.md`
identifies as the source-filter handler. Only one option path copies a
`__msfilterreq`, so there is no hidden v4 twin carrying an unfixed copy-after-lock
ordering. A search for any other 0x98 copyin site in the whole text returns
nothing.

## What this does not give

- No write to a caller-chosen address. `msfr_srcs` is the destination and the
  copyout predicate validates it; `claim` and `nsrcs` only size a copy that is
  clamped to 128 entries.
- No kernel pointer. Every dword the kernel writes is either a `sockaddr_in`
  header, an address we supplied, or zero.
- No unchecked index: the interface index is looked up (`EADDRNOTAVAIL`), and a
  v6+family source entry on a v4 socket is rejected by family, not by index.
- The CVE-2026-49412 race remains unproven *and* unreachable by ordering; see
  `docs/DEAD_ENDS.md`.

## Captures

| probe | capture | what it establishes |
|---|---|---|
| 1434a | `results/phase36_realargs/1434a_ip_mcast_surface_20261109_164244.txt` | v4 join works; `ip_mreq` takes an address; option sweep 0..90 |
| 1435a | `results/phase36_realargs/1435a_ip_msfilter_ifindex_20261109_164339.txt` | ifindex 3; round trip; clamp; zero-fill tail |
| 1436a | `results/phase36_realargs/1436a_mmap_dmem_phys_sweep_20261109_164617.txt` | 628 index/physical/flag sweep |
| 1437a | `results/phase36_realargs/1437a_mmap_dmem_descriptor_20261109_164725.txt` | 628 unaffected by open/mmap |
| 1438a | `results/phase36_realargs/1438a_dmem_marker_persistence_20261109_164756.txt` | dmem writes do not outlive the process |
| 1439a | `results/phase36_realargs/1439a_ip_msfilter_bad_entry_20261109_164928.txt` | validate-before-swap on rejected lists |
