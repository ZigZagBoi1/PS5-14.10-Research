# IPv6 ancillary data on 14.10 — validated, and the headers are refused

Status: measured (50l, 50m, 50n). This closes the pktopts/ancillary line that
`docs/UNTESTED_THEORIES.md` lists as untested, and records a harness defect that
made four earlier probes meaningless.

## The harness defect first

`50f`, `50g`, `50h` and `50k` built cmsghdrs with 64-bit fields: `cmsg_len` as a
qword at +0, `cmsg_level` at +8, `cmsg_type` at +12. FreeBSD's cmsghdr is

```c
struct cmsghdr {
	socklen_t cmsg_len;   /* +0, 4 bytes */
	int       cmsg_level; /* +4 */
	int       cmsg_type;  /* +8 */
};                        /* data at +16 */
```

with the data at `CMSG_DATA` = +16, which is what `108a`'s working SCM_RIGHTS
transfer uses. With the wrong layout every IPv6 cmsg had level 0 and the kernel's
`if (cm->cmsg_level != IPPROTO_IPV6) continue;` skipped all of them. Those four
probes recorded "every shape is accepted", which described nothing at all. The
lesson is the same one 928a taught about gadget matches: a wrong binary layout
produces a plausible result, never an error.

A second defect in the same probes: the three "plain" sends in 50h passed a
non-NULL `msg_control` with `msg_controllen = 0`, and this kernel returns EINVAL
for that pair (50i). The baseline was wrong, not the traffic.

## What the parser actually does

With the layout fixed (50l), the kernel behaves like stock FreeBSD 9
`ip6_setpktopts()`: walk the control buffer, reject `cmsg_len == 0` or larger
than the remaining length, skip foreign levels, and validate each option.

| shape | expected | measured |
|---|---|---|
| PKTINFO, 20 bytes, ifindex 0 | send | 4 |
| PKTINFO, 4 or 24 bytes | EINVAL | -1 |
| PKTINFO, ifindex 0x7FFFFFFF | ENXIO | -1 |
| HOPLIMIT, 4 bytes = 300 | EINVAL | -1 |
| HOPLIMIT, 2 bytes | EINVAL | -1 |
| HOPLIMIT, 4 bytes = 5 | send | 4 |
| TCLASS, 4 bytes = 300 | EINVAL | -1 |
| TCLASS, 4 bytes = 8 | send | 4 |
| NEXTHOP, 8 bytes | EINVAL | -1 |
| unknown type 0 or 0x7F | EINVAL | -1 |
| `cmsg_len = 15` (below the header) | EINVAL | -1 |
| foreign level 0xFFFF | skipped | 4 |
| `cmsg_len = 0x1000` with 40 bytes | EINVAL | -1 |

So the length and range checks are present, including the one that would have
underflowed if a sub-header `cmsg_len` had been accepted.

## Extension headers are refused even when valid

Every hop-by-hop, destination-option and routing-header cmsg fails in both its
valid and its inconsistent shape:

```
RTHDR  len 8  ip6r_len 0   segleft 0   -> -1
RTHDR  len 24 ip6r_len 2   segleft 1   -> -1
HOPOPTS len 8  hdrlen 0                -> -1
HOPOPTS len 24 hdrlen 2                -> -1
DSTOPTS len 8  hdrlen 255              -> -1
```

That is the shape of a `priv_check(PRIV_NETINET_SETHDROPTS)` refusal: the
options are legal, so a length check is not what rejects them. This process does
not hold the privilege, so the whole class — including the historically buggy
`ip6_rthdr0()` length handling — cannot be reached from it.

The RFC 2292 aliases do not open a side door (50m): as cmsgs, 22/23/24 fail like
their RFC 3542 counterparts; as sticky socket options, `setsockopt(24, 4 bytes)`
and `setsockopt(19, 4 bytes)` return 0 but store nothing — `getsockopt(25)`
reports an empty option list and the following sends are ordinary datagrams
(50n). A 4-byte routing header with `ip6r_len = 255` never reaches the packet.

## Consequence

The control-message path cannot be used to hand the kernel a length it trusts:
the only options that accept user data are fixed-size values, and everything that
carries an attacker-sized header is behind a privilege this process lacks.
`IPV6_MSFILTER` is a **separate** option that works when the request has the amd64
`sockaddr_storage` alignment: `50f` records successful INCLUDE/EXCLUDE requests
with the 152-byte `__msfilterreq`, while the earlier uniform rejections came from
a 148-byte misaligned struct. The cmsg findings above say nothing about it. The line is closed unless the
process can obtain PRIV_NETINET_SETHDROPTS, which no measured path provides.
