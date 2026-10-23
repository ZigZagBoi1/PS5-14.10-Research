# IPv6 Multicast Filter — Correction for the Assigned Researcher

**Date:** 2026-10-23  
**Priority:** BLOCKING — the 50e result cannot close or advance this lane until corrected

## The Problem

The `50e` probe run (`results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261023_071112.txt`) used `msfr_ifindex=0` in the `IPV6_MSFILTER` setsockopt request.

FreeBSD's `in6p_set_source_filters()` in [`sys/netinet6/in6_mcast.c`](https://cgit.freebsd.org/src/tree/sys/netinet6/in6_mcast.c?id=dd2f74a820b70879d48d39e9c6b00ad7ed9a0e5a) explicitly rejects interface index zero:

```c
ifp = ifnet_byindex(msfr.msfr_ifindex);
if (ifp == NULL)
    return (EADDRNOTAVAIL);
```

`ifnet_byindex(0)` returns NULL, so the handler returns `EADDRNOTAVAIL` **before** it ever checks group membership or reaches the vulnerable filter-manipulation code path described in FreeBSD-SA-26:29.

## What This Means

- The `-1` results from `50e` do **not** establish that Sony lacks the IPV6_MSFILTER handler.
- The `-1` results do **not** establish that the FreeBSD-SA-26:29 vulnerability is unreachable.
- The run was rejected at the interface-lookup stage, not at the group-membership or filter stage.
- **This lane remains open** — it needs a correctly formed request before it can be closed.

## What Needs to Change

1. **Get the actual joined interface index.** After `IPV6_JOIN_GROUP` succeeds, the kernel binds the membership to an interface. Retrieve the index via:
   - The `ipv6mr_interface` field used in the join call, OR
   - `sysctl net.inet6.ip6.mif6table` or `getifaddrs()` equivalent, OR
   - Enumerate interfaces with `SIOCGIFINDEX` ioctl on an IPv6-capable interface

2. **Verify the full request layout.** The `struct __msfilterreq` must have:
   ```c
   struct __msfilterreq {
       uint32_t  msfr_ifindex;    // actual joined interface index (NOT 0)
       uint32_t  msfr_fmode;      // MCAST_INCLUDE (1) or MCAST_EXCLUDE (2)
       uint32_t  msfr_nsrcs;      // number of sources (can be 0 for initial test)
       uint32_t  __msfr_align;    // padding
       struct sockaddr_storage msfr_group;  // the joined multicast group address
       struct sockaddr_storage *msfr_srcs;  // pointer to source list (can be NULL if nsrcs=0)
   };
   ```

3. **Run with a valid interface index and compare:**
   - Positive test: correct interface index + correct group → should either succeed or fail with a group/filter error (NOT EADDRNOTAVAIL)
   - Negative control: correct interface index + wrong group → should fail differently
   - If both return the same `-1`, check errno to distinguish the rejection reason

4. **Only then** can you determine whether the filter manipulation code is reachable on 14.10.

## Stop Condition

If a correctly formed request with the real joined interface index and verified group address still returns `-1` with an error that indicates the handler/option is absent (ENOPROTOOPT) or the group check fails despite a valid join, **then** this lane can be closed.

## References

- FreeBSD-SA-26:29.ip6_multicast: https://lists.freebsd.org/archives/freebsd-security/2026-June/000486.html
- FreeBSD handler source: https://cgit.freebsd.org/src/tree/sys/netinet6/in6_mcast.c?id=dd2f74a820b70879d48d39e9c6b00ad7ed9a0e5a
- Local probe: `probes/phase11_network_attacks/50e_ipv6_msfilter_reach.lua`
- Local result: `results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261023_071112.txt`
- Research memo: `docs/research/PATH_OPTIONS_2026-10-23.md` (Lane 1)
