# aio on 14.10: the submit path is real, and delete refuses in-flight entries

Measured on firmware 14.10 (console 192.168.1.121, Lua loader on TCP 9026) with the
probes listed at the end. This note corrects the earlier reading that the aio family
is bookkeeping only: submission works, reads are queued on real descriptors, and the
kernel reports their progress through the same call that would free them.

## The sequence

`669(cmd = 0x1001, reqs, count, prio = 3, ids)` with `reqs` carrying `nbyte`,
`buf` and `fd` submits real reads on a socketpair:

```
submit 4 reads, then poll (664)
  states 1 1 1 1          (954a with two reads: 2 2)
delete one entry
  element status 0x80020010      in flight, not freed
write into the peer
  states move to 3 for the entries whose data arrived
delete again
  element status 0                freed
```

## What the states mean

| value | meaning | evidence |
|---|---|---|
| 1 | queued, not yet handed to a worker | 959a: four reads, all `1` after submit and after data |
| 2 | dispatched and waiting for data | 954a/956a: two reads show `2`; data moves one to `3` |
| 3 | completed | 954a: slot 0 after 16 bytes; 956a: both after 8 KB |
| 4 | cancelled | earlier cancel/poll runs (894a) |

Only a small number of entries are dispatched at once: two reads show `2`, four show
`1`, so the worker depth is not the count that was submitted. That also explains why
`943a`-era measurements disagreed between runs: the probe read the states at
different points of that dispatch.

## delete

`662(ids, count, errs)` succeeds only for entries that have completed. Anything in a
non-terminal state returns `0x80020010` in that element's slot, immediately and
without blocking - a child thread calling it returns in microseconds while the parent
is still sending (956a).

`955a` appeared to show a blocking delete because its parent used a blocking `write()`
of 32 KB into a peer whose reads had not all completed; the socket buffer filled and
the parent never returned. That is a loader-wedge bug in the probe, not kernel
behaviour. Every parent-side call in this family must use `sendto(..., MSG_DONTWAIT)`.

## The race that was tried and did not fire

The 14.20 note describes a generation check after a lock drop and re-acquisition in
`aio_multi_delete`, which is exactly the shape that would turn a reused slot into a
free of the wrong object. Three attempts to reach it on 14.10:

- `957a`: child deletes continuously while the parent completes reads and re-submits
  into the freed slots. 12 rounds: no element was freed twice, every fresh object was
  allocated and answered normally.
- `958a`: the parent polls and deletes each id the moment its state reaches 3, with a
  child hammering the same ids. 20 rounds: `freed_total=0`, because the entries never
  reached state 3 in that shape (`sendto` delivered 8192 of the 16384 bytes the read
  set wanted).
- `959a`: the state map with no child and no delete until the end, which is what
  established the dispatch depth above.

None of this proves the window is unreachable, only that the shapes tried do not
enter it: with the descriptors completing from the same process that submits them,
the delete always runs either before completion or after the entry is gone.

## Probes and captures

| probe | capture |
|---|---|
| `probes/phase17_new_vectors/954a_aio_inflight_oracle.lua` | `results/phase17_new_vectors/954a_aio_inflight_oracle_20261030_104037.txt` |
| `955a_aio_inflight_delete_race.lua` | `955a_..._20261030_104154.txt` (wedge) |
| `956a_aio_lock_probe.lua` | `956a_..._20261030_105108.txt` |
| `957a_aio_slot_reuse_race.lua` | `957a_..._20261030_105153.txt` |
| `958a_aio_double_delete_hunt.lua` | `958a_..._20261030_105341.txt` |
| `959a_aio_state_map.lua` | `959a_..._20261030_105401.txt` |
