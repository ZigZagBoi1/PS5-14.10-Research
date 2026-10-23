# netcontrol (99) on 14.10: the public use-after-free is a leak

## 2026-10-22 qualification

The later raw probes narrow several statements below. In 277g, PID 192 could
register a socket on ifindex 4; after closing that descriptor, CLEAR with the
dead descriptor and SET with a replacement both returned `-1`, while the peer
still returned `-1` rather than EOF. The three other tested ifindexes were
unavailable before the trigger. In contrast, 277e's final scan reported all
four indexes available after its close-before-unregister trials. The difference
is unresolved; permanent slot exhaustion across process exit or reboot is not
established. A nonblocking peer read of `-1` needs errno to distinguish its
specific state. The `soref`/`sorele` and patch explanations below are models,
not verified kernel-side facts. No kernel read/write or usable UAF has been
demonstrated from this behavior.

Evidence: `results/phase17_new_vectors/277e_netcontrol_definitive_leak_20261022_181828.txt`,
`results/phase17_new_vectors/277f_replacement_release_test_20261022_182059.txt`,
`results/phase17_new_vectors/277g_netcontrol_dead_clear_slot_test_20261022_200623.txt`.

Probes 218a-234a, 2026-10-21. Every value below is a measured return from the
console or a measured read from a socket peer; the captures are named per
section.

## Why this syscall

`99` is `netcontrol` (`docs/sysent-names-13.60.csv:101`, handler `0x265950`). It
is the syscall the only public PS5 kernel chain drives: Gezine's Poops
(`Gezine/Luac0re/payloads/poops_ps5.lua`, with `egycnq`), which descends from
TheFlow's `ExploitNetControlImpl` gist and is documented only up to 12.00. The
presence map had it as "present, `-1` on six zeros" and nothing more, so the
only public kernel bug on this platform had never been called with a real
argument on 14.10.

The public ABI, recovered from the gist rather than guessed:

```c
private int __sys_netcontrol(int ifindex, int cmd, Buffer buf, int size);
NET_CONTROL_NETEVENT_SET_QUEUE   = 0x20000003;
NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;
// ifindex = -1, buf = 8 bytes holding the fd as an int at +0
```

## The ABI is present and argument-checked (218a)

`probes/phase17_new_vectors/218a_netcontrol_abi.lua`,
`results/phase17_new_vectors/218a_netcontrol_abi_20261021_140851.txt`:

| call | return |
|---|---|
| `(0,0,0,0,0,0)` | `-1` |
| `(-1, SET_QUEUE, zeroed buf, 8)` | `-1` (fd 0 does not register) |
| register `fd 28` on `-1` | `0` |
| unregister `fd 28` on `-1` | `0` |
| register `fd 0xFFFF` / `fd 0` | `-1` |
| register with NULL buffer | `-1` |
| size `0`, `4` | `-1` |
| size `8`, `16`, `64` | `0` |

Of the sixteen commands `0x20000000`-`0x2000000F`, only `0x03` and `0x07` are
accepted. The handler reads one int at `buf[0]` and requires at least 8 bytes;
it does not trust a larger size. So the subsystem is compiled in, reachable
from a game process, and validating rather than ignoring its arguments.

## The queue is per interface, and `-1` is one shared queue (223a-225a)

Closing a registered descriptor is the public trigger. Done on `ifindex -1` it
makes every later netcontrol call return `-1`, in that process and the next
(`219a`, `221a`,
`results/phase17_new_vectors/219a_netcontrol_close_registered_20261021_141946.txt`,
`results/phase17_new_vectors/221a_netcontrol_stale_registration_20261021_142008.txt`).

`probes/phase17_new_vectors/224a_netcontrol_ifindex_scope.lua`
(`..._224a_netcontrol_ifindex_scope_20261021_143238.txt`) explains it: with the
wedge in place, index `-1` and `0` return `-1` while **index 1 returns `0`**.
The queue is keyed on the interface index, and `-1` - the index the public ABI
uses for "the process's own queue" - is a single shared object with a single
owner. `225a` then shows an ordinary index keeps working after the same
trigger: register `0`, close, unregister `-1`, and a fresh socket on that index
still registers `0`.

Capacity is not the limit: index 3 holds two registrations at once and clears
both (`226a`). Only `-1` is spent forever, and it is spent for the boot, for
every process, and only a power cycle clears it (`227a`, `228a`).

## It is a reference, not a dangling pointer (232a-234a)

This is the question that decides whether the public bug is alive. A slab
refill cannot answer it: after the orphan, 96 sockets, 32 `538` event flags, 32
`557` named objects and 8 kqueues changed nothing and nothing faulted
(`232a`).

Connection state can answer it. Take a connected `socketpair` (AF_UNIX,
SOCK_STREAM, syscall `135`), register one end, close it, and read the other end
with `MSG_DONTWAIT` (syscall `29`):

| sequence | peer read | meaning |
|---|---|---|
| close, no registration | `0` | EOF - the socket died with the descriptor |
| register, close | `-1` | still connected - the socket is **alive** |
| register, unregister, close | `0` | EOF - the reference was returned, then the close destroyed it |
| register, close, unregister the dead number | `-1` | still connected, and permanently |

`probes/phase17_new_vectors/233a_netcontrol_peer_state.lua`
(`results/phase17_new_vectors/233a_netcontrol_peer_state_20261021_144705.txt`)
and `probes/phase17_new_vectors/234a_netcontrol_ref_release.lua`
(`results/phase17_new_vectors/234a_netcontrol_ref_release_20261021_144722.txt`)
carry those four rows.

So registering a socket **holds a reference on it**, and unregistering returns
that reference. A descriptor closed while registered therefore does not free
the socket: the queue keeps it alive, the unregister can no longer resolve the
dead descriptor (`-1`), and the reference is never returned. What 219a
recorded is a descriptor lookup that refuses, not a freed object being walked.

## What this means for Poops

The public chain's precondition is *shape*, not *effect*: the sequence runs,
the free does not happen. On 14.10 the `-1` from the orphaned unregister is the
patch working - the queue no longer trusts a descriptor it cannot resolve, so
the socket stays referenced instead of being freed underneath it. There is no
double free to reclaim, which is also why refilling every slab changed nothing.

Consequences, stated as scope:

- Nothing about `99 netcontrol` is a memory-corruption primitive on 14.10.
- The trigger leaves a working socket leaked and the `ifindex -1` queue
  permanently unusable for the boot. That is a resource leak reachable from an
  unprivileged game process, and it survives the death of the process that
  caused it - the console only recovers on a power cycle.
- A use-after-free in this subsystem would need the reference to be dropped
  while a descriptor for the same file is still resolvable, i.e. a way to make
  the unregister succeed after the close. The three sequences above cover the
  reachable orderings: `dup`ped descriptors were not tried, and a `CLEAR_QUEUE`
  through a duplicate would return the reference exactly once, which is the
  balanced case, not a second free.
- This closes the only public kernel-bug lead that maps onto a 14.10 syscall.

## Reproducing

```
python tools/send_probe.py probes/phase17_new_vectors/233a_netcontrol_peer_state.lua \
    --ip <console> --timeout 25 --save
python tools/send_probe.py probes/phase17_new_vectors/234a_netcontrol_ref_release.lua \
    --ip <console> --timeout 25 --save
```

Both are non-destructive to the console. `219a` and `221a` spend the
`ifindex -1` queue until the next power cycle, so run those last.
