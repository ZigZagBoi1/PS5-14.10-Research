# The descriptor table is readable on 14.10 — and holds no privileged channel

**Date:** 2026-11-03
**Probes:** `probes/phase17_new_vectors/975c_fcntl_fd_map.lua`,
`975d_fd_identify.lua`, `975e_fd_peername.lua`, `976a_ioctl_real_fds.lua`
**Captures:** `results/phase17_new_vectors/975c_*_20261103_112621.txt`,
`975d_*_20261103_112700.txt`, `975e_*_20261103_112723.txt`,
`976a_*_20261103_112812.txt`

## Why this was never visible

`fstat(189)` kills the process on 14.10 and `dup(41)` returns `-1`, so every earlier
survey treated the descriptor table as opaque. It is not: `fcntl(92)` with
`F_GETFL` (3) validates a descriptor without reading, writing, or closing it, and
returns its status flags. `getsockname(32)` and `getpeername(31)` are equally safe.

## The table (loader process, pid 217)

```
fd 0        fl=0x0   non-socket, no ioctl          (stdin)
fd 1..3     fl=0x1   non-socket, no ioctl          (stdout, stderr, one more)
fd 4..13    fl=0x2   non-socket, no ioctl
fd 10       fl=0x2   ioctl -> EINVAL (22) for every request
fd 14       fl=0x0   ioctl -> 0x803B0004 (Sony error) for every request
fd 15..17   fl=0x2   non-socket, no ioctl
fd 18,19    fl=0x0/0x1  FIONBIO/FIOASYNC -> 0   (pipes or socketpairs)
fd 20,21    AF_INET  local 192.168.1.121:9026, peer 192.168.1.185:52970
                     (the loader's listener and the accepted TCP connection)
fd 22..33   AF_UNIX  sa_len=16, sa_family=1, sun_path empty (unnamed socketpairs)
```

Two error codes single out descriptors: `fd 10` answers `EINVAL` to every ioctl, and
`fd 14` answers the Sony status `0x803B0004`. The same two are the only entries
`669` (aio submit) rejects — `fd 10` with `22`, `fd 14` with `0x803B0004` — so both
paths agree these are special objects, not files.

## The descriptor table is not a privilege channel

There is no connected socket to a Sony service. The AF_UNIX entries are *unnamed
socketpairs*, which cannot be reached by path and are created inside the process; the
only network socket is the loader's own listener. The non-socket entries refuse every
ioctl we can construct:

| request | result on fd 0-9, 11-13, 15-17 |
|---|---|
| `FIONBIO` `0x8004667E` | `-1` |
| `TIOCGWINSZ` `0x40487413` | `-1` |
| `TIOCGETA` `0x4004746A` | `-1` |
| `FIONREAD` `0x20006415` | `-1` |
| `FIOASYNC` `0x4004667F` | `-1` |

`FIONBIO` returning `-1` on a socketpair we created ourselves is the notable one: the
descriptor table the loader sees is not the raw kernel table for socket objects.

## What this changes

Nothing about the kernel boundary. It removes one "we cannot see it" claim and adds a
safe way to ask whether a descriptor exists, what its access mode is, and whether it is
a socket — useful for future work, but on this process the answer is that every device
descriptor refuses ioctl and every socket is either ours or an unnamed pair.

## Follow-ups, and what the entries actually are

`read(3)` on `fd 18` returns the loader's own source text (`WRITABLE_PATH`,
`LOG_FILE = WRITABLE_PATH .. "loader_log.txt"`, the `print` wrapper, the
`syscall.resolve{...}` table with `thr_self = 0x1b0`, `dlsym = 0x24f`,
`dynlib_load_prx = 0x252`). So `fd 18` is the Lua file the loader read to start
itself, not a service channel. `fd 14` answers `0` to `read()` with an empty buffer,
`fd 10` answers `-1`, and `mmap` on either returns `-1` with both `0x1002` and
`0x1001` flags.

`/dev/random` is the only new node that opened and produced data; `/dev/klog`,
`/dev/console`, `/dev/tty`, `/dev/mem` and `/dev/kmem` all failed to open, and the
sweep then wedged the single-threaded loader on a blocking open or read (likely
`/dev/stdin`), which is why `978a` ends at `IDLE_TIMEOUT`.

The conclusion is unchanged and now has a cause: every descriptor in this table is
the loader's own bookkeeping plus unnamed socketpairs, none of it belongs to a
daemon, and the jail exposes no kernel log or memory device.
