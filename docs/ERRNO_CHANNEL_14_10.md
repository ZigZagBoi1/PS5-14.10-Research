# The errno channel: the loader's return value is not rax, and what that invalidates

Boot of 2026-11-04, sixteenth/seventeenth, live console at 192.168.1.121:9026, firmware 14.10.
Everything below is measured on the console unless marked STATIC.

## 1. The measurement

Probe 1200d called ten syscalls whose failure mode is not in doubt and printed, for each, the
value the Lua loader returned and the string returned by the loader's own `get_error_string()`.

| call | returned value | get_error_string() | what a correct rax would be |
|---|---|---|---|
| open("/nonexistent") | 0 | 22 Invalid argument | -1 (EINVAL/ENOENT) |
| open("/no/such/path") | 0 | 2 No such file or directory | -1 (ENOENT) |
| close(9999) | 0 | 9 Bad file descriptor | -1 (EBADF) |
| fcntl(9999, F_GETFL) | 0 | 9 Bad file descriptor | -1 (EBADF) |
| read(9999, buf, 4) | 0 | 9 Bad file descriptor | -1 (EBADF) |
| ioctl(9999, TCGETS, buf) | 0 | 25 Inappropriate ioctl for device | -1 (EBADF) |
| fcntl(/dev/null fd, F_GETFL) | 2 | (stale 25) | 2, success |
| ioctl(619, ...) / ioctl(620, ...) | 0 | 78 Function not implemented | -1 (ENOSYS) |

Two facts follow directly.

**The returned value is 0 for every failure**, not -1 and not an errno. Every failure in the
table above returns 0 while `get_error_string()` carries the real code. Successes return their
real value: `fcntl(fd, F_GETFL)` returns 2 (O_RDWR), `open` returns the descriptor number 22/24/25.

**`get_error_string()` is a real error channel**, and it distinguishes ENOSYS (78) from EBADF
(9) from EPERM (1) from ENOTTY (25) from ESRCH (3). Nothing in this project used it as the
primary judgement before this boot.

## 2. What this invalidates

Every probe in the tree that decided "supported / not supported" from the numeric return value is
unfounded. In particular:

- **"rv == 0 means success"** was used throughout to read a syscall as accepted. It means the
  opposite: the call failed and set errno. The only way to tell a success apart from a failure is
  `get_error_string()` returning a fresh code (or the call's own written output).
- **"rv == -1 means unsupported"** is equally unfounded. -1 does appear in older captures (1165a,
  1076a, 598a), so the wrapper is not even self-consistent between builds of the payload host; the
  numeric value cannot be used as evidence at all.
- **open() failure returns 0, and 0 is stdin.** Probes that test `if fd < 0 then return end` then
  proceed with fd 0 and issue their ioctls/reads against the loader's own socket instead of the
  device they thought they had opened. 1200e measured `/dev/usbctl` failing with EACCES (13);
  every probe that "opened usbctl" before this boot was talking to fd 0.

No claim in this document depends on a numeric return value.

## 3. The devfs ioctl surface, re-measured with the working channel

1200a issued all 256 commands 0x00-0xFF on /dev/dmem0, /dev/gc, /dev/dce and /dev/hid, seventeen
times each, with the first dword of the argument buffer set to a different candidate constant
(0, 1, 2, 0x10, 0x100, 0x1000, 0x10000, 0x40000, 0x100000, 0x400000, 0x1000000, 0x10000000,
0x40000000, 0x80000000, 0xDEADBEEF, 0x13371337, 0xFFFFFFFF). For every command the returned value
was identical across all seventeen, and no byte of a 0x200-byte 0xA5A5A5A5 sentinel buffer was
ever modified. That is the 674-lesson test - the magic dword - and it finds nothing on these nodes.

1200e repeated the whole 0x00-0xFF space once per node and recorded `get_error_string()`:

| node | open | error over all 256 commands |
|---|---|---|
| /dev/null | fd 22 | 25 ENOTTY x256 |
| /dev/dmem0 | fd 22 | 25 ENOTTY x256 |
| /dev/gc | fd 22 | 25 ENOTTY x256 |
| /dev/dce | fd 22 | 25 ENOTTY x256 |
| /dev/hid | fd 22 | 25 ENOTTY x256 |
| /dev/ugen0.2 | fd 22 | 25 ENOTTY x256 |
| /dev/usbctl | open refused, 13 EACCES | - |

**/dev/null and /dev/dmem0 answer identically**, which is correct for /dev/null and impossible for
a node whose driver implements 256 commands - and 1200d shows that the call does not even resolve
the descriptor: ioctl(9999, TCGETS) answers ENOTTY (25), where a descriptor-taking call must answer
EBADF (9). syscall 54, as reached from this host, never consults the file table; it cannot be used
to reach a driver.

The neighbours were checked too (1202a), all with the same argument triple (fd, 0x5413, buf):

| syscall | fd = 9999 | fd = /dev/dmem0 | verdict |
|---|---|---|---|
| 615 | 1 EPERM | 1 EPERM | does not take a descriptor |
| 616 | 3 ESRCH | 3 ESRCH | does not take a descriptor |
| 617 | 3 ESRCH | 3 ESRCH | does not take a descriptor |
| 618 | 1 EPERM | 1 EPERM | does not take a descriptor |
| 619 | 78 ENOSYS | 78 ENOSYS | absent stub (matches the 9-byte static stub) |
| 620 | 78 ENOSYS | 78 ENOSYS | absent stub (matches the 9-byte static stub) |
| 614 | - | - | process died; no line printed |

## 4. What this means for the corpus

- The "19 live ioctl commands on /dev/ugen0.2 and 3 on /dev/usbctl" recorded by 288a, and the
  EPERM/ENXIO pairs in 1165a, were judgements about a constant. 1200e shows every command on
  /dev/ugen0.2 answers ENOTTY; the two non-ENOTTY codes in 1165a were stale errno left by the
  open() attempts, which is exactly the hazard 1165a's own header warned about, made invisible by
  the return value being useless.
- The devfs ioctl surface is therefore **not measured at all**, in either direction. No driver has
  ever been entered from userland through this path on 14.10. That is a reopening, not a closure:
  a new entry point has to be found before the device drivers can be attacked, and none of the
  6xx neighbours is it.
- The 2.9 million "ioctl calls" recorded in the devfs work measured a function that does not read
  its arguments.

## 5. The instrument this gives us

`get_error_string()` after each call, and a fresh connection per experiment, makes the whole
syscall space safe to map: a syscall that returns ENOSYS is an absent stub, a syscall that returns
EBADF took the descriptor, a syscall that returns EPERM is capability-gated rather than
unimplemented, and a syscall that returns EINVAL has the argument shape wrong. The first full map
produced this way is in `docs/SYSCALL_ERRNO_MAP_14_10.md`.
