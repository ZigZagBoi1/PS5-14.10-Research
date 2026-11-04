# /dev on 14.10: the enumerated namespace

Every device probe in this repository before 2026-11-04 named its targets by hand. 1038a
guessed eight nodes, 376a/380a guessed `gc`/`dce`, and the 32 MiB ioctl sweeps guessed a
command range. Nothing had asked the kernel what exists. This note records the answer, and the
nodes the answer exposes that no probe has touched.

Probe: `probes/phase17_new_vectors/1070a_devfs_enum.lua`
Capture: `results/phase17_new_vectors/1070a_devfs_enum_20261104_095131.txt`

## Method

```
open("/dev", O_RDONLY)            -> fd 22
getdirentries(196)(fd, buf, 0x2000, &base)
```

One call returns the whole namespace: `rv = 1360`, `base = 1360`, and the next call returns
`rv = 0`. `getdirentries` is syscall 196 (`handler_rva 0x265a58` in
`docs/sysent-names-13.60.csv`), absent from the Lua resolver but reachable through
`make_syscall(196)` like every other number in this work.

## Record layout

The variable-length FreeBSD layout, **not** the older fixed `d_name[256]` form:

| offset | field |
|---|---|
| +0x00 | `d_fileno` (u32) |
| +0x04 | `d_reclen` (u16) |
| +0x06 | `d_type` (u8) |
| +0x07 | `d_namlen` (u8) |
| +0x08 | `d_name` (`d_namlen` bytes, then padding to `d_reclen`) |

Two things worth knowing before parsing one:

- **Do not assume a stride.** devfs returns 4-byte-aligned records (`.` -> 12, `..` -> 12,
  `system_tmp` -> 20), while the `/app0` PFS returns a fixed 24-byte record for every name
  including `movie`. Follow `d_reclen` and nothing else.
- **Byte extraction must not go through qwords.** Eight ASCII bytes exceed 2^53, so
  `tonumber(memory.read_qword(p))` rounds and the low bytes are lost: the first run of this
  probe printed `xstem_tmp` for `system_tmp` and `tAXezOVQyq` for `/`'s per-boot temp
  directory. Reading 32-bit words and shifting is exact.

## The listing

78 entries, one `getdirentries` call, in return order:

| # | name | ino | type | | # | name | ino | type |
|---|---|---|---|---|---|---|---|---|
| 1 | `.` | 2 | 4 | | 40 | `hmd_cmd` | 72 | 2 |
| 2 | `..` | 2 | 4 | | 41 | `hmd_snsr` | 73 | 2 |
| 3 | `random` | 4 | 2 | | 42 | `hmd_3da` | 74 | 2 |
| 4 | `urandom` | 5 | 10 | | 43 | `hmd_dist` | 75 | 2 |
| 5 | `dipsw` | 6 | 2 | | 44 | `sce_zlib` | 82 | 2 |
| 6 | `fd` | 334 | 4 | | 45 | `bt` | 89 | 2 |
| 7 | `stdin` | 10 | 10 | | 46 | `hid` | 90 | 2 |
| 8 | `stdout` | 12 | 10 | | 47 | `mp3` | 93 | 2 |
| 9 | `stderr` | 14 | 10 | | 48 | `dmem0` | 99 | 2 |
| 10 | `deci_stdout` | 18 | 2 | | 49 | `dmem1` | 100 | 2 |
| 11 | `deci_stderr` | 19 | 2 | | 50 | `dmem2` | 101 | 2 |
| 12 | `deci_tty2` | 20 | 2 | | 51 | `gc` | 108 | 2 |
| 13 | `deci_tty3` | 21 | 2 | | 52 | `ajmi` | 111 | 2 |
| 14 | `deci_tty4` | 22 | 2 | | 53 | `ajm` | 112 | 2 |
| 15 | `deci_tty5` | 23 | 2 | | 54 | `dce` | 116 | 2 |
| 16 | `deci_tty6` | 24 | 2 | | 55 | `rng` | 117 | 2 |
| 17 | `deci_tty7` | 25 | 2 | | 56 | `dbggc` | 121 | 2 |
| 18 | `deci_tty8` | 26 | 2 | | 57 | `sbl_srv` | 123 | 2 |
| 19 | `deci_tty9` | 27 | 2 | | 58 | `encdec` | 124 | 2 |
| 20 | `deci_tty10` | 28 | 2 | | 59 | `uvd_dec` | 129 | 2 |
| 21 | `deci_tty11` | 29 | 2 | | 60 | `uvd_enc` | 130 | 2 |
| 22 | `deci_tty12` | 30 | 2 | | 61 | `fttrm` | 134 | 2 |
| 23 | `deci_tty13` | 31 | 2 | | 62 | `duid` | 139 | 2 |
| 24 | `deci_tty14` | 32 | 2 | | 63 | `acm` | 141 | 2 |
| 25 | `deci_ttya0` | 33 | 2 | | 64 | `gic` | 143 | 2 |
| 26 | `deci_ttyb0` | 34 | 2 | | 65 | `notification0` | 144 | 2 |
| 27 | `deci_ttyc0` | 35 | 2 | | 66 | `notification1` | 145 | 2 |
| 28 | `null` | 40 | 2 | | 67 | `notification6` | 150 | 2 |
| 29 | `zero` | 41 | 2 | | 68 | `notification7` | 151 | 2 |
| 30 | `deci_stdin` | 42 | 2 | | 69 | `usbctl` | 159 | 2 |
| 31 | `hmd2_cmd` | 58 | 2 | | 70 | `camera` | 161 | 2 |
| 32 | `hmd2_imu` | 59 | 2 | | 71 | `a53mm` | 198 | 2 |
| 33 | `hmd2_track` | 63 | 2 | | 72 | `a53mmsys` | 199 | 2 |
| 34 | `hmd2_leddet` | 64 | 2 | | 73 | `usb` | 339 | 4 |
| 35 | `hmd2_image` | 65 | 2 | | 74 | `ugen0.1` | 205 | 10 |
| 36 | `hmd2_gen_data` | 66 | 2 | | 75 | `ugen1.1` | 226 | 10 |
| 37 | `hmd2_slam_trace` | 67 | 2 | | 76 | `ugen0.2` | 229 | 10 |
| 38 | `hmd2_gaze` | 68 | 2 | | 77 | `ugen2.1` | 244 | 10 |
| 39 | `ctty` | 69 | 2 | | 78 | `lvd3` | 340 | 2 |

`d_type` is the FreeBSD value: 2 = `DT_CHR`, 4 = `DT_DIR`, 10 = `DT_LNK`.

The root `/` (same probe) returns eight entries: `.`, `..`, `system_tmp`, `dev`, a per-boot
random name, `app0`, `savedata0`, `av_contents`. `/system`, `/user`, `/mnt` and `/data` do not
open; `/app0` returns `movie`, `sce_module`, `eboot.bin`, `root.pfs`, `root.pfs.000`,
`sce_discmap.plt`.

## What this settles and what it opens

- **No `mem`, `kmem`, `physmem`, `msr`, `cpuctl`, `pci` node is listed.** This is not proof of
  absence — devfs can hide a node from `readdir` while leaving name lookup intact — so
  `probes/phase17_new_vectors/1073a_hidden_node_open.lua` tests those names by `open()` alone.
- **The nodes every probe had been guessing at are listed normally.** `gc`, `dce`, `ajm`,
  `ajmi`, `gic`, `usbctl`, `notification0/1`, `camera` and `rng` all appear at positions
  47-69; an earlier 40-entry walk cap was what made them look absent. There is no hide rule to
  explain away.
- **Sixteen nodes had never been opened by any probe in this repository**, because no probe
  knew the names. `probes/phase17_new_vectors/1071a_devfs_full_read.lua` has since opened and
  read all of them (results below): `mp3`, `dmem1`, `dmem2`, `dbggc`, `sbl_srv`, `encdec`, `uvd_dec`, `uvd_enc`,
  `fttrm`, `duid`, `acm`, `notification6`, `notification7`, `a53mm`, `a53mmsys`, `lvd3`.
  `dmem1`/`dmem2` matter because the `dmem0` verdict in the dead-end list
  ("opens but all operations fail — GPU partition only") was never tested against its two
  siblings, and `a53mm`/`a53mmsys` name the southbridge A53's memory interface.
- **`read()` on a tty node blocks even with `O_NONBLOCK`.** `/dev/deci_stdin` accepted the
  flags, returned an fd, and then parked the loader's only Lua thread inside `read()` for the
  rest of the connection (`LOADER-STUCK accepted, no reply`). Any future device sweep must
  either exclude the tty group or issue those reads from a `thr_create` child.

## read() over the enumerated nodes

`probes/phase17_new_vectors/1071a_devfs_full_read.lua` reads 0x400 bytes from each node with
`O_RDONLY|O_NONBLOCK`, into a buffer pre-filled with the sentinel `0xCDCDCDCD`, then scans every
qword for a supervisor-range value. The tty group is excluded (see the blocking note above).

**Only three nodes returned bytes.** Of the 37 nodes attempted, 13 refused `open()`, 18 returned
`-1` from `read()`, and 3 returned 0 (`bt`, `hid`, `null`). The scan therefore examined 3 × 1024
bytes of kernel-generated PRNG and zero fill, not 37 nodes.

| result | nodes |
|---|---|
| `open()` failed | `a53mm`, `a53mmsys`, `dbggc`, `sbl_srv`, `encdec`, `fttrm`, `duid`, `mp3`, `acm`, `lvd3`, `hmd2_image`, `hmd2_slam_trace` |
| `read()` = -1 | `dmem0`, `dmem1`, `dmem2`, `uvd_enc`, `rng`, `camera`, `sce_zlib`, `dipsw`, `hmd_cmd`, `hmd_snsr`, `hmd_3da`, `hmd_dist`, `hmd2_cmd`, `hmd2_imu`, `hmd2_leddet`, `hmd2_gen_data`, `hmd2_gaze`, `hmd2_track` |
| `read()` = 0 | `bt`, `hid`, `null` |
| 1024 bytes, no supervisor value | `zero`, `random`, `urandom` |

**No kernel-range qword appeared in the bytes that were actually returned** — three nodes' worth,
not thirty-seven. `dmem1` and `dmem2` behave exactly like `dmem0`,
so the "GPU partition only" verdict in the dead-end list is a property of the `dmem` class, not
of `dmem0` specifically.

Caveat: this loader normalises every failed syscall to `-1`, so an `open()` that returns `-1`
cannot be distinguished from `EACCES`, `ENOENT` or `ENODEV` at the wire. The twelve nodes above
are listed by `getdirentries` and still refuse to open, which is a permission outcome on
present nodes rather than evidence that the name is unknown — the same shape as the credential
bit-62 gate on syscall 622.

## Hidden names: none

`probes/phase17_new_vectors/1073a_hidden_node_open.lua` opens the names FreeBSD would give a
raw memory, MSR or bus interface directly, without consulting `getdirentries` at all, in case
devfs hides a node from `readdir` while keeping lookup. **13 of 55 names open**, and every one of
the 13 is already in the 78-entry listing:

`dmem0`, `null`, `zero`, `gc`, `dce`, `ajm`, `ajmi`, `gic`, `usbctl`, `usb`, `notification0`,
`camera`, `sce_zlib`.

Refused: `mem`, `kmem`, `physmem`, `memctl`, `msr`, `cpuctl`, `pci`, `pcib0`, `smb0`, `iic0`,
`spi0`, `gpio`, `bpf`, `audit`, `kaudit`, `klog`, `console`, `ctty`, `ttyv0`, `ttyu0`, `uart`,
`ada0`, `da0`, `cd0`, `nvme0`, `nvme0ns1`, `mmcsd0`, `md0`, `tap0`, `tun0`, `dmass`, `sceKernel`,
`scevfs`, `scezlib`, `notification1`, and the rest.

What this does **not** prove on its own: `open() = -1` is not a membership test. The capture
carries its own counterexample — `notification1` (ino 145) and `ctty` (ino 69) are in the
78-entry listing and also print `-`, while `notification0` opens. A present-but-gated node and an
absent name are indistinguishable through this syscall, because the loader normalises every
failure to `-1`.

What makes the negative stand is the **combination**: `mem`, `kmem`, `physmem`, `memctl`, `msr`,
`cpuctl`, `pci`, `pcib0`, `bpf`, `audit`, `klog`, `ada0`, `nvme0` and the rest are *neither listed
by `getdirentries` nor openable*. A node in this devfs that exists but is credential-gated shows
up in the listing and then refuses (`dbggc`, `sbl_srv`, `encdec`, `uvd_dec`, `mp3`, `a53mm`,
`a53mmsys`, `fttrm`, `duid`, `acm`, `lvd3`, `hmd2_image`, `hmd2_slam_trace`). None of the
guessed memory-interface names does.

## ioctl on a real device descriptor

The dead-end list says "ioctl via make_syscall returns -1 for all tested codes". That measurement
never held a device descriptor — the fd was the loader's own stream. The thirteen devices that
open are now known by name, so `probes/phase17_new_vectors/1075a_device_ioctl.lua` called
`ioctl(54)` on each with 26 request codes and a sentinel-filled buffer.

**Twelve of thirteen return `-1` for every code.** `/dev/camera` is the exception: it accepts the
call and returns **22** for every request whose declared size is at least 8 bytes, and `-1` for
size 0. `probes/phase17_new_vectors/1077a_camera_ioctl_type.lua` then swept direction × type
(0-63) × number (0-3) and found the behaviour is selected by the **direction bits alone**: every
`_IOW` request zeroes the first 8 bytes of the caller buffer, and `_IOR`/`_IOWR` leave it
untouched.

| direction | observed |
|---|---|
| `0x40000000` (`_IOW`) | `rv=22`, first 8 bytes of the buffer become zero |
| `0x80000000` (`_IOR`) | `rv=22`, buffer untouched |
| `0xC0000000` (`_IOWR`) | `rv=22`, buffer untouched |

The zeroing is not a round trip: a buffer painted with `0xA0000000` comes back as `0x00000000`,
so the kernel writes a zeroed buffer rather than echoing what it read. **No kernel data reaches
the caller**, and the handler rejects every code with the same value, so this is not a leak and
not a usable primitive.

Two measurement traps burned runs here: `_IOC` packs the *number* in bits 0-7 and the *type* in
bits 8-15, so a sweep that steps `cmd += 0x100` varies the type and never the number; and reading
a sentinel qword such as `0xCDCDCDCDCDCDCDCD` through `tonumber` rounds it above 2^53, which
fabricates a changed-dword result — compare dwords with `memory.read_dword`.
