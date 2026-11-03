# The loader process's descriptor table

Status: measured, 2026-11-03, firmware 14.10, on the game process that hosts the
remote Lua loader (`savedata/main.lua`).

`fstat(189)` kills this kernel, so the descriptor table was mapped with calls that only
inspect: `fcntl(fd, F_GETFL=3)`, `getsockname(32)` and `getpeername(33)`. All three are
safe on every descriptor. `read(3)` is **not**: descriptor 18 is the loader's source
stream, and descriptors 20/21 are the loader's own TCP listener and the accepted PC
connection, so a blocking read there wedges the loader permanently.

## The table

Measured with `probes/phase17_new_vectors/975c_fcntl_fd_map.lua`,
`975d_fd_identify.lua` and `975e_fd_peername.lua` (`results/phase17_new_vectors/975c_*`,
`975d_*`, `975e_*`). Controls in the same runs: `fcntl(28, F_GETFL)` returns `0x2`, a
bogus descriptor `2047` returns `-1`, and `read(fd, buf, 0)` returns `0` on a good
descriptor and `-1` on a bad one.

| fds | `F_GETFL` | identity |
|---|---|---|
| 0 | `0x0` | not a socket, no access flags |
| 1, 2, 3, 7, 19 | `0x1` | write-only |
| 4, 5, 6, 8…13, 15…17 | `0x2` | read/write |
| 14, 18 | `0x0` | see below |
| 20, 21 | `0x2` | **`AF_INET` bound to port 9026** — the listener and the accepted PC connection |
| 22…33 | `0x2` | `AF_UNIX` socketpairs, unnamed (`sun_path` empty) |

Descriptors 10 and 14 are the two the kernel answers differently: `653` returns
`EINVAL` for fd 10 and the Sony status `0x803B0004` for fd 14, while every other
descriptor yields `-1`. Neither is readable or mappable: `read(3)` returns `-1` on fd
10 and `0` on fd 14, and `mmap(477)` with `MAP_PRIVATE` or `MAP_SHARED` on fd 10, 14 or
3 fails with `-1` (`977a`).

## Descriptor 18 is the loader's own source

`read(3)` on fd 18 returns the text of the loader's `main.lua`, up to `0x100` bytes per
call, and the stream advances. This is the channel used by
[LOADER_FAULT_CHANNEL_14_10.md](LOADER_FAULT_CHANNEL_14_10.md) to read the loader's
capability list, and by `probes/phase17_new_vectors/987a_loader_source_extract.lua` to
print it.

## The only device node that answers

`probes/phase17_new_vectors/978a_dev_nodes.lua` tried the usual console nodes through
`io.open`: `/dev/random` opens and returns real random bytes. `/dev/null`, `/dev/zero`
and `/dev/urandom` were already known to work; `/dev/klog`, `/dev/console`, `/dev/tty`,
`/dev/mem` and `/dev/kmem` do not exist. `ioctl(54)` returns `-1` for every request on
every descriptor tested (`976a`), so there is no device-control surface reachable
through the descriptor table.

## What this means

The descriptor table of the game process is the loader's own plumbing and nothing
else: three standard streams, two device-ish descriptors that refuse every operation,
one source stream, the TCP pair, and a set of anonymous socketpairs the loader creates
for its payloads. `sys 653` hands out further descriptors (28, 29, 835 in the `985a`
run) that behave the same as fd 10.

The useful consequences are the two negative ones: there is no device `mmap`/`ioctl`
door here, and the only descriptor that yields data is the loader's own source.

## Probes and captures

| probe | capture | content |
|---|---|---|
| `975c_fcntl_fd_map.lua` | `975c_fcntl_fd_map_20261103_112621.txt` | `F_GETFL` sweep 0…47 with controls |
| `975d_fd_identify.lua` | `975d_fd_identify_20261103_112648.txt`, `…_112700.txt` | flags plus `getsockname` |
| `975e_fd_peername.lua` | `975e_fd_peername_20261103_112723.txt` | peer addresses |
| `976a_ioctl_real_fds.lua` | `976a_ioctl_real_fds_20261103_112812.txt` | `ioctl` refused everywhere |
| `977a_device_fd_mmap.lua` | `977a_device_fd_mmap_20261103_112901.txt` | `mmap`/`read` on fd 10, 14, 3 |
| `977b_fd18_content.lua` | `977b_fd18_content_20261103_112918.txt` | fd 18 returns source |
| `978a_dev_nodes.lua` | `978a_dev_nodes_20261103_113020.txt` | `/dev` node sweep |
| `985a_device_fd_io.lua` | `985a_device_fd_io_20261103_151106.txt` | `read`/`write` on the `653` descriptors |
