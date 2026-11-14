# arg1 pointer classes, syscalls 1-531 (14.10)

The sibling of `docs/ARG1_CLASSES_14_10.md`: that page swept 532-676 and found eight
handlers whose answer depends on the class of the first argument. This one covers the
BSD-native range, which until now had only been called with six zeros, one connection
per number (`tools/syscall_isolation_sweep.py`, indexed in
`docs/SYSENT_PRESENCE_14_10.md`).

## Method

`SIG_IGN` on signals 5, 6, 7, 8, 12, 24, 25, 26, 30 and 31 first, so the reserved `nosys`
trampoline answers `-1`/`ENOSYS` instead of raising SIGSYS and killing the caller
(`probes/phase17_new_vectors/353b_lethal_reclassify.lua:41-57`). Then each number is called
as `n(arg1, 0, 0, 0, 0, 0)` with `arg1` = a mapped 0x4000-byte page painted `0xA5`, and the
page is re-read through `memory.read_buffer` to count writes.

A single thread cannot hold the whole range: several numbers block or kill, and the loader
serves one connection at a time, so one hang costs one relaunch. The range was therefore
measured in five segments, each one starting after the number that ended the previous one:

| segment | range | ended on |
|---|---|---|
| `1376a` | 1-73 | 74 `mprotect` faulted the caller |
| `1376b` | 75-340 | 341 `sigsuspend` blocked |
| `1376c` | 342-344 | 345 `sigtimedwait` blocked |
| `1376d` | 346-430 | 431 `thr_exit` ended the loader thread |
| `1376e` | 433-531 | completed |

507 of the 531 numbers are measured; the 24 that are not are listed at the end with the
reason. Captures live in `results/phase35_dead_end_reruns/1376a..1376e_*.txt` and
`results/phase35_dead_end_reruns/1377a_arg1_kernel_class_bsd_20261109_132333.txt`.

## What the range looks like

**346 of the 507 measured numbers are the shared `nosys` stub** (`-1`/`ENOSYS`, errno 78).
That is the headline: the BSD-native range on 14.10 is mostly not implemented, and the 161
numbers that `docs/SYSENT_PRESENCE_14_10.md` recorded as *kills* were almost all the SIGSYS
trampoline rather than a hostile handler. Of the 161 real handlers, 24 answer a pointer with
a non-negative return value, and the rest reject the call with a specific errno.

**No handler in 1-531 depends on the class of `arg1`.** The 24 live rows were re-called with
`arg1 = 0xFFFFFFFFC1000000` (this boot's kernel image base, present supervisor page per
`1331a`): the twelve that ignore `arg1` answer exactly the same, and **the five that copy
out answer `-1`/EFAULT** (`116 gettimeofday`, `343 sigpending`, `404 ksem_init`,
`405 ksem_open`, `421 getcontext`). The destination predicate holds for all five, so the
range offers no kernel read. `78 mincore` moves from `0` to `-1`/ENOMEM and `65 msync`/
`75 madvise` from `0` to `-1`/EINVAL, which is the VM layer rejecting a supervisor address,
not a class-dependent read.

Writers confirmed with a user destination, for the record: `421 getcontext` writes 0x110
bytes of context, `116 gettimeofday` 16 bytes, `343 sigpending` 16 bytes of sigset, and
`404`/`405` 8 bytes carrying a small id (`0x19`, `0x1A`). None of them ever produce a
kernel-shaped qword, which matches the rest of the corpus: no syscall output on 14.10 has
leaked a kernel pointer.

**Identity numbers**: `20 getpid` answers 278/300 across the segments, `39 getppid` the
loader's pid 54, `24/25/43/47` (getuid/geteuid/getegid/getgid) 1, `42 compat10.pipe` 22
(the descriptor count, not a pair), `362 kqueue` 22/24 (the fd).

## The table

Empty kernel column = the number ignores `arg1` and answered identically.

| # | 13.60 name | arg1 = mapped user page | arg1 = kernel image base |
|---|---|---|---|
| 1 | `exit` | *skipped* | *skipped* |
| 2 | `fork` | `-1` Operation not permitted |  |
| 3 | `read` | `-1` Bad file descriptor |  |
| 4 | `write` | `-1` Bad file descriptor |  |
| 5 | `open` | `-1` File name too long |  |
| 6 | `close` | `-1` Bad file descriptor |  |
| 7 | `wait4` | `-1` Operation not permitted |  |
| 8 | `compat.creat` | `-1` ENOSYS |  |
| 9 | `link` | `-1` ENOSYS |  |
| 10 | `unlink` | `-1` File name too long |  |
| 11 | `obs_execv` | `-1` ENOSYS |  |
| 12 | `chdir` | `-1` Operation not permitted |  |
| 13 | `fchdir` | `-1` ENOSYS |  |
| 14 | `mknod` | `-1` ENOSYS |  |
| 15 | `chmod` | `-1` File name too long |  |
| 16 | `chown` | `-1` ENOSYS |  |
| 17 | `obs_{` | `-1` ENOSYS |  |
| 18 | `compat4.getfsstat` | `-1` ENOSYS |  |
| 19 | `compat.lseek` | `-1` ENOSYS |  |
| 20 | `getpid` | `278` | `300` |
| 21 | `mount` | `-1` ENOSYS |  |
| 22 | `unmount` | `-1` ENOSYS |  |
| 23 | `setuid` | `-1` Operation not permitted |  |
| 24 | `getuid` | `1` | `1` |
| 25 | `geteuid` | `1` | `1` |
| 26 | `ptrace` | `-1` ENOSYS |  |
| 27 | `recvmsg` | `-1` Bad address |  |
| 28 | `sendmsg` | `-1` Bad address |  |
| 29 | `recvfrom` | `-1` Bad file descriptor |  |
| 30 | `accept` | `-1` Bad file descriptor |  |
| 31 | `getpeername` | `-1` Bad address |  |
| 32 | `getsockname` | `-1` Bad address |  |
| 33 | `access` | `-1` Operation not permitted |  |
| 34 | `chflags` | `-1` File name too long |  |
| 35 | `fchflags` | `-1` Bad file descriptor |  |
| 36 | `sync` | `0` | `0` |
| 37 | `kill` | `-1` No such process |  |
| 38 | `compat.stat` | `-1` ENOSYS |  |
| 39 | `getppid` | `54` | `54` |
| 40 | `compat.lstat` | `-1` ENOSYS |  |
| 41 | `dup` | `-1` Operation not permitted |  |
| 42 | `compat10.pipe` | `22` | `22` |
| 43 | `getegid` | `1` | `1` |
| 44 | `profil` | `0` | `0` |
| 45 | `ktrace` | `-1` ENOSYS |  |
| 46 | `compat.sigaction` | `-1` ENOSYS |  |
| 47 | `getgid` | `1` | `1` |
| 48 | `compat.sigprocmask` | `-1` ENOSYS |  |
| 49 | `getlogin` | `-1` Result too large |  |
| 50 | `setlogin` | `-1` Operation not permitted |  |
| 51 | `obs_{` | `-1` ENOSYS |  |
| 52 | `compat.sigpending` | `-1` ENOSYS |  |
| 53 | `sigaltstack` | `-1` Invalid argument |  |
| 54 | `ioctl` | `-1` Inappropriate ioctl for device |  |
| 55 | `reboot` | `-1` Operation not permitted |  |
| 56 | `revoke` | `-1` Operation not permitted |  |
| 57 | `symlink` | `-1` ENOSYS |  |
| 58 | `readlink` | `-1` ENOSYS |  |
| 59 | `execve` | *skipped* | *skipped* |
| 60 | `umask` | `-1` ENOSYS |  |
| 61 | `chroot` | `-1` ENOSYS |  |
| 62 | `compat.fstat` | `-1` ENOSYS |  |
| 63 | `compat.getkerninfo` | `-1` ENOSYS |  |
| 64 | `compat.getpagesize` | `-1` ENOSYS |  |
| 65 | `msync` | `0` | `-1 EINVAL` |
| 66 | `vfork` | `-1` ENOSYS |  |
| 67 | `obs_vread` | `-1` ENOSYS |  |
| 68 | `obs_vwrite` | `-1` ENOSYS |  |
| 69 | `sbrk` | `-1` ENOSYS |  |
| 70 | `sstk` | `-1` ENOSYS |  |
| 71 | `compat.mmap` | `-1` ENOSYS |  |
| 72 | `obs_{` | `-1` ENOSYS |  |
| 73 | `munmap` | `-1` Invalid argument |  |
| 74 | `mprotect` | *skipped* | *skipped* |
| 75 | `madvise` | `0` | `-1 EINVAL` |
| 76 | `obs_vhangup` | `-1` ENOSYS |  |
| 77 | `obs_vlimit` | `-1` ENOSYS |  |
| 78 | `mincore` | `0` | `-1 ENOMEM` |
| 79 | `getgroups` | `-1` Bad address |  |
| 80 | `setgroups` | `-1` Invalid argument |  |
| 81 | `getpgrp` | `-1` ENOSYS |  |
| 82 | `setpgid` | `-1` ENOSYS |  |
| 83 | `setitimer` | `-1` Invalid argument |  |
| 84 | `compat.wait` | `-1` ENOSYS |  |
| 85 | `swapon` | `-1` ENOSYS |  |
| 86 | `getitimer` | `-1` Invalid argument |  |
| 87 | `compat.gethostname` | `-1` ENOSYS |  |
| 88 | `compat.sethostname` | `-1` ENOSYS |  |
| 89 | `getdtablesize` | `-1` Operation not permitted |  |
| 90 | `dup2` | `-1` Operation not permitted |  |
| 91 | `#91` | `-1` ENOSYS |  |
| 92 | `fcntl` | `-1` Invalid argument |  |
| 93 | `select` | *skipped* | *skipped* |
| 94 | `#94` | `-1` ENOSYS |  |
| 95 | `fsync` | *skipped* | *skipped* |
| 96 | `setpriority` | `-1` Invalid argument |  |
| 97 | `socket` | `-1` Address family not supported by protocol family |  |
| 98 | `connect` | `-1` Invalid argument |  |
| 99 | `netcontrol` | `-1` Invalid argument |  |
| 100 | `getpriority` | `-1` Invalid argument |  |
| 101 | `netabort` | `-1` Bad file descriptor |  |
| 102 | `netgetsockinfo` | `-1` Bad file descriptor |  |
| 103 | `compat.sigreturn` | `-1` ENOSYS |  |
| 104 | `bind` | `-1` Invalid argument |  |
| 105 | `setsockopt` | `-1` Bad file descriptor |  |
| 106 | `listen` | `-1` Bad file descriptor |  |
| 107 | `obs_vtimes` | `-1` ENOSYS |  |
| 108 | `compat.sigvec` | `-1` ENOSYS |  |
| 109 | `compat.sigblock` | `-1` ENOSYS |  |
| 110 | `compat.sigsetmask` | `-1` ENOSYS |  |
| 111 | `compat.sigsuspend` | `-1` ENOSYS |  |
| 112 | `compat.sigstack` | `-1` ENOSYS |  |
| 113 | `socketex` | `-1` Address family not supported by protocol family |  |
| 114 | `socketclose` | `-1` Bad file descriptor |  |
| 115 | `obs_vtrace` | `-1` ENOSYS |  |
| 116 | `gettimeofday` | `0` (wrote 16 B) | `-1 EFAULT` |
| 117 | `getrusage` | `-1` Invalid argument |  |
| 118 | `getsockopt` | `-1` Bad file descriptor |  |
| 119 | `#119` | `-1` ENOSYS |  |
| 120 | `readv` | `-1` Bad file descriptor |  |
| 121 | `writev` | `-1` Bad file descriptor |  |
| 122 | `settimeofday` | `-1` Operation not permitted |  |
| 123 | `fchown` | `-1` ENOSYS |  |
| 124 | `fchmod` | `-1` Bad file descriptor |  |
| 125 | `netgetiflist` | `-1` Invalid argument |  |
| 126 | `setreuid` | `-1` Operation not permitted |  |
| 127 | `setregid` | `-1` Operation not permitted |  |
| 128 | `rename` | `-1` File name too long |  |
| 129 | `compat.truncate` | `-1` ENOSYS |  |
| 130 | `compat.ftruncate` | `-1` ENOSYS |  |
| 131 | `flock` | `-1` Bad file descriptor |  |
| 132 | `mkfifo` | `-1` ENOSYS |  |
| 133 | `sendto` | `-1` Bad file descriptor |  |
| 134 | `shutdown` | `-1` Bad file descriptor |  |
| 135 | `socketpair` | `-1` Address family not supported by protocol family |  |
| 136 | `mkdir` | `-1` File name too long |  |
| 137 | `rmdir` | `-1` File name too long |  |
| 138 | `utimes` | `-1` File name too long |  |
| 139 | `obs_4.2` | `-1` ENOSYS |  |
| 140 | `adjtime` | `-1` Operation not permitted |  |
| 141 | `kqueueex` | `-1` File name too long |  |
| 142 | `compat.gethostid` | `-1` ENOSYS |  |
| 143 | `compat.sethostid` | `-1` ENOSYS |  |
| 144 | `compat.getrlimit` | `-1` ENOSYS |  |
| 145 | `compat.setrlimit` | `-1` ENOSYS |  |
| 146 | `compat.killpg` | `-1` ENOSYS |  |
| 147 | `setsid` | `-1` Operation not permitted |  |
| 148 | `obs_{` | `-1` ENOSYS |  |
| 149 | `compat.quota` | `-1` ENOSYS |  |
| 150 | `compat.getsockname` | `-1` ENOSYS |  |
| 151 | `#151` | `-1` ENOSYS |  |
| 152 | `#152` | `-1` ENOSYS |  |
| 153 | `#153` | `-1` ENOSYS |  |
| 154 | `nlm_syscall` | `-1` ENOSYS |  |
| 155 | `nfssvc` | `-1` ENOSYS |  |
| 156 | `compat.getdirentries` | `-1` ENOSYS |  |
| 157 | `compat4.statfs` | `-1` ENOSYS |  |
| 158 | `compat4.fstatfs` | `-1` ENOSYS |  |
| 159 | `#159` | `-1` ENOSYS |  |
| 160 | `obs_{` | `-1` ENOSYS |  |
| 161 | `obs_{` | `-1` ENOSYS |  |
| 162 | `compat4.getdomainname` | `-1` ENOSYS |  |
| 163 | `compat4.setdomainname` | `-1` ENOSYS |  |
| 164 | `compat4.uname` | `-1` ENOSYS |  |
| 165 | `sysarch` | `-1` Invalid argument |  |
| 166 | `rtprio` | `-1` ENOSYS |  |
| 167 | `#167` | `-1` ENOSYS |  |
| 168 | `#168` | `-1` ENOSYS |  |
| 169 | `semsys` | `-1` ENOSYS |  |
| 170 | `msgsys` | `-1` ENOSYS |  |
| 171 | `shmsys` | `-1` ENOSYS |  |
| 172 | `#172` | `-1` ENOSYS |  |
| 173 | `compat6.pread` | `-1` ENOSYS |  |
| 174 | `compat6.pwrite` | `-1` ENOSYS |  |
| 175 | `obs_{` | `-1` ENOSYS |  |
| 176 | `obs_{` | `-1` ENOSYS |  |
| 177 | `#177` | `-1` ENOSYS |  |
| 178 | `#178` | `-1` ENOSYS |  |
| 179 | `#179` | `-1` ENOSYS |  |
| 180 | `#180` | `-1` ENOSYS |  |
| 181 | `setgid` | `-1` ENOSYS |  |
| 182 | `setegid` | `-1` Operation not permitted |  |
| 183 | `seteuid` | `-1` Operation not permitted |  |
| 184 | `#184` | `-1` ENOSYS |  |
| 185 | `#185` | `-1` ENOSYS |  |
| 186 | `#186` | `-1` ENOSYS |  |
| 187 | `#187` | `-1` ENOSYS |  |
| 188 | `stat` | `-1` File name too long |  |
| 189 | `fstat` | `-1` Bad file descriptor |  |
| 190 | `lstat` | `-1` Operation not permitted |  |
| 191 | `pathconf` | `-1` Operation not permitted |  |
| 192 | `fpathconf` | `-1` Operation not permitted |  |
| 193 | `#193` | `-1` ENOSYS |  |
| 194 | `getrlimit` | `-1` Invalid argument |  |
| 195 | `setrlimit` | `-1` Bad address |  |
| 196 | `getdirentries` | `-1` Invalid argument |  |
| 197 | `compat6.mmap` | `-1` ENOSYS |  |
| 198 | `__syscall` | `-1` ENOSYS |  |
| 199 | `compat6.lseek` | `-1` ENOSYS |  |
| 200 | `compat6.truncate` | `-1` ENOSYS |  |
| 201 | `compat6.ftruncate` | `-1` ENOSYS |  |
| 202 | `__sysctl` | `-1` Invalid argument |  |
| 203 | `mlock` | `0` | `0` |
| 204 | `munlock` | `-1` Invalid argument |  |
| 205 | `obs_{` | `-1` ENOSYS |  |
| 206 | `futimes` | `-1` Bad file descriptor |  |
| 207 | `getpgid` | `-1` ENOSYS |  |
| 208 | `#208` | `-1` ENOSYS |  |
| 209 | `poll` | `0` | `0` |
| 210 | `lkmnosys` | `-1` ENOSYS |  |
| 211 | `lkmnosys` | `-1` ENOSYS |  |
| 212 | `lkmnosys` | `-1` ENOSYS |  |
| 213 | `lkmnosys` | `-1` ENOSYS |  |
| 214 | `lkmnosys` | `-1` ENOSYS |  |
| 215 | `lkmnosys` | `-1` ENOSYS |  |
| 216 | `lkmnosys` | `-1` ENOSYS |  |
| 217 | `lkmnosys` | `-1` ENOSYS |  |
| 218 | `lkmnosys` | `-1` ENOSYS |  |
| 219 | `lkmnosys` | `-1` ENOSYS |  |
| 220 | `compat7.__semctl` | `-1` ENOSYS |  |
| 221 | `semget` | `-1` ENOSYS |  |
| 222 | `semop` | `-1` ENOSYS |  |
| 223 | `#223` | `-1` ENOSYS |  |
| 224 | `compat7.msgctl` | `-1` ENOSYS |  |
| 225 | `msgget` | `-1` ENOSYS |  |
| 226 | `msgsnd` | `-1` ENOSYS |  |
| 227 | `msgrcv` | `-1` ENOSYS |  |
| 228 | `shmat` | `-1` ENOSYS |  |
| 229 | `compat7.shmctl` | `-1` ENOSYS |  |
| 230 | `shmdt` | `-1` ENOSYS |  |
| 231 | `shmget` | `-1` ENOSYS |  |
| 232 | `clock_gettime` | `-1` Invalid argument |  |
| 233 | `clock_settime` | `-1` Operation not permitted |  |
| 234 | `clock_getres` | `0` | `0` |
| 235 | `ktimer_create` | `-1` Invalid argument |  |
| 236 | `ktimer_delete` | `-1` Invalid argument |  |
| 237 | `ktimer_settime` | `-1` Bad address |  |
| 238 | `ktimer_gettime` | `-1` Invalid argument |  |
| 239 | `ktimer_getoverrun` | `-1` Invalid argument |  |
| 240 | `nanosleep` | `-1` Invalid argument |  |
| 241 | `ffclock_getcounter` | `-1` ENOSYS |  |
| 242 | `ffclock_setestimate` | `-1` ENOSYS |  |
| 243 | `ffclock_getestimate` | `-1` ENOSYS |  |
| 244 | `#244` | `-1` ENOSYS |  |
| 245 | `#245` | `-1` ENOSYS |  |
| 246 | `#246` | `-1` ENOSYS |  |
| 247 | `clock_getcpuclockid2` | `-1` ENOSYS |  |
| 248 | `obs_{` | `-1` ENOSYS |  |
| 249 | `#249` | `-1` ENOSYS |  |
| 250 | `minherit` | `-1` ENOSYS |  |
| 251 | `rfork` | `-1` Operation not permitted |  |
| 252 | `obs_{` | `-1` ENOSYS |  |
| 253 | `issetugid` | `0` | `0` |
| 254 | `lchown` | `-1` ENOSYS |  |
| 255 | `aio_read` | `-1` ENOSYS |  |
| 256 | `aio_write` | `-1` ENOSYS |  |
| 257 | `obs_{` | `-1` ENOSYS |  |
| 258 | `#258` | `-1` ENOSYS |  |
| 259 | `#259` | `-1` ENOSYS |  |
| 260 | `#260` | `-1` ENOSYS |  |
| 261 | `#261` | `-1` ENOSYS |  |
| 262 | `#262` | `-1` ENOSYS |  |
| 263 | `#263` | `-1` ENOSYS |  |
| 264 | `#264` | `-1` ENOSYS |  |
| 265 | `#265` | `-1` ENOSYS |  |
| 266 | `#266` | `-1` ENOSYS |  |
| 267 | `#267` | `-1` ENOSYS |  |
| 268 | `#268` | `-1` ENOSYS |  |
| 269 | `#269` | `-1` ENOSYS |  |
| 270 | `#270` | `-1` ENOSYS |  |
| 271 | `#271` | `-1` ENOSYS |  |
| 272 | `getdents` | `-1` Invalid argument |  |
| 273 | `#273` | `-1` ENOSYS |  |
| 274 | `lchmod` | `-1` ENOSYS |  |
| 275 | `netbsd_lchown` | `-1` ENOSYS |  |
| 276 | `lutimes` | `-1` ENOSYS |  |
| 277 | `netbsd_msync` | `-1` ENOSYS |  |
| 278 | `obs_{` | `-1` ENOSYS |  |
| 279 | `obs_{` | `-1` ENOSYS |  |
| 280 | `obs_{` | `-1` ENOSYS |  |
| 281 | `#281` | `-1` ENOSYS |  |
| 282 | `#282` | `-1` ENOSYS |  |
| 283 | `#283` | `-1` ENOSYS |  |
| 284 | `#284` | `-1` ENOSYS |  |
| 285 | `#285` | `-1` ENOSYS |  |
| 286 | `#286` | `-1` ENOSYS |  |
| 287 | `#287` | `-1` ENOSYS |  |
| 288 | `#288` | `-1` ENOSYS |  |
| 289 | `preadv` | `-1` Bad file descriptor |  |
| 290 | `pwritev` | `-1` Bad file descriptor |  |
| 291 | `#291` | `-1` ENOSYS |  |
| 292 | `#292` | `-1` ENOSYS |  |
| 293 | `#293` | `-1` ENOSYS |  |
| 294 | `#294` | `-1` ENOSYS |  |
| 295 | `#295` | `-1` ENOSYS |  |
| 296 | `#296` | `-1` ENOSYS |  |
| 297 | `compat4.fhstatfs` | `-1` ENOSYS |  |
| 298 | `obs_{` | `-1` ENOSYS |  |
| 299 | `obs_{` | `-1` ENOSYS |  |
| 300 | `obs_{` | `-1` ENOSYS |  |
| 301 | `obs_{` | `-1` ENOSYS |  |
| 302 | `obs_{` | `-1` ENOSYS |  |
| 303 | `obs_{` | `-1` ENOSYS |  |
| 304 | `kldload` | `-1` ENOSYS |  |
| 305 | `kldunload` | `-1` ENOSYS |  |
| 306 | `kldfind` | `-1` ENOSYS |  |
| 307 | `kldnext` | `-1` ENOSYS |  |
| 308 | `kldstat` | `-1` ENOSYS |  |
| 309 | `kldfirstmod` | `-1` ENOSYS |  |
| 310 | `getsid` | `-1` No such process |  |
| 311 | `setresuid` | `-1` ENOSYS |  |
| 312 | `setresgid` | `-1` ENOSYS |  |
| 313 | `obs_signanosleep` | `-1` ENOSYS |  |
| 314 | `aio_return` | `-1` ENOSYS |  |
| 315 | `aio_suspend` | `-1` Operation not permitted |  |
| 316 | `aio_cancel` | `-1` ENOSYS |  |
| 317 | `aio_error` | `-1` ENOSYS |  |
| 318 | `compat6.aio_read` | `-1` ENOSYS |  |
| 319 | `compat6.aio_write` | `-1` ENOSYS |  |
| 320 | `compat6.lio_listio` | `-1` ENOSYS |  |
| 321 | `yield` | `-1` ENOSYS |  |
| 322 | `obs_thr_sleep` | `-1` ENOSYS |  |
| 323 | `obs_thr_wakeup` | `-1` ENOSYS |  |
| 324 | `mlockall` | `-1` Invalid argument |  |
| 325 | `munlockall` | `-1` Operation not supported |  |
| 326 | `__getcwd` | `-1` ENOSYS |  |
| 327 | `sched_setparam` | `-1` Bad address |  |
| 328 | `sched_getparam` | `-1` No such process |  |
| 329 | `sched_setscheduler` | `-1` Bad address |  |
| 330 | `sched_getscheduler` | `-1` No such process |  |
| 331 | `sched_yield` | `0` | `0` |
| 332 | `sched_get_priority_max` | `-1` Invalid argument |  |
| 333 | `sched_get_priority_min` | `-1` Invalid argument |  |
| 334 | `sched_rr_get_interval` | `-1` No such process |  |
| 335 | `utrace` | `-1` ENOSYS |  |
| 336 | `compat4.sendfile` | `-1` ENOSYS |  |
| 337 | `kldsym` | `-1` ENOSYS |  |
| 338 | `obs_{` | `-1` ENOSYS |  |
| 339 | `nnpfs_syscall` | `-1` ENOSYS |  |
| 340 | `sigprocmask` | `0` | `0` |
| 341 | `sigsuspend` | *skipped* | *skipped* |
| 342 | `compat4.sigaction` | `-1` ENOSYS |  |
| 343 | `sigpending` | `0` (wrote 16 B) | `-1 EFAULT` |
| 344 | `compat4.sigreturn` | `-1` ENOSYS |  |
| 345 | `sigtimedwait` | *skipped* | *skipped* |
| 346 | `sigwaitinfo` | *skipped* | *skipped* |
| 347 | `obs_{` | `-1` ENOSYS |  |
| 348 | `obs_{` | `-1` ENOSYS |  |
| 349 | `obs_{` | `-1` ENOSYS |  |
| 350 | `obs_{` | `-1` ENOSYS |  |
| 351 | `obs_{` | `-1` ENOSYS |  |
| 352 | `obs_{` | `-1` ENOSYS |  |
| 353 | `obs_{` | `-1` ENOSYS |  |
| 354 | `obs_{` | `-1` ENOSYS |  |
| 355 | `obs_{` | `-1` ENOSYS |  |
| 356 | `obs_{` | `-1` ENOSYS |  |
| 357 | `obs_{` | `-1` ENOSYS |  |
| 358 | `obs_{` | `-1` ENOSYS |  |
| 359 | `aio_waitcomplete` | *skipped* | *skipped* |
| 360 | `getresuid` | `-1` ENOSYS |  |
| 361 | `getresgid` | `-1` ENOSYS |  |
| 362 | `kqueue` | `22` | `24` |
| 363 | `kevent` | *skipped* | *skipped* |
| 364 | `#364` | `-1` ENOSYS |  |
| 365 | `#365` | `-1` ENOSYS |  |
| 366 | `#366` | `-1` ENOSYS |  |
| 367 | `#367` | `-1` ENOSYS |  |
| 368 | `#368` | `-1` ENOSYS |  |
| 369 | `#369` | `-1` ENOSYS |  |
| 370 | `#370` | `-1` ENOSYS |  |
| 371 | `obs_{` | `-1` ENOSYS |  |
| 372 | `obs_{` | `-1` ENOSYS |  |
| 373 | `obs_{` | `-1` ENOSYS |  |
| 374 | `__setugid` | `-1` ENOSYS |  |
| 375 | `#375` | `-1` ENOSYS |  |
| 376 | `obs_{` | `-1` ENOSYS |  |
| 377 | `afs3_syscall` | `-1` ENOSYS |  |
| 378 | `nmount` | `-1` ENOSYS |  |
| 379 | `mtypeprotect` | `-1` Operation not supported |  |
| 380 | `#380` | `-1` ENOSYS |  |
| 381 | `#381` | `-1` ENOSYS |  |
| 382 | `#382` | `-1` ENOSYS |  |
| 383 | `#383` | `-1` ENOSYS |  |
| 384 | `__mac_get_proc` | `-1` ENOSYS |  |
| 385 | `__mac_set_proc` | `-1` ENOSYS |  |
| 386 | `__mac_get_fd` | `-1` ENOSYS |  |
| 387 | `__mac_get_file` | `-1` ENOSYS |  |
| 388 | `__mac_set_fd` | `-1` ENOSYS |  |
| 389 | `__mac_set_file` | `-1` ENOSYS |  |
| 390 | `kenv` | `-1` ENOSYS |  |
| 391 | `lchflags` | `-1` ENOSYS |  |
| 392 | `uuidgen` | `-1` Invalid argument |  |
| 393 | `sendfile` | `-1` Bad file descriptor |  |
| 394 | `mac_syscall` | `-1` ENOSYS |  |
| 395 | `getfsstat` | `-1` ENOSYS |  |
| 396 | `statfs` | `-1` ENOSYS |  |
| 397 | `fstatfs` | `-1` Operation not permitted |  |
| 398 | `obs_{` | `-1` ENOSYS |  |
| 399 | `#399` | `-1` ENOSYS |  |
| 400 | `ksem_close` | `-1` Invalid argument |  |
| 401 | `ksem_post` | `-1` Invalid argument |  |
| 402 | `ksem_wait` | *skipped* | *skipped* |
| 403 | `ksem_trywait` | `-1` Invalid argument |  |
| 404 | `ksem_init` | `0` (wrote 8 B) | `-1 EFAULT` |
| 405 | `ksem_open` | `0` (wrote 8 B) | `-1 EFAULT` |
| 406 | `ksem_unlink` | `-1` File name too long |  |
| 407 | `ksem_getvalue` | `-1` Invalid argument |  |
| 408 | `ksem_destroy` | `-1` Invalid argument |  |
| 409 | `__mac_get_pid` | `-1` ENOSYS |  |
| 410 | `__mac_get_link` | `-1` ENOSYS |  |
| 411 | `__mac_set_link` | `-1` ENOSYS |  |
| 412 | `obs_{` | `-1` ENOSYS |  |
| 413 | `obs_{` | `-1` ENOSYS |  |
| 414 | `obs_{` | `-1` ENOSYS |  |
| 415 | `__mac_execve` | `-1` ENOSYS |  |
| 416 | `sigaction` | `-1` Invalid argument |  |
| 417 | `sigreturn` | *skipped* | *skipped* |
| 418 | `#418` | `-1` ENOSYS |  |
| 419 | `#419` | `-1` ENOSYS |  |
| 420 | `#420` | `-1` ENOSYS |  |
| 421 | `getcontext` | `0` (wrote 1120 B) | `-1 EFAULT` |
| 422 | `setcontext` | `-1` Invalid argument |  |
| 423 | `swapcontext` | `-1` Invalid argument |  |
| 424 | `obs_{` | `-1` ENOSYS |  |
| 425 | `obs_{` | `-1` ENOSYS |  |
| 426 | `obs_{` | `-1` ENOSYS |  |
| 427 | `obs_{` | `-1` ENOSYS |  |
| 428 | `obs_{` | `-1` ENOSYS |  |
| 429 | `sigwait` | *skipped* | *skipped* |
| 430 | `?` | `-1` Invalid argument |  |
| 431 | `thr_exit` | *skipped* | *skipped* |
| 432 | `thr_self` | *skipped* | *skipped* |
| 433 | `thr_kill` | `-1` No such process |  |
| 434 | `#434` | `-1` ENOSYS |  |
| 435 | `#435` | `-1` ENOSYS |  |
| 436 | `obs_{` | `-1` ENOSYS |  |
| 437 | `obs_{` | `-1` ENOSYS |  |
| 438 | `obs_{` | `-1` ENOSYS |  |
| 439 | `obs_{` | `-1` ENOSYS |  |
| 440 | `#440` | `-1` ENOSYS |  |
| 441 | `ksem_timedwait` | *skipped* | *skipped* |
| 442 | `thr_suspend` | *skipped* | *skipped* |
| 443 | `thr_wake` | `-1` No such process |  |
| 444 | `kldunloadf` | `-1` ENOSYS |  |
| 445 | `obs_{` | `-1` ENOSYS |  |
| 446 | `obs_{` | `-1` ENOSYS |  |
| 447 | `obs_{` | `-1` ENOSYS |  |
| 448 | `obs_{` | `-1` ENOSYS |  |
| 449 | `obs_{` | `-1` ENOSYS |  |
| 450 | `obs_{` | `-1` ENOSYS |  |
| 451 | `obs_{` | `-1` ENOSYS |  |
| 452 | `obs_{` | `-1` ENOSYS |  |
| 453 | `obs_{` | `-1` ENOSYS |  |
| 454 | `_umtx_op` | `-1` Operation not supported |  |
| 455 | `thr_new` | *skipped* | *skipped* |
| 456 | `sigqueue` | `-1` No such process |  |
| 457 | `kmq_open` | `-1` ENOSYS |  |
| 458 | `kmq_setattr` | `-1` ENOSYS |  |
| 459 | `kmq_timedreceive` | `-1` ENOSYS |  |
| 460 | `aio_suspend` | *skipped* | *skipped* |
| 461 | `aio_suspend` family | *skipped* | *skipped* |
| 462 | `aio_fsync` family | *skipped* | *skipped* |
| 463 | `obs_{` | `-1` ENOSYS |  |
| 464 | `thr_set_name` | `-1` No such process |  |
| 465 | `aio_fsync` | *skipped* | *skipped* |
| 466 | `rtprio_thread` | `-1` Invalid argument |  |
| 467 | `#467` | `-1` ENOSYS |  |
| 468 | `#468` | `-1` ENOSYS |  |
| 469 | `#469` | `-1` ENOSYS |  |
| 470 | `#470` | `-1` ENOSYS |  |
| 471 | `obs_{` | `-1` ENOSYS |  |
| 472 | `obs_{` | `-1` ENOSYS |  |
| 473 | `obs_{` | `-1` ENOSYS |  |
| 474 | `obs_{` | `-1` ENOSYS |  |
| 475 | `pread` | `-1` Bad file descriptor |  |
| 476 | `?` | `-1` Bad file descriptor |  |
| 477 | `?` | `-1` Invalid argument |  |
| 478 | `?` | `-1` Bad file descriptor |  |
| 479 | `?` | `-1` File name too long |  |
| 480 | `?` | `-1` Bad file descriptor |  |
| 481 | `?` | `-1` No such process |  |
| 482 | `?` | `-1` File name too long |  |
| 483 | `?` | `-1` File name too long |  |
| 484 | `?` | `-1` ENOSYS |  |
| 485 | `?` | `-1` ENOSYS |  |
| 486 | `?` | `-1` Invalid argument |  |
| 487 | `?` | `-1` Result too large |  |
| 488 | `?` | `-1` Result too large |  |
| 489 | `?` | `-1` ENOSYS |  |
| 490 | `?` | `-1` ENOSYS |  |
| 491 | `?` | `-1` ENOSYS |  |
| 492 | `obs_{` | `-1` ENOSYS |  |
| 493 | `fstatat` | `-1` ENOSYS |  |
| 494 | `futimesat` | `-1` ENOSYS |  |
| 495 | `linkat` | `-1` ENOSYS |  |
| 496 | `mkdirat` | `-1` ENOSYS |  |
| 497 | `mkfifoat` | `-1` ENOSYS |  |
| 498 | `mknodat` | `-1` ENOSYS |  |
| 499 | `openat` | `-1` Operation not permitted |  |
| 500 | `obs_{` | `-1` ENOSYS |  |
| 501 | `renameat` | `-1` ENOSYS |  |
| 502 | `symlinkat` | `-1` ENOSYS |  |
| 503 | `unlinkat` | `-1` ENOSYS |  |
| 504 | `obs_{` | `-1` ENOSYS |  |
| 505 | `gssd_syscall` | `-1` ENOSYS |  |
| 506 | `obs_{` | `-1` ENOSYS |  |
| 507 | `obs_{` | `-1` ENOSYS |  |
| 508 | `obs_{` | `-1` ENOSYS |  |
| 509 | `obs_{` | `-1` ENOSYS |  |
| 510 | `__semctl` | `-1` ENOSYS |  |
| 511 | `msgctl` | `-1` ENOSYS |  |
| 512 | `shmctl` | `-1` ENOSYS |  |
| 513 | `obs_{` | `-1` ENOSYS |  |
| 514 | `obs_cap_new` | `-1` ENOSYS |  |
| 515 | `__cap_rights_get` | `-1` ENOSYS |  |
| 516 | `cap_enter` | `-1` ENOSYS |  |
| 517 | `cap_getmode` | `-1` ENOSYS |  |
| 518 | `obs_{` | `-1` ENOSYS |  |
| 519 | `pdkill` | `-1` ENOSYS |  |
| 520 | `pdgetpid` | `-1` ENOSYS |  |
| 521 | `#521` | `-1` ENOSYS |  |
| 522 | `pselect` | *skipped* | *skipped* |
| 523 | `obs_{` | `-1` ENOSYS |  |
| 524 | `obs_{` | `-1` ENOSYS |  |
| 525 | `rctl_get_racct` | `-1` ENOSYS |  |
| 526 | `rctl_get_rules` | `-1` ENOSYS |  |
| 527 | `rctl_get_limits` | `-1` ENOSYS |  |
| 528 | `rctl_add_rule` | `-1` ENOSYS |  |
| 529 | `rctl_remove_rule` | `-1` ENOSYS |  |
| 530 | `obs_{` | *skipped* | *skipped* |
| 531 | `?` | `-1` ENOSYS |  |

## Skipped, with the reason

| # | 13.60 name | why |
|---|---|---|
| 1 | `exit` | ends the connection |
| 59 | `execve` | would replace the process under us |
| 74 | `mprotect` | **faults the caller** on a mapped heap page with `len=0, prot=0` |
| 93 | `select` | blocks with a null timeout set |
| 95 | `fsync` | blocks |
| 341 | `sigsuspend` | blocks, by design |
| 345 | `sigtimedwait` | null timeout blocks |
| 346 | `sigwaitinfo` | blocks |
| 359 | `aio_waitcomplete` | blocks |
| 363 | `kevent` | blocks |
| 402 | `ksem_wait` | blocks |
| 417 | `sigreturn` | a garbage frame is lethal by construction (`docs/ARG1_CLASSES_14_10.md`, 1359a) |
| 429 | `sigwait` | blocks |
| 431 | `thr_exit` | ends the loader's own thread |
| 432 | `thr_self` | `NO_OUTPUT` in the presence sweep |
| 441 | `ksem_timedwait` | null timeout blocks |
| 442 | `thr_suspend` | suspends the caller |
| 455 | `thr_new` | a painted `thr_param` is a garbage start routine |
| 460 | `aio_suspend` | blocks |
| 461 | `aio_suspend` family | blocks |
| 462 | `aio_fsync` family | blocks |
| 465 | `aio_fsync` | blocks |
| 522 | `pselect` | null timeout blocks |
| 530 | `obs_{` | `NO_OUTPUT` in the presence sweep |

Two of these are new measurements, not planned exclusions: **74 `mprotect` faults the
caller** when it is given a mapped heap page with `len=0, prot=0` and answers `0` to six
zeros, and **93 `select`/95 `fsync`/341 `sigsuspend`/345 `sigtimedwait` block** with a null
timeout or timeout pointer. Neither is a primitive: the first is a fault inside the call
(the capture ends in the loader's fault dump), the second is the wait it advertises.

## What this does not give

No kernel address is read, no kernel memory is written, and no handler in the range takes
an attacker-chosen destination or source. The 24 live rows are all self-report calls
(identity, time, VM hints, ksem ids, context capture). The range is closed as a surface:
the same three questions asked of 532-676 (a caller-controlled copy destination, a
caller-controlled copy source, a class-dependent answer) have the same negative answer
here.
