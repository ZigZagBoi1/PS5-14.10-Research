# External sources consulted

- https://cgit.freebsd.org/src/tree/sys/kern/kern_sysctl.c — FreeBSD sysctl implementation; source tree for sysctl handlers and copyout paths.
- https://cgit.freebsd.org/src/tree/sys/kern/syscalls.master — FreeBSD syscall master table; reference for standard syscall names/numbers (current tree, not an exact PS5 r230171 checkout).
- https://cgit.freebsd.org/src/tree/sys/kern/kern_descrip.c — FreeBSD descriptor/fstat implementation; fd metadata is exported through controlled structures rather than raw kernel pointers.
- https://github.com/freebsd/freebsd-src/blob/main/sys/netinet/ip_input.c — `ip_input()` validates packet length/checksum, processes `ip_dooptions()`, calls `ip_reass()` for fragments, then dispatches to protocol input.
- https://cgit.freebsd.org/src/tree/sys/vm/vm_meter.c — VM counters are exposed as scalar/opaque sysctls. Relevant counters include free/active/inactive pages, faults, context switches, traps and syscalls; these are values, not pointers.
- https://man.freebsd.org/cgi/man.cgi?query=sysctl&sektion=8&manpath=FreeBSD+14.0-RELEASE — sysctl read/write privilege model and documented writable/read-only baseline. PS5 restrictions are stricter than stock FreeBSD.

Caveat: public sources above are current FreeBSD source/man pages, not a verified exact checkout of Sony's FreeBSD r230171 fork. Use them for control-flow and structure expectations, then validate every layout/permission assumption against the PS5 dump and logs.
