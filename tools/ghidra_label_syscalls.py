# Ghidra script: Label PS5 13.60 kernel syscall handlers from sysent_index.json
# Usage: Run in Ghidra's Script Manager (Jython). Place sysent_index.json next to the script
#        or set SYSENT_JSON below. The kernel ELF must already be loaded in Ghidra.
#
# What it does:
#   - Labels every syscall handler function (sys_read, sys_write, sony_syscall_NNN, nosys, etc.)
#   - Sets plate comments with argument count and syscall number
#   - Creates a "Syscalls" namespace for all labels
#   - Marks nosys stubs with a NOSYS prefix
#
# @category PS5
# @author ZigZagBoi1

import json
import os

# ---- Configuration ----
# Path to sysent_index.json. If empty, looks next to this script.
SYSENT_JSON = ""

# Kernel base used when the JSON was captured. If the Ghidra image base differs,
# addresses are rebased automatically.
JSON_KERNEL_BASE = 0xffffffff8a9c0000

# The nosys stub RVA (relative to kernel base)
NOSYS_RVA = 0x265760

# FreeBSD syscall number-to-name mapping (r230171 / FreeBSD 9-era sysent)
# Sources: sys/kern/syscalls.c, sys/compat/freebsd32/syscalls.master
SYSCALL_NAMES = {
    0: "nosys",          # syscall (indirect)
    1: "sys_exit",
    2: "fork",
    3: "read",
    4: "write",
    5: "open",
    6: "close",
    7: "wait4",
    8: "old_creat",      # obsolete
    9: "link",
    10: "unlink",
    11: "obs_execv",
    12: "chdir",
    13: "fchdir",
    14: "mknod",
    15: "chmod",
    16: "chown",
    17: "break",
    18: "freebsd4_getfsstat",
    19: "old_lseek",
    20: "getpid",
    21: "mount",
    22: "unmount",
    23: "setuid",
    24: "getuid",
    25: "geteuid",
    26: "ptrace",
    27: "recvmsg",
    28: "sendmsg",
    29: "recvfrom",
    30: "accept",
    31: "getpeername",
    32: "getsockname",
    33: "access",
    34: "chflags",
    35: "fchflags",
    36: "sync",
    37: "kill",
    38: "old_stat",
    39: "getppid",
    40: "old_lstat",
    41: "dup",
    42: "pipe",
    43: "getegid",
    44: "profil",
    45: "ktrace",
    46: "old_sigaction",
    47: "getgid",
    48: "old_sigprocmask",
    49: "getlogin",
    50: "setlogin",
    51: "acct",
    52: "old_sigpending",
    53: "sigaltstack",
    54: "ioctl",
    55: "reboot",
    56: "revoke",
    57: "symlink",
    58: "readlink",
    59: "execve",
    60: "umask",
    61: "chroot",
    62: "old_fstat",
    63: "old_getkerninfo",
    64: "old_getpagesize",
    65: "msync",
    66: "vfork",
    67: "obs_vread",
    68: "obs_vwrite",
    69: "sbrk",
    70: "sstk",
    71: "old_mmap",
    72: "vadvise",
    73: "munmap",
    74: "mprotect",
    75: "madvise",
    76: "obs_vhangup",
    77: "obs_vlimit",
    78: "mincore",
    79: "getgroups",
    80: "setgroups",
    81: "getpgrp",
    82: "setpgid",
    83: "setitimer",
    84: "old_wait",
    85: "swapon",
    86: "getitimer",
    87: "old_gethostname",
    88: "old_sethostname",
    89: "getdtablesize",
    90: "dup2",
    92: "fcntl",
    93: "select",
    95: "fsync",
    96: "setpriority",
    97: "socket",
    98: "connect",
    99: "old_accept",
    100: "getpriority",
    101: "old_send",
    102: "old_recv",
    103: "old_sigreturn",
    104: "bind",
    105: "setsockopt",
    106: "listen",
    107: "obs_vtimes",
    108: "old_sigvec",
    109: "old_sigblock",
    110: "old_sigsetmask",
    111: "old_sigsuspend",
    112: "old_sigstack",
    113: "old_recvmsg",
    114: "old_sendmsg",
    115: "obs_vtrace",
    116: "gettimeofday",
    117: "getrusage",
    118: "getsockopt",
    120: "readv",
    121: "writev",
    122: "settimeofday",
    123: "fchown",
    124: "fchmod",
    125: "old_recvfrom",
    126: "setreuid",
    127: "setregid",
    128: "rename",
    129: "old_truncate",
    130: "old_ftruncate",
    131: "flock",
    132: "mkfifo",
    133: "sendto",
    134: "shutdown",
    135: "socketpair",
    136: "mkdir",
    137: "rmdir",
    138: "utimes",
    139: "obs_4_2_sigreturn",
    140: "adjtime",
    141: "old_getpeername",
    142: "old_gethostid",
    143: "old_sethostid",
    144: "old_getrlimit",
    145: "old_setrlimit",
    146: "old_killpg",
    147: "setsid",
    148: "quotactl",
    149: "old_quota",
    150: "old_getsockname",
    155: "nfssvc",
    156: "old_getdirentries",
    157: "freebsd4_statfs",
    158: "freebsd4_fstatfs",
    160: "lgetfh",
    161: "getfh",
    162: "freebsd4_getdomainname",
    163: "freebsd4_setdomainname",
    164: "freebsd4_uname",
    165: "sysarch",
    166: "rtprio",
    169: "semsys",
    170: "msgsys",
    171: "shmsys",
    173: "freebsd6_pread",
    174: "freebsd6_pwrite",
    175: "setfib",
    176: "ntp_adjtime",
    181: "setgid",
    182: "setegid",
    183: "seteuid",
    188: "stat",
    189: "fstat",
    190: "lstat",
    191: "pathconf",
    192: "fpathconf",
    194: "getrlimit",
    195: "setrlimit",
    196: "getdirentries",
    197: "freebsd6_mmap",
    198: "nosys",          # __syscall
    199: "freebsd6_lseek",
    200: "freebsd6_truncate",
    201: "freebsd6_ftruncate",
    202: "__sysctl",
    203: "mlock",
    204: "munlock",
    205: "undelete",
    206: "futimes",
    207: "getpgid",
    210: "__semctl",
    211: "semget",
    212: "semop",
    214: "msgctl",
    215: "msgget",
    216: "msgsnd",
    217: "msgrcv",
    218: "shmat",
    219: "shmctl",
    220: "shmdt",
    221: "shmget",
    222: "clock_gettime",
    223: "clock_settime",
    224: "clock_getres",
    225: "ktimer_create",
    226: "ktimer_delete",
    227: "ktimer_settime",
    228: "ktimer_gettime",
    229: "ktimer_getoverrun",
    230: "nanosleep",
    231: "ffclock_getcounter",
    232: "ffclock_setestimate",
    233: "ffclock_getestimate",
    234: "clock_nanosleep",
    240: "clock_getcpuclockid2",
    241: "ntp_gettime",
    247: "clock_getcpuclockid2",
    250: "minherit",
    251: "rfork",
    252: "openbsd_poll",
    253: "issetugid",
    254: "lchown",
    272: "getdents",
    274: "lchmod",
    275: "netbsd_lchown",
    276: "lutimes",
    277: "netbsd_msync",
    278: "nstat",
    279: "nfstat",
    280: "nlstat",
    289: "preadv",
    290: "pwritev",
    297: "freebsd4_fhstatfs",
    298: "fhopen",
    299: "fhstat",
    300: "modnext",
    301: "modstat",
    302: "modfnext",
    303: "modfind",
    304: "kldload",
    305: "kldunload",
    306: "kldfind",
    307: "kldnext",
    308: "kldstat",
    309: "kldfirstmod",
    310: "getsid",
    311: "setresuid",
    312: "setresgid",
    314: "aio_return",
    315: "aio_suspend",
    316: "aio_cancel",
    317: "aio_error",
    318: "freebsd6_aio_read",
    319: "freebsd6_aio_write",
    320: "freebsd6_lio_listio",
    321: "yield",
    324: "mlockall",
    325: "munlockall",
    326: "__getcwd",
    327: "sched_setparam",
    328: "sched_getparam",
    329: "sched_setscheduler",
    330: "sched_getscheduler",
    331: "sched_yield",
    332: "sched_get_priority_max",
    333: "sched_get_priority_min",
    334: "sched_rr_get_interval",
    335: "utrace",
    336: "freebsd4_sendfile",
    337: "kldsym",
    338: "jail",
    339: "nnpfs_syscall",
    340: "sigprocmask",
    341: "sigsuspend",
    342: "freebsd4_sigaction",
    343: "sigpending",
    344: "freebsd4_sigreturn",
    345: "sigtimedwait",
    346: "sigwaitinfo",
    347: "__acl_get_file",
    348: "__acl_set_file",
    349: "__acl_get_fd",
    350: "__acl_set_fd",
    351: "__acl_delete_file",
    352: "__acl_delete_fd",
    353: "__acl_aclcheck_file",
    354: "__acl_aclcheck_fd",
    355: "extattrctl",
    356: "extattr_set_file",
    357: "extattr_get_file",
    358: "extattr_delete_file",
    359: "aio_waitcomplete",
    360: "getresuid",
    361: "getresgid",
    362: "kqueue",
    363: "kevent",
    366: "extattr_set_fd",
    367: "extattr_get_fd",
    368: "extattr_delete_fd",
    369: "__setugid",
    371: "eaccess",
    372: "afs3_syscall",
    373: "nmount",
    374: "__mac_get_proc",
    375: "__mac_set_proc",
    376: "__mac_get_fd",
    377: "__mac_get_file",
    378: "__mac_set_fd",
    379: "__mac_set_file",
    380: "kenv",
    381: "lchflags",
    382: "uuidgen",
    383: "sendfile",
    384: "mac_syscall",
    385: "getfsstat",
    386: "statfs",
    387: "fstatfs",
    388: "fhstatfs",
    390: "ksem_close",
    391: "ksem_post",
    392: "ksem_wait",
    393: "ksem_trywait",
    394: "ksem_init",
    395: "ksem_open",
    396: "ksem_unlink",
    397: "ksem_getvalue",
    398: "ksem_destroy",
    399: "__mac_get_pid",
    400: "__mac_get_link",
    401: "__mac_set_link",
    402: "extattr_set_link",
    403: "extattr_get_link",
    404: "extattr_delete_link",
    405: "__mac_execve",
    406: "sigaction",
    407: "sigreturn",
    410: "__mac_get_mount",
    411: "__mac_get_mount",
    416: "getcontext",
    417: "setcontext",
    418: "swapcontext",
    419: "swapoff",
    420: "__acl_get_link",
    421: "__acl_set_link",
    422: "__acl_delete_link",
    423: "__acl_aclcheck_link",
    424: "sigwait",
    425: "thr_create",
    426: "thr_exit",
    427: "thr_self",
    428: "thr_kill",
    429: "jail_attach",
    430: "extattr_list_fd",
    431: "extattr_list_file",
    432: "extattr_list_link",
    433: "ksem_timedwait",
    434: "thr_suspend",
    435: "thr_wake",
    436: "kldunloadf",
    437: "audit",
    438: "auditon",
    439: "getauid",
    440: "setauid",
    441: "getaudit",
    442: "setaudit",
    443: "getaudit_addr",
    444: "setaudit_addr",
    445: "auditctl",
    446: "_umtx_op",
    447: "thr_new",
    448: "sigqueue",
    449: "kmq_open",
    450: "kmq_setattr",
    451: "kmq_timedreceive",
    452: "kmq_timedsend",
    453: "kmq_notify",
    454: "kmq_unlink",
    455: "abort2",
    456: "thr_set_name",
    457: "aio_fsync",
    458: "rtprio_thread",
    461: "sctp_peeloff",
    462: "sctp_generic_sendmsg",
    463: "sctp_generic_sendmsg_iov",
    464: "sctp_generic_recvmsg",
    465: "pread",
    466: "pwrite",
    467: "mmap",
    468: "lseek",
    469: "truncate",
    470: "ftruncate",
    471: "thr_kill2",
    472: "shm_open",
    473: "shm_unlink",
    474: "cpuset",
    475: "cpuset_setid",
    476: "cpuset_getid",
    477: "cpuset_getaffinity",
    478: "cpuset_setaffinity",
    479: "faccessat",
    480: "fchmodat",
    481: "fchownat",
    482: "fexecve",
    483: "fstatat",
    484: "futimesat",
    485: "linkat",
    486: "mkdirat",
    487: "mkfifoat",
    488: "mknodat",
    489: "openat",
    490: "readlinkat",
    491: "renameat",
    492: "symlinkat",
    493: "unlinkat",
    494: "posix_openpt",
    495: "gssd_syscall",
    496: "jail_get",
    497: "jail_set",
    498: "jail_remove",
    499: "closefrom",
    500: "__semctl",
    501: "msgctl",
    502: "shmctl",
    503: "lpathconf",
    504: "obs___cap_rights_get",
    505: "cap_enter",
    506: "cap_getmode",
    507: "pdfork",
    508: "pdkill",
    509: "pdgetpid",
    511: "pselect",
    512: "getloginclass",
    513: "setloginclass",
    514: "rctl_get_racct",
    515: "rctl_get_rules",
    516: "rctl_get_limits",
    517: "rctl_add_rule",
    518: "rctl_remove_rule",
    519: "posix_fallocate",
    520: "posix_fadvise",
    521: "wait6",
    522: "cap_rights_limit",
    523: "cap_ioctls_limit",
    524: "cap_ioctls_get",
    525: "cap_fcntls_limit",
    526: "cap_fcntls_get",
    527: "bindat",
    528: "connectat",
    529: "chflagsat",
    530: "accept4",
    531: "pipe2",
}


def run():
    import ghidra
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import CodeUnit

    program = currentProgram
    listing = program.getListing()
    symTable = program.getSymbolTable()
    space = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()

    # Resolve JSON path
    json_path = SYSENT_JSON
    if not json_path:
        script_dir = os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath()))
        json_path = os.path.join(script_dir, "sysent_index.json")
        if not os.path.exists(json_path):
            # Try docs/dumps_13.60/ relative to project
            json_path = os.path.join(script_dir, "..", "docs", "dumps_13.60", "sysent_index.json")

    if not os.path.exists(json_path):
        printerr("Cannot find sysent_index.json. Set SYSENT_JSON path in script.")
        return

    with open(json_path) as f:
        data = json.load(f)

    json_base = int(data["kernel_base"], 16)
    entries = data["entries"]

    # Ghidra image base
    ghidra_base = program.getImageBase().getOffset()
    rebase = ghidra_base - json_base
    println("JSON kernel base:  0x%x" % json_base)
    println("Ghidra image base: 0x%x" % ghidra_base)
    println("Rebase delta:      0x%x" % rebase)
    println("Entries:           %d" % len(entries))

    nosys_abs = json_base + NOSYS_RVA

    # Create namespace
    ns = symTable.getNamespace("Syscalls", None)
    if ns is None:
        ns = symTable.createNameSpace(None, "Syscalls", SourceType.USER_DEFINED)

    labeled = 0
    nosys_count = 0
    sony_count = 0

    for e in entries:
        num = e["num"]
        narg = e["narg"]
        sy_call = int(e["sy_call"], 16)

        is_nosys = (sy_call == nosys_abs)

        # Determine name
        if is_nosys:
            name = "nosys_%d" % num
            nosys_count += 1
        elif num in SYSCALL_NAMES:
            name = "sys_%s" % SYSCALL_NAMES[num]
        elif 532 <= num <= 676:
            name = "sony_syscall_%d" % num
            sony_count += 1
        else:
            name = "syscall_%d" % num

        # Compute address in Ghidra
        addr = space.getAddress(sy_call + rebase)

        # Create function if none exists
        fn = listing.getFunctionAt(addr)
        if fn is None:
            createFunction(addr, name)
            fn = listing.getFunctionAt(addr)

        # Set label in Syscalls namespace
        try:
            symTable.createLabel(addr, name, ns, SourceType.USER_DEFINED)
        except:
            pass  # label may already exist

        # Set plate comment
        comment = "Syscall #%d | narg=%d" % (num, narg)
        if is_nosys:
            comment += " | NOSYS STUB"
        cu = listing.getCodeUnitAt(addr)
        if cu is not None:
            cu.setComment(CodeUnit.PLATE_COMMENT, comment)

        labeled += 1

    println("")
    println("Done: %d syscalls labeled" % labeled)
    println("  nosys stubs: %d" % nosys_count)
    println("  Sony (532-676): %d" % sony_count)
    println("  Standard FreeBSD: %d" % (labeled - nosys_count - sony_count))


run()
