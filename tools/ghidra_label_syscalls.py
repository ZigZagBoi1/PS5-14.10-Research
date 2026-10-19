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

# FreeBSD syscall number-to-name mapping, generated from the committed 13.60
# sysent capture (docs/sysent-names-13.60.csv). Do not hand-edit: regenerate
# with `python tools/gen_syscall_labels.py`, verify with `--check`.
# The previous hand list was a compacted FreeBSD-9 sequence that dropped
# unimplemented slots without renumbering, so its entries drifted by up to
# sixteen numbers (it claimed 429 = jail_attach where the table says sigwait).
SYSCALL_NAMES = {
# BEGIN GENERATED SYSCALL_NAMES
    0: "syscall",
    1: "exit",
    2: "fork",
    3: "read",
    4: "write",
    5: "open",
    6: "close",
    7: "wait4",
    8: "compat_creat",
    9: "link",
    10: "unlink",
    11: "obs_execv",
    12: "chdir",
    13: "fchdir",
    14: "mknod",
    15: "chmod",
    16: "chown",
    18: "compat4_getfsstat",
    19: "compat_lseek",
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
    38: "compat_stat",
    39: "getppid",
    40: "compat_lstat",
    41: "dup",
    42: "compat10_pipe",
    43: "getegid",
    44: "profil",
    45: "ktrace",
    46: "compat_sigaction",
    47: "getgid",
    48: "compat_sigprocmask",
    49: "getlogin",
    50: "setlogin",
    52: "compat_sigpending",
    53: "sigaltstack",
    54: "ioctl",
    55: "reboot",
    56: "revoke",
    57: "symlink",
    58: "readlink",
    59: "execve",
    60: "umask",
    61: "chroot",
    62: "compat_fstat",
    63: "compat_getkerninfo",
    64: "compat_getpagesize",
    65: "msync",
    66: "vfork",
    67: "obs_vread",
    68: "obs_vwrite",
    69: "sbrk",
    70: "sstk",
    71: "compat_mmap",
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
    84: "compat_wait",
    85: "swapon",
    86: "getitimer",
    87: "compat_gethostname",
    88: "compat_sethostname",
    89: "getdtablesize",
    90: "dup2",
    92: "fcntl",
    93: "select",
    95: "fsync",
    96: "setpriority",
    97: "socket",
    98: "connect",
    99: "netcontrol",
    100: "getpriority",
    101: "netabort",
    102: "netgetsockinfo",
    103: "compat_sigreturn",
    104: "bind",
    105: "setsockopt",
    106: "listen",
    107: "obs_vtimes",
    108: "compat_sigvec",
    109: "compat_sigblock",
    110: "compat_sigsetmask",
    111: "compat_sigsuspend",
    112: "compat_sigstack",
    113: "socketex",
    114: "socketclose",
    115: "obs_vtrace",
    116: "gettimeofday",
    117: "getrusage",
    118: "getsockopt",
    120: "readv",
    121: "writev",
    122: "settimeofday",
    123: "fchown",
    124: "fchmod",
    125: "netgetiflist",
    126: "setreuid",
    127: "setregid",
    128: "rename",
    129: "compat_truncate",
    130: "compat_ftruncate",
    131: "flock",
    132: "mkfifo",
    133: "sendto",
    134: "shutdown",
    135: "socketpair",
    136: "mkdir",
    137: "rmdir",
    138: "utimes",
    139: "obs_4_2",
    140: "adjtime",
    141: "kqueueex",
    142: "compat_gethostid",
    143: "compat_sethostid",
    144: "compat_getrlimit",
    145: "compat_setrlimit",
    146: "compat_killpg",
    147: "setsid",
    149: "compat_quota",
    150: "compat_getsockname",
    154: "nlm_syscall",
    155: "nfssvc",
    156: "compat_getdirentries",
    157: "compat4_statfs",
    158: "compat4_fstatfs",
    162: "compat4_getdomainname",
    163: "compat4_setdomainname",
    164: "compat4_uname",
    165: "sysarch",
    166: "rtprio",
    169: "semsys",
    170: "msgsys",
    171: "shmsys",
    173: "compat6_pread",
    174: "compat6_pwrite",
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
    197: "compat6_mmap",
    198: "__syscall",
    199: "compat6_lseek",
    200: "compat6_truncate",
    201: "compat6_ftruncate",
    202: "__sysctl",
    203: "mlock",
    204: "munlock",
    206: "futimes",
    207: "getpgid",
    209: "poll",
    210: "lkmnosys",
    211: "lkmnosys",
    212: "lkmnosys",
    213: "lkmnosys",
    214: "lkmnosys",
    215: "lkmnosys",
    216: "lkmnosys",
    217: "lkmnosys",
    218: "lkmnosys",
    219: "lkmnosys",
    220: "compat7___semctl",
    221: "semget",
    222: "semop",
    224: "compat7_msgctl",
    225: "msgget",
    226: "msgsnd",
    227: "msgrcv",
    228: "shmat",
    229: "compat7_shmctl",
    230: "shmdt",
    231: "shmget",
    232: "clock_gettime",
    233: "clock_settime",
    234: "clock_getres",
    235: "ktimer_create",
    236: "ktimer_delete",
    237: "ktimer_settime",
    238: "ktimer_gettime",
    239: "ktimer_getoverrun",
    240: "nanosleep",
    241: "ffclock_getcounter",
    242: "ffclock_setestimate",
    243: "ffclock_getestimate",
    247: "clock_getcpuclockid2",
    250: "minherit",
    251: "rfork",
    253: "issetugid",
    254: "lchown",
    255: "aio_read",
    256: "aio_write",
    272: "getdents",
    274: "lchmod",
    275: "netbsd_lchown",
    276: "lutimes",
    277: "netbsd_msync",
    289: "preadv",
    290: "pwritev",
    297: "compat4_fhstatfs",
    304: "kldload",
    305: "kldunload",
    306: "kldfind",
    307: "kldnext",
    308: "kldstat",
    309: "kldfirstmod",
    310: "getsid",
    311: "setresuid",
    312: "setresgid",
    313: "obs_signanosleep",
    314: "aio_return",
    315: "aio_suspend",
    316: "aio_cancel",
    317: "aio_error",
    318: "compat6_aio_read",
    319: "compat6_aio_write",
    320: "compat6_lio_listio",
    321: "yield",
    322: "obs_thr_sleep",
    323: "obs_thr_wakeup",
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
    336: "compat4_sendfile",
    337: "kldsym",
    339: "nnpfs_syscall",
    340: "sigprocmask",
    341: "sigsuspend",
    342: "compat4_sigaction",
    343: "sigpending",
    344: "compat4_sigreturn",
    345: "sigtimedwait",
    346: "sigwaitinfo",
    359: "aio_waitcomplete",
    360: "getresuid",
    361: "getresgid",
    362: "kqueue",
    363: "kevent",
    374: "__setugid",
    377: "afs3_syscall",
    378: "nmount",
    379: "mtypeprotect",
    384: "__mac_get_proc",
    385: "__mac_set_proc",
    386: "__mac_get_fd",
    387: "__mac_get_file",
    388: "__mac_set_fd",
    389: "__mac_set_file",
    390: "kenv",
    391: "lchflags",
    392: "uuidgen",
    393: "sendfile",
    394: "mac_syscall",
    395: "getfsstat",
    396: "statfs",
    397: "fstatfs",
    400: "ksem_close",
    401: "ksem_post",
    402: "ksem_wait",
    403: "ksem_trywait",
    404: "ksem_init",
    405: "ksem_open",
    406: "ksem_unlink",
    407: "ksem_getvalue",
    408: "ksem_destroy",
    409: "__mac_get_pid",
    410: "__mac_get_link",
    411: "__mac_set_link",
    415: "__mac_execve",
    416: "sigaction",
    417: "sigreturn",
    421: "getcontext",
    422: "setcontext",
    423: "swapcontext",
    429: "sigwait",
    430: "thr_create",
    431: "thr_exit",
    432: "thr_self",
    433: "thr_kill",
    441: "ksem_timedwait",
    442: "thr_suspend",
    443: "thr_wake",
    444: "kldunloadf",
    454: "_umtx_op",
    455: "thr_new",
    456: "sigqueue",
    457: "kmq_open",
    458: "kmq_setattr",
    459: "kmq_timedreceive",
    460: "kmq_timedsend",
    461: "kmq_notify",
    462: "kmq_unlink",
    464: "thr_set_name",
    465: "aio_fsync",
    466: "rtprio_thread",
    475: "pread",
    476: "pwrite",
    477: "mmap",
    478: "lseek",
    479: "truncate",
    480: "ftruncate",
    481: "thr_kill2",
    482: "shm_open",
    483: "shm_unlink",
    484: "cpuset",
    485: "cpuset_setid",
    486: "cpuset_getid",
    487: "cpuset_getaffinity",
    488: "cpuset_setaffinity",
    490: "fchmodat",
    491: "fchownat",
    493: "fstatat",
    494: "futimesat",
    495: "linkat",
    496: "mkdirat",
    497: "mkfifoat",
    498: "mknodat",
    499: "openat",
    501: "renameat",
    502: "symlinkat",
    503: "unlinkat",
    505: "gssd_syscall",
    510: "__semctl",
    511: "msgctl",
    512: "shmctl",
    514: "obs_cap_new",
    515: "__cap_rights_get",
    516: "cap_enter",
    517: "cap_getmode",
    519: "pdkill",
    520: "pdgetpid",
    522: "pselect",
    525: "rctl_get_racct",
    526: "rctl_get_rules",
    527: "rctl_get_limits",
    528: "rctl_add_rule",
    529: "rctl_remove_rule",
# END GENERATED SYSCALL_NAMES
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
