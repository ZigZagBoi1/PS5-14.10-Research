/* Minimal Relapse elfldr startup check. No PUP, storage, or network access. */
static long raw_syscall3(long number, long a, long b, long c) {
    unsigned char carry;
    __asm__ volatile("syscall; setc %1" : "+a"(number), "=qm"(carry)
                     : "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory", "cc");
    return carry ? -1 : number;
}

void _start(void) {
    static const char message[] = "PUP14 ENTRY OK\n";
    static const char path[] = "/data/pup14-entry-20261020.txt";
    long fd = raw_syscall3(5, (long)path, 0x601, 0644);
    if (fd >= 0) {
        raw_syscall3(4, fd, (long)message, sizeof(message) - 1);
        raw_syscall3(6, fd, 0, 0);
    }
    raw_syscall3(4, 1, (long)message, sizeof(message) - 1);
    raw_syscall3(1, 0, 0, 0);
    for (;;) {}
}
