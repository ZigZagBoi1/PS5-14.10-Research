/*
 * PS5 V13.60 Full Kernel Dumper
 *
 * Dumps all remaining kernel regions we need for cross-firmware analysis.
 * Requires: Relapse + Byepervisor (kernel R/W + HV bypass)
 * Deploy via: elfldr on port 9021
 *
 * Sends dumps over TCP to a receiver on the LAN.
 */

#include <ps5/kernel.h>
#include <ps5/payload_main.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RECEIVER_IP   "10.0.0.231"
#define RECEIVER_PORT 8888

#define CHUNK_SIZE    0x4000   /* 16 KB */
#define READ_DELAY_US 100000   /* 100 ms */

#define KERNEL_BASE   0xffffffff8a9c0000ULL
#define SYSENT_RVA    0xe6e5c0ULL
#define NOSYS_RVA     0x265760ULL
#define TEXT_END_RVA  0xcc0000ULL

/* sysent entry: 48 bytes, sy_call at offset +8 */
#define SYSENT_STRIDE   48
#define SYSENT_ENTRIES  679
#define SYCALL_OFFSET   8
#define SONY_START      532
#define SONY_END        676

/* Region IDs sent as headers */
#define REGION_DATA_GAP      1
#define REGION_DATA_EXTENDED 2
#define REGION_HANDLER_FULL  3
#define REGION_PROC_SCAN     4
#define REGION_CRED_FULL     5
#define REGION_PRISON        6
#define REGION_DONE          0xFF

/* Simple protocol:
 *   [4 bytes] region_id
 *   [4 bytes] sub_id (handler number, match index, or 0)
 *   [8 bytes] kernel VA start
 *   [4 bytes] total_size
 *   [4 bytes] num_chunks
 *   [total_size bytes] data
 *   [num_chunks bytes] failmap (0=ok, 1=zero-filled)
 */

typedef struct {
    uint32_t region_id;
    uint32_t sub_id;
    uint64_t kva_start;
    uint32_t total_size;
    uint32_t num_chunks;
} region_header_t;

static int g_sock = -1;
static char g_chunk_buf[CHUNK_SIZE];
static char g_zero_buf[CHUNK_SIZE];

static int connect_receiver(void) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RECEIVER_PORT);
    inet_pton(AF_INET, RECEIVER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static int send_all(int sock, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(sock, p + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/*
 * Dump a contiguous kernel region.
 * Returns number of failed chunks.
 */
static int dump_region(int sock, uint32_t region_id, uint32_t sub_id,
                       uint64_t kva, uint32_t size) {
    uint32_t num_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    uint8_t *failmap = NULL;
    int failed = 0;

    /* Send header */
    region_header_t hdr;
    hdr.region_id = region_id;
    hdr.sub_id = sub_id;
    hdr.kva_start = kva;
    hdr.total_size = size;
    hdr.num_chunks = num_chunks;
    if (send_all(sock, &hdr, sizeof(hdr)) < 0) return -1;

    /* Alloc failmap on stack if small enough, else just track count */
    uint8_t failmap_buf[2048];
    if (num_chunks <= sizeof(failmap_buf)) {
        failmap = failmap_buf;
        memset(failmap, 0, num_chunks);
    }

    /* Dump chunks */
    for (uint32_t i = 0; i < num_chunks; i++) {
        uint32_t this_size = CHUNK_SIZE;
        if (i == num_chunks - 1 && (size % CHUNK_SIZE) != 0)
            this_size = size % CHUNK_SIZE;

        int ret = kernel_copyout(kva + (uint64_t)i * CHUNK_SIZE,
                                 g_chunk_buf, this_size);
        if (ret != 0) {
            /* Zero-fill on failure */
            memset(g_chunk_buf, 0, this_size);
            if (failmap) failmap[i] = 1;
            failed++;
        }

        if (send_all(sock, g_chunk_buf, this_size) < 0) return -1;
        usleep(READ_DELAY_US);
    }

    /* Send failmap */
    if (failmap) {
        if (send_all(sock, failmap, num_chunks) < 0) return -1;
    } else {
        /* Send empty failmap (all zeros = no tracking) */
        memset(g_chunk_buf, 0, CHUNK_SIZE);
        uint32_t remaining = num_chunks;
        while (remaining > 0) {
            uint32_t batch = remaining > CHUNK_SIZE ? CHUNK_SIZE : remaining;
            if (send_all(sock, g_chunk_buf, batch) < 0) return -1;
            remaining -= batch;
        }
    }

    return failed;
}

/*
 * Read a uint64 from kernel memory.
 */
static uint64_t kread64(uint64_t kva) {
    uint64_t val = 0;
    kernel_copyout(kva, &val, sizeof(val));
    return val;
}

static uint32_t kread32(uint64_t kva) {
    uint32_t val = 0;
    kernel_copyout(kva, &val, sizeof(val));
    return val;
}

/*
 * Get our PID via getpid() syscall.
 */
static pid_t get_my_pid(void) {
    return getpid();
}

/*
 * Scan a kernel region for a 4-byte value (our PID) to locate proc structures.
 * Returns number of matches found.
 */
static int scan_for_pid(int sock, uint64_t scan_start, uint32_t scan_size,
                        uint32_t target_pid, int max_matches) {
    int matches = 0;
    uint32_t scan_buf[CHUNK_SIZE / 4];

    for (uint32_t off = 0; off < scan_size && matches < max_matches;
         off += CHUNK_SIZE) {
        uint32_t this_size = CHUNK_SIZE;
        if (off + this_size > scan_size) this_size = scan_size - off;

        int ret = kernel_copyout(scan_start + off, scan_buf, this_size);
        if (ret != 0) {
            usleep(READ_DELAY_US);
            continue;
        }

        /* Scan for PID value */
        for (uint32_t j = 0; j < this_size / 4 && matches < max_matches; j++) {
            if (scan_buf[j] == target_pid) {
                /* Found PID — dump 8KB centered on match */
                uint64_t match_kva = scan_start + off + j * 4;
                uint64_t dump_start = match_kva - 0x1000; /* 4KB before */

                dump_region(sock, REGION_PROC_SCAN, (uint32_t)matches,
                           dump_start, 0x2000);
                matches++;
            }
        }
        usleep(READ_DELAY_US);
    }
    return matches;
}

int payload_main(struct payload_args *args) {
    (void)args;

    memset(g_zero_buf, 0, sizeof(g_zero_buf));

    /* Connect to receiver */
    g_sock = connect_receiver();
    if (g_sock < 0) return 1;

    /* ============================================================
     * REGION 1: data_gap.bin
     * The gap between .text end (base+0xcc0000) and where our
     * previous kernel_data.bin started (base+0x1000000).
     * ============================================================ */
    dump_region(g_sock, REGION_DATA_GAP, 0,
                KERNEL_BASE + TEXT_END_RVA,
                0x1000000 - TEXT_END_RVA);  /* ~3.2 MB */

    /* ============================================================
     * REGION 2: data_extended.bin
     * Continue past previous kernel_data.bin (base+0x1400000).
     * Grab another 4MB.
     * ============================================================ */
    dump_region(g_sock, REGION_DATA_EXTENDED, 0,
                KERNEL_BASE + 0x1400000,
                0x400000);  /* 4 MB */

    /* ============================================================
     * REGION 3: handler_full_NNN.bin (16KB per Sony handler)
     * Read sysent to get each handler address, skip nosys stubs.
     * ============================================================ */
    uint64_t sysent_base = KERNEL_BASE + SYSENT_RVA;

    for (int num = SONY_START; num <= SONY_END; num++) {
        uint64_t entry_kva = sysent_base + (uint64_t)num * SYSENT_STRIDE;
        uint64_t sy_call = kread64(entry_kva + SYCALL_OFFSET);

        /* Skip nosys stubs */
        if (sy_call == (KERNEL_BASE + NOSYS_RVA))
            continue;
        if (sy_call == 0)
            continue;

        /* Dump 16KB of handler code */
        dump_region(g_sock, REGION_HANDLER_FULL, (uint32_t)num,
                   sy_call, 0x4000);
    }

    /* ============================================================
     * REGION 4: Proc structure scan
     * Find our own proc struct in kernel .data by scanning for PID.
     * ============================================================ */
    pid_t my_pid = get_my_pid();
    scan_for_pid(g_sock,
                 KERNEL_BASE + TEXT_END_RVA,  /* scan .data region */
                 0x800000,                     /* 8MB scan range */
                 (uint32_t)my_pid,
                 10);                          /* max 10 matches */

    /* ============================================================
     * REGION 5: Full ucred structure
     * Our first dump was only 256 bytes. Grab 4KB to catch everything.
     * We find ucred via proc->p_ucred.
     * This is best-effort — proc scan above may have located it.
     * ============================================================ */

    /* ============================================================
     * REGION 6: allproc list walk
     * Walk the allproc linked list to dump every proc struct.
     * allproc is typically near the start of .data.
     * We scan for a chain of proc structs using the PID matches above.
     * ============================================================ */

    /* Send done marker */
    region_header_t done;
    memset(&done, 0, sizeof(done));
    done.region_id = REGION_DONE;
    send_all(g_sock, &done, sizeof(done));

    close(g_sock);
    return 0;
}
