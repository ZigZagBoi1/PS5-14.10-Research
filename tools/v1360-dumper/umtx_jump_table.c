#include <ps5/kernel.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECEIVER_IP "10.0.0.231"
#define RECEIVER_PORT 8889
#define TABLE_RVA 0x14c0728ULL

static const uint8_t expected_text[16] = {
    0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec,
    0x18, 0x48, 0x8d, 0x1d, 0xf0, 0xc2, 0x91, 0x03
};

int main(void) {
    uint64_t base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    uint32_t fw = kernel_get_fw_version();
    uint8_t observed_text[16] = {0};
    uint8_t table[16] = {0};
    int sig_read = -1, table_read = -1;
    int sig_match = 0;

    if ((base >> 48) == 0xffff && (base & 0x3fff) == 0) {
        sig_read = kernel_copyout((intptr_t)(base + 0x10), observed_text, sizeof(observed_text));
        if (sig_read == 0 && memcmp(expected_text, observed_text, sizeof(expected_text)) == 0) {
            sig_match = 1;
            table_read = kernel_copyout((intptr_t)(base + TABLE_RVA), table, sizeof(table));
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(RECEIVER_PORT);
    if (inet_pton(AF_INET, RECEIVER_IP, &dst.sin_addr) != 1 ||
        connect(sock, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        close(sock);
        return 2;
    }
    char line[256];
    int n = snprintf(line, sizeof(line),
        "UMTX_TABLE_V1 fw=%08x base=%016llx sig_read=%d sig_match=%d table_read=%d table=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        fw, (unsigned long long)base, sig_read, sig_match, table_read,
        table[0], table[1], table[2], table[3], table[4], table[5], table[6], table[7],
        table[8], table[9], table[10], table[11], table[12], table[13], table[14], table[15]);
    if (n > 0 && n < (int)sizeof(line)) write(sock, line, (size_t)n);
    close(sock);
    return 0;
}
