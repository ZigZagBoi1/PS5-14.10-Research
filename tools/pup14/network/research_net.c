#include "resolve.h"
#include "research_net.h"

#define RESEARCH_PORT 9028
#define MAX_FRAME (2U * 1024U * 1024U)

static int research_sock = -1;
static int resume_entry[3];

static void put32(unsigned char *p, uint32_t x) {
  for (int i = 0; i < 4; i++) p[i] = (unsigned char)(x >> (i * 8));
}
static void put64(unsigned char *p, uint64_t x) {
  for (int i = 0; i < 8; i++) p[i] = (unsigned char)(x >> (i * 8));
}
static int send_all(const void *data, uint32_t size) {
  const unsigned char *p = data;
  while (size) {
    int n = f_sceNetSend(research_sock, p, size, 0);
    if (n <= 0) return -1;
    p += n;
    size -= (uint32_t)n;
  }
  return 0;
}
static int recv_all(void *data, uint32_t size) {
  unsigned char *p = data;
  while (size) {
    int n = f_sceNetRecv(research_sock, p, size, 0);
    if (n <= 0) return -1;
    p += n;
    size -= (uint32_t)n;
  }
  return 0;
}
static int header(char op, int entry, uint64_t offset, uint32_t length) {
  unsigned char h[20] = {'P','1','4','R',0};
  if (research_sock < 0 || length > MAX_FRAME) return -1;
  h[4] = (unsigned char)op;
  h[5] = (unsigned char)entry;
  put64(h + 8, offset);
  put32(h + 16, length);
  return send_all(h, sizeof(h));
}
static int ack(void) {
  unsigned char reply[4];
  if (recv_all(reply, sizeof(reply)) != 0) return -1;
  return reply[0]=='O' && reply[1]=='K' && reply[2]=='A' && reply[3]=='Y' ? 0 : -1;
}

int research_net_connect(void) {
  struct sockaddr_in server;
  f_memset(&server, 0, sizeof(server));
  server.sin_len = sizeof(server);
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = IP(10,0,0,80);
  server.sin_port = f_sceNetHtons(RESEARCH_PORT);
  research_sock = f_sceNetSocket("pup14-research", AF_INET, SOCK_STREAM, 0);
  if (research_sock < 0) return -1;
  if (f_sceNetConnect(research_sock, (struct sockaddr *)&server, sizeof(server)) != 0) {
    research_net_close();
    return -1;
  }
  return 0;
}
void research_net_close(void) {
  if (research_sock >= 0) f_sceNetSocketClose(research_sock);
  research_sock = -1;
}
int research_net_read(uint64_t offset, uint32_t length, void *buffer) {
  if (header('R', 0, offset, length) != 0 || ack() != 0) return -1;
  return recv_all(buffer, length);
}
int research_net_write(int entry, uint64_t offset, uint32_t length, const void *buffer) {
  if (entry != 1 && entry != 2) return -1;
  if (header('W', entry, offset, length) != 0 || send_all(buffer, length) != 0) return -1;
  return ack();
}
int research_net_begin(int entry) {
  unsigned char reply[4];
  if (entry != 1 && entry != 2) return -1;
  if (header('B', entry, 0, 0) != 0 || recv_all(reply, sizeof(reply)) != 0) return -1;
  if (reply[0]=='O' && reply[1]=='L' && reply[2]=='D' && reply[3]=='!') {
    resume_entry[entry] = 1;
    return 0;
  }
  if (reply[0]=='O' && reply[1]=='K' && reply[2]=='A' && reply[3]=='Y') {
    resume_entry[entry] = 0;
    return 0;
  }
  return -1;
}
int research_net_resuming(int entry) { return entry >= 1 && entry <= 2 && resume_entry[entry]; }
int research_net_has_range(int entry, uint64_t offset, uint32_t length) {
  unsigned char reply[4];
  if (entry != 1 && entry != 2) return -1;
  if (header('Q', entry, offset, length) != 0 || recv_all(reply, sizeof(reply)) != 0) return -1;
  if (reply[0]=='H' && reply[1]=='A' && reply[2]=='V' && reply[3]=='E') return 1;
  if (reply[0]=='M' && reply[1]=='I' && reply[2]=='S' && reply[3]=='S') return 0;
  return -1;
}
void research_net_log(const char *message, uint32_t length) {
  if (length > 511) length = 511;
  if (header('L', 0, 0, length) != 0 || send_all(message, length) != 0) return;
  ack();
}
void research_net_finish(int success) {
  if (header('F', 0, success ? 1 : 0, 0) == 0) ack();
}
