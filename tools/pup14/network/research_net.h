#ifndef RESEARCH_NET_H
#define RESEARCH_NET_H

#include <stddef.h>
#include <stdint.h>

#define RESEARCH_VIRTUAL_FD 0x71717171

int research_net_connect(void);
void research_net_close(void);
int research_net_read(uint64_t offset, uint32_t length, void *buffer);
int research_net_write(int entry, uint64_t offset, uint32_t length, const void *buffer);
int research_net_begin(int entry);
int research_net_has_range(int entry, uint64_t offset, uint32_t length);
int research_net_resuming(int entry);
void research_net_log(const char *message, uint32_t length);
void research_net_finish(int success);

#endif
