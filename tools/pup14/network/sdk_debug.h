#ifndef __DEBUG_H__
#include "research_net.h"
#define __DEBUG_H__


#define printfsocket(format, ...)\
do {\
  char __printfsocket_buffer[512];\
  int __printfsocket_size = f_snprintf(__printfsocket_buffer, sizeof(__printfsocket_buffer), format, ##__VA_ARGS__);\
  if (__printfsocket_size > 0) research_net_log(__printfsocket_buffer, __printfsocket_size);\
} while(0)


#include "time.h"

void notify(char* message);
unsigned char GetElapsed(unsigned long ResetInterval);

extern int sock;

extern time_t prevtime;

#define SSIZET_FMT "%zd"

#endif
