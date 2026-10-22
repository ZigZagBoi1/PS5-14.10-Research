/* Loader check for the installed PS5 Payload SDK. No PUP/update access. */
#include <stdio.h>
#include <string.h>

typedef struct notify_request {
  char reserved[45];
  char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

int main(void) {
  static const char marker[] = "PUP14 SDK ENTRY OK\n";
  FILE *file = fopen("/data/pup14-sdk-entry-20261020.txt", "wb");
  if (file) {
    fwrite(marker, 1, sizeof(marker) - 1, file);
    fclose(file);
  }
  notify_request_t notification;
  memset(&notification, 0, sizeof(notification));
  strncpy(notification.message, file ? "PUP14 SDK entry reached" : "PUP14 SDK entry: file failed",
          sizeof(notification.message) - 1);
  return sceKernelSendNotificationRequest(0, &notification, sizeof(notification), 0);
}
