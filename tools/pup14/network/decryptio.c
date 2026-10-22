#include "resolve.h"
#include "decryptio.h"
#include "research_net.h"

#define CHUNK (2U * 1024U * 1024U)
static uint64_t input_pos = 0;
static uint64_t output_pos = 0;

int research_has_output(const decrypt_state *state, size_t offset, size_t bytes) {
  uint64_t pos = offset == DIO_BASEOFFSET ? state->output_base_offset :
                 offset == DIO_NOSEEK ? output_pos : state->output_base_offset + offset;
  int entry = state->entryname[9] == '1' ? 1 : 2;
  if (!research_net_resuming(entry)) return 0;
  size_t done = 0;
  while (done < bytes) {
    uint32_t n = bytes - done > CHUNK ? CHUNK : (uint32_t)(bytes - done);
    int found = research_net_has_range(entry, pos + done, n);
    if (found != 1) return found;
    done += n;
  }
  return 1;
}

void research_advance_io(const decrypt_state *state, size_t offset, size_t bytes) {
  if (offset == DIO_RESET) input_pos = output_pos = 0;
  else if (offset == DIO_BASEOFFSET) {
    input_pos = state->input_base_offset + bytes;
    output_pos = state->output_base_offset + bytes;
  } else if (offset == DIO_NOSEEK) {
    input_pos += bytes;
    output_pos += bytes;
  } else {
    input_pos = state->input_base_offset + offset + bytes;
    output_pos = state->output_base_offset + offset + bytes;
  }
}

ssize_t readbytes(const decrypt_state *state, size_t offset, size_t bytes,
                  void *buffer, size_t buffersize) {
  if (bytes > buffersize || !buffer) return -1;
  if (offset == DIO_RESET) input_pos = 0;
  else if (offset == DIO_BASEOFFSET) input_pos = state->input_base_offset;
  else if (offset != DIO_NOSEEK) input_pos = state->input_base_offset + offset;
  size_t done = 0;
  while (done < bytes) {
    uint32_t n = bytes - done > CHUNK ? CHUNK : (uint32_t)(bytes - done);
    if (research_net_read(input_pos, n, (unsigned char *)buffer + done) != 0) return -1;
    input_pos += n;
    done += n;
  }
  return (ssize_t)done;
}

ssize_t writebytes(const decrypt_state *state, size_t offset, size_t bytes,
                   void *buffer, size_t buffersize) {
  if (bytes > buffersize || !buffer) return -1;
  if (offset == DIO_RESET) output_pos = 0;
  else if (offset == DIO_BASEOFFSET) output_pos = state->output_base_offset;
  else if (offset != DIO_NOSEEK) output_pos = state->output_base_offset + offset;
  size_t done = 0;
  while (done < bytes) {
    uint32_t n = bytes - done > CHUNK ? CHUNK : (uint32_t)(bytes - done);
    if (research_net_write(state->entryname[9] == '1' ? 1 : 2, output_pos,
                           n, (unsigned char *)buffer + done) != 0) return -1;
    output_pos += n;
    done += n;
  }
  return (ssize_t)done;
}
