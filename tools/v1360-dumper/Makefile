# PS5 Full Kernel Dumper — builds with PS5 Payload Dev SDK
#
# Set PS5SDK to your SDK root, e.g.:
#   export PS5SDK=/opt/ps5-payload-dev/sdk
#
# Then: make

ifndef PS5SDK
$(error PS5SDK is not set. Point it at your ps5-payload-dev SDK root.)
endif

CC      := $(PS5SDK)/bin/prospero-clang
CFLAGS  := -target x86_64-sie-ps5 -Os -Wall -Wextra
LDFLAGS := -target x86_64-sie-ps5 -lps5 -lkernel_sys
OBJDIR  := build

ELF     := ps5-final-dumper.elf

SRCS    := main.c
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

all: $(ELF)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(ELF): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -rf $(OBJDIR) $(ELF)

.PHONY: all clean
