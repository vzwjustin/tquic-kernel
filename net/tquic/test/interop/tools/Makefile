# SPDX-License-Identifier: GPL-2.0
#
# Makefile for TQUIC interoperability test tools

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g
LDFLAGS ?= -lpthread

TARGETS = tquic_test_server tquic_test_client

.PHONY: all clean install

all: $(TARGETS)

tquic_test_server: tquic_test_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

tquic_test_client: tquic_test_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

install: $(TARGETS)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGETS) $(DESTDIR)/usr/local/bin/

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean all

# Address sanitizer build
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address
asan: clean all
