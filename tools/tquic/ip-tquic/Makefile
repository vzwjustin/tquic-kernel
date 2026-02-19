# SPDX-License-Identifier: GPL-2.0-only
# Makefile for ip-tquic - iproute2-compatible TQUIC management tool

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS  += -I../../../include/uapi

TARGET  := ip-tquic

.PHONY: all clean install

all: $(TARGET)

$(TARGET): iptquic.c
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET)
	install -D -m 755 $(TARGET) $(DESTDIR)/usr/lib/iproute2/ip-tquic
	install -D -m 755 $(TARGET) $(DESTDIR)/usr/sbin/ip-tquic

clean:
	rm -f $(TARGET)
