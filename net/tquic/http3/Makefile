# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC HTTP/3 support (RFC 9114)
#

# Include paths matching parent net/tquic/Makefile
ccflags-y += -I$(src)/.. -I$(src)/../../.. -I$(src)/../diag -DTQUIC_OUT_OF_TREE
ccflags-y += -Wno-missing-prototypes -Wno-missing-declarations

# HTTP/3 module
obj-$(CONFIG_TQUIC_HTTP3) += tquic_http3.o

# Core HTTP/3 frame layer and connection management
tquic_http3-y := \
	http3_frame.o \
	http3_settings.o \
	http3_conn.o \
	http3_stream.o \
	http3_request.o \
	http3_priority.o \
	http3_module.o

# QPACK header compression support (RFC 9204)
tquic_http3-$(CONFIG_TQUIC_HTTP3_QPACK) += \
	qpack.o \
	qpack_static.o \
	qpack_dynamic.o \
	qpack_encoder.o \
	qpack_decoder.o

# WebTransport support (draft-ietf-webtrans-http3)
tquic_http3-$(CONFIG_TQUIC_WEBTRANSPORT) += webtransport.o
