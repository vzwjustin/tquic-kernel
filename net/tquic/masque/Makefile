# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC MASQUE subsystem
#
# MASQUE (Multiplexed Application Substrate over QUIC Encryption)
# provides HTTP proxy functionality using QUIC:
#
#   - capsule.o: Capsule Protocol (RFC 9297)
#   - http_datagram.o: HTTP Datagrams (RFC 9297)
#   - connect_udp.o: CONNECT-UDP (RFC 9298)
#   - connect_ip.o: CONNECT-IP (RFC 9484)
#

# Include paths matching parent net/tquic/Makefile
ccflags-y += -I$(src)/.. -I$(src)/../../.. -I$(src)/../diag -DTQUIC_OUT_OF_TREE
ccflags-y += -Wno-missing-prototypes -Wno-missing-declarations

obj-$(CONFIG_TQUIC_MASQUE) += tquic_masque.o

tquic_masque-y := \
	capsule.o \
	http_datagram.o \
	connect_udp.o \
	connect_ip.o \
	quic_proxy.o \
	quic_proxy_capsules.o \
	masque_module.o
