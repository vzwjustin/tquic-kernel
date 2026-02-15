# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC Transport Modules Makefile
#
# This builds the QUIC-over-TCP transport module which provides:
# - TCP encapsulation for QUIC packets (draft-ietf-quic-over-tcp)
# - Automatic UDP-to-TCP fallback mechanism
# - Flow control and congestion control coordination
# - MTU handling and keepalive coordination
#

# Main QUIC-over-TCP transport module
obj-$(CONFIG_TQUIC_OVER_TCP) += tquic_tcp.o

# Module objects
tquic_tcp-y := quic_over_tcp.o
tquic_tcp-y += tcp_fallback.o

# Enable extra warnings for this subsystem
ccflags-y += -Werror
