# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for QUIC
#

obj-$(CONFIG_QUIC) += quic.o

quic-y := \
	protocol.o \
	connection.o \
	stream.o \
	packet.o \
	crypto.o \
	cong.o \
	flow.o \
	loss.o \
	path.o \
	timer.o \
	ack.o \
	offload.o \
	output.o \
	tquic_bonding.o \
	tquic_reorder.o \
	tquic_failover.o \
	sched_minrtt.o \
	sched_aggregate.o \
	sched_weighted.o \
	sched_blest.o \
	sched_ecf.o
