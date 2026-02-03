# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for QUIC
#

obj-$(CONFIG_QUIC) += quic.o

quic-y := \
	protocol.o \
	connection.o \
	socket.o \
	stream.o \
	packet.o \
	packet_coalesce_fix.o \
	crypto.o \
	key_update.o \
	cong.o \
	cong_coupled.o \
	ecn.o \
	flow.o \
	loss.o \
	path.o \
	timer.o \
	ack.o \
	ack_frequency.o \
	offload.o \
	output.o \
	sysctl.o \
	early_data.o \
	priority.o \
	trace.o \
	mp_frame.o \
	tquic_bonding.o \
	tquic_reorder.o \
	tquic_failover.o \
	tquic_path.o \
	tquic_scheduler.o \
	tquic_netlink.o \
	sched_minrtt.o \
	sched_aggregate.o \
	sched_weighted.o \
	sched_blest.o \
	sched_ecf.o
