# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for QUIC (TQUIC implementation)
#

# Include paths for headers
ccflags-y += -I$(src)/tquic/include -I$(src)/../.. -I$(src)/tquic/diag -DTQUIC_OUT_OF_TREE
# Suppress warnings treated as errors during development (remove for production)
ccflags-y += -Wno-error=unused-function -Wno-error=unused-variable
ccflags-y += -Wno-error=missing-prototypes

obj-$(CONFIG_IP_QUIC) += quic.o

# Main QUIC module (backed by the TQUIC implementation under net/tquic/)
quic-y := \
	tquic/tquic_main.o \
	tquic/tquic_proto.o \
	tquic/tquic_socket.o \
	tquic/tquic_stream.o \
	tquic/tquic_handshake.o \
	tquic/tquic_netlink.o \
	tquic/tquic_sysctl.o \
	tquic/tquic_udp.o \
	tquic/tquic_output.o \
	tquic/tquic_input.o \
	tquic/tquic_offload.o \
	tquic/quic_offload.o \
	tquic/tquic_timer.o \
	tquic/tquic_cid.o \
	tquic/tquic_migration.o \
	tquic/tquic_pmtud.o \
	tquic/tquic_diag.o \
	tquic/tquic_mib.o \
	tquic/tquic_proc.o \
	tquic/tquic_server.o \
	tquic/tquic_zerocopy.o \
	tquic/tquic_retry.o \
	tquic/tquic_token.o \
	tquic/tquic_stateless_reset.o \
	tquic/tquic_forward.o \
	tquic/tquic_preferred_addr.o \
	tquic/tquic_qos.o \
	tquic/tquic_tunnel.o \
	tquic/tquic_ratelimit.o \
	tquic/rate_limit.o \
	tquic/grease.o \
	tquic/tquic_ack_frequency.o \
	tquic/security_hardening.o \
	tquic/cong/tquic_cong.o \
	tquic/cong/cong_data.o \
	tquic/cong/persistent_cong.o \
	tquic/cong/coupled.o \
	tquic/cong/bbrv2.o \
	tquic/cong/bbrv3.o \
	tquic/cong/prague.o \
	tquic/cong/cubic.o \
	tquic/cong/bbr.o \
	tquic/cong/copa.o \
	tquic/cong/westwood.o \
	tquic/cong/l4s.o \
	tquic/cong/accecn.o \
	tquic/core/varint.o \
	tquic/core/connection.o \
	tquic/core/stream.o \
	tquic/core/frame.o \
	tquic/core/packet.o \
	tquic/core/ack_frequency.o \
	tquic/core/flow_control.o \
	tquic/core/transport_params.o \
	tquic/core/address_discovery.o \
	tquic/core/receive_timestamps.o \
	tquic/core/reliable_reset.o \
	tquic/core/one_way_delay.o \
	tquic/core/additional_addresses.o \
	tquic/core/quic_protocol.o \
	tquic/core/quic_connection.o \
	tquic/core/quic_crypto.o \
	tquic/core/quic_packet.o \
	tquic/core/quic_output.o \
	tquic/core/quic_cong.o \
	tquic/core/quic_ecn.o \
	tquic/core/quic_flow.o \
	tquic/core/quic_loss.o \
	tquic/core/quic_path.o \
	tquic/core/ack.o \
	tquic/core/quic_ack.o \
	tquic/core/quic_ack_frequency.o \
	tquic/core/quic_key_update.o \
	tquic/core/packet_coalesce_fix.o \
	tquic/core/early_data.o \
	tquic/core/priority.o \
	tquic/bond/bonding.o \
	tquic/bond/tquic_bonding.o \
	tquic/bond/tquic_failover.o \
	tquic/bond/tquic_reorder.o \
	tquic/bond/tquic_bpm.o \
	tquic/bond/cong_coupled.o \
	tquic/pm/pm_types.o \
	tquic/pm/pm_kernel.o \
	tquic/pm/pm_netlink.o \
	tquic/pm/path_manager.o \
	tquic/pm/path_validation.o \
	tquic/pm/nat_keepalive.o \
	tquic/pm/nat_lifecycle.o \
	tquic/pm/pm_userspace.o \
	tquic/pm/pm_module.o \
	tquic/sched/scheduler.o \
	tquic/sched/deadline_scheduler.o \
	tquic/sched/deadline_aware.o \
	tquic/multipath/mp_frame.o \
	tquic/multipath/mp_ack.o \
	tquic/multipath/mp_deadline.o \
	tquic/multipath/path_abandon.o \
	tquic/multipath/mp_sched_registry.o \
	tquic/multipath/multipath_module.o \
	tquic/multipath/sched_minrtt.o \
	tquic/multipath/sched_ecf.o \
	tquic/multipath/sched_blest.o \
	tquic/multipath/sched_weighted.o \
	tquic/multipath/sched_aggregate.o \
	tquic/multipath/tquic_scheduler.o \
	tquic/crypto/cert_verify.o \
	tquic/crypto/tls.o \
	tquic/crypto/header_protection.o \
	tquic/crypto/key_update.o \
	tquic/crypto/extended_key_update.o \
	tquic/crypto/zero_rtt.o \
	tquic/crypto/handshake.o \
	tquic/crypto/crypto_module.o \
	tquic/crypto/hw_offload.o \
	tquic/tquic_debug.o

# Diagnostics (tracepoints.o excluded pending struct field fixes)
quic-$(CONFIG_TQUIC_DIAG) += tquic/diag/path_metrics.o
quic-$(CONFIG_TQUIC_QLOG) += tquic/diag/qlog.o tquic/diag/qlog_v2.o

# Tracing support
quic-$(CONFIG_TRACEPOINTS) += tquic/diag/trace.o

# IPv6 Support
quic-$(CONFIG_TQUIC_IPV6) += tquic/tquic_ipv6.o

# NAPI polling support
quic-$(CONFIG_TQUIC_NAPI) += tquic/napi.o

# io_uring support for high-performance async I/O
quic-$(CONFIG_TQUIC_IO_URING) += tquic/io_uring.o
