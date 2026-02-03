# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the TQUIC Diagnostics subsystem
#

obj-$(CONFIG_TQUIC_DIAG) += tquic_diag_module.o

tquic_diag_module-y := path_metrics.o tracepoints.o

# Qlog tracing support (draft-ietf-quic-qlog-main-schema)
obj-$(CONFIG_TQUIC_QLOG) += tquic_qlog.o
tquic_qlog-y := qlog.o qlog_v2.o
