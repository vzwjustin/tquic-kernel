# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the TQUIC Diagnostics subsystem
#

# Include paths matching parent net/tquic/Makefile
ccflags-y += -I$(src)/.. -I$(src)/../../.. -I$(src) -DTQUIC_OUT_OF_TREE
ccflags-y += -Wno-missing-prototypes -Wno-missing-declarations

obj-$(CONFIG_TQUIC_DIAG) += tquic_diag_module.o

tquic_diag_module-y := path_metrics.o tracepoints.o

# Qlog tracing support (draft-ietf-quic-qlog-main-schema)
obj-$(CONFIG_TQUIC_QLOG) += tquic_qlog.o
tquic_qlog-y := qlog.o qlog_v2.o
