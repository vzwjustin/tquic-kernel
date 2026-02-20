# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC FEC (Forward Error Correction)
#

# FEC objects - compiled as part of tquic module.
# Guard with CONFIG_TQUIC_FEC so that a standalone
# 'make M=net/tquic/fec' does not build FEC unconditionally.
obj-$(CONFIG_TQUIC_FEC) += fec_core.o
obj-$(CONFIG_TQUIC_FEC) += fec_encoder.o
obj-$(CONFIG_TQUIC_FEC) += fec_decoder.o
obj-$(CONFIG_TQUIC_FEC) += xor_fec.o
obj-$(CONFIG_TQUIC_FEC) += reed_solomon.o
obj-$(CONFIG_TQUIC_FEC) += fec_scheduler.o

# Compiler flags
ccflags-y += -I$(srctree)/net/tquic
ccflags-y += -I$(srctree)/include
