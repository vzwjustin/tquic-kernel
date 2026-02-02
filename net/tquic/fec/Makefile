# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC FEC (Forward Error Correction)
#

# FEC objects - compiled as part of tquic module
obj-y += fec_core.o
obj-y += fec_encoder.o
obj-y += fec_decoder.o
obj-y += xor_fec.o
obj-y += reed_solomon.o
obj-y += fec_scheduler.o

# Compiler flags
ccflags-y += -I$(srctree)/net/tquic
ccflags-y += -I$(srctree)/include
