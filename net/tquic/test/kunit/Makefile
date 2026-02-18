# SPDX-License-Identifier: GPL-2.0-only
#
# TQUIC KUnit Tests Makefile
#

obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_kunit.o

tquic_kunit-y := extensions_test.o

obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_stateless_reset_kunit.o

tquic_stateless_reset_kunit-y := ../stateless_reset_test.o

obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_loss_kunit.o

tquic_loss_kunit-y := quic_loss_test.o

obj-$(CONFIG_TQUIC_KUNIT_TEST) += tquic_path_kunit.o

tquic_path_kunit-y := quic_path_test.o
