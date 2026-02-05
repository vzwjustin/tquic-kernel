// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Tracepoint Definitions
 *
 * This file creates the tracepoint implementations for QUIC debugging.
 * It must define TRACE_INCLUDE_PATH and CREATE_TRACE_POINTS before
 * including the tracepoint header.
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#define CREATE_TRACE_POINTS
#include "trace.h"
/*
 * Tracepoints are built into the owning object/module. Keep module metadata
 * in the top-level TQUIC module instead of the tracepoint translation unit.
 */
