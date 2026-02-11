/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Coupled Multipath Congestion Control API
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Public interface for coupled congestion control algorithms (LIA, OLIA, BALIA).
 */

#ifndef _TQUIC_CONG_COUPLED_H
#define _TQUIC_CONG_COUPLED_H

#include <linux/types.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct tquic_coupled_state;

/* Coupled congestion control algorithms */
enum tquic_coupled_algo {
	TQUIC_COUPLED_ALGO_LIA = 0,	/* Linked Increases Algorithm */
	TQUIC_COUPLED_ALGO_OLIA,	/* Opportunistic Linked Increases (RFC 6356) */
	TQUIC_COUPLED_ALGO_BALIA,	/* Balanced Linked Adaptation */
};

/*
 * Coupled congestion control lifecycle
 */

/* Create coupled CC state for a connection */
struct tquic_coupled_state *tquic_coupled_create(struct tquic_connection *conn,
						 enum tquic_coupled_algo algo);

/* Destroy coupled CC state */
void tquic_coupled_destroy(struct tquic_coupled_state *state);

/*
 * Path management
 */

/* Attach a path to coupled CC */
int tquic_coupled_attach_path(struct tquic_coupled_state *state,
			      struct tquic_path *path);

/* Detach a path from coupled CC */
void tquic_coupled_detach_path(struct tquic_coupled_state *state,
			       struct tquic_path *path);

/*
 * Event handlers
 */

/* Handle ACK received on a path */
void tquic_coupled_on_ack_ext(struct tquic_coupled_state *state,
			      struct tquic_path *path,
			      u32 acked_bytes, u32 rtt_us);

/* Handle packet loss on a path */
void tquic_coupled_on_loss_ext(struct tquic_coupled_state *state,
			       struct tquic_path *path,
			       u32 lost_bytes);

#endif /* _TQUIC_CONG_COUPLED_H */
