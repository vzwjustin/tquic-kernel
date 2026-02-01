/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC - Transport Parameters Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Definitions for QUIC transport parameters as defined in RFC 9000 Section 18.
 * This includes a custom enable_multipath parameter for WAN bonding support.
 */

#ifndef _TQUIC_TRANSPORT_PARAMS_H
#define _TQUIC_TRANSPORT_PARAMS_H

#include <linux/types.h>
#include <net/tquic.h>

/* Stateless reset token length */
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/**
 * struct tquic_preferred_address - Preferred address transport parameter
 * @ipv4_addr: IPv4 address (4 bytes)
 * @ipv4_port: IPv4 port
 * @ipv6_addr: IPv6 address (16 bytes)
 * @ipv6_port: IPv6 port
 * @cid: Connection ID for the preferred address
 * @stateless_reset_token: Stateless reset token for the preferred address
 *
 * This structure represents the preferred_address transport parameter
 * as defined in RFC 9000 Section 18.2.
 */
struct tquic_preferred_address {
	u8 ipv4_addr[4];
	u16 ipv4_port;
	u8 ipv6_addr[16];
	u16 ipv6_port;
	struct tquic_cid cid;
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
};

/**
 * struct tquic_transport_params - QUIC transport parameters
 * @original_dcid: Original destination connection ID (server only)
 * @original_dcid_present: Whether original_dcid is set
 * @initial_scid: Initial source connection ID
 * @initial_scid_present: Whether initial_scid is set
 * @retry_scid: Retry source connection ID (server only, after Retry)
 * @retry_scid_present: Whether retry_scid is set
 * @max_idle_timeout: Maximum idle timeout in milliseconds (0 = disabled)
 * @stateless_reset_token: Stateless reset token (server only)
 * @stateless_reset_token_present: Whether stateless_reset_token is set
 * @max_udp_payload_size: Maximum UDP payload size
 * @initial_max_data: Initial value for connection-level flow control
 * @initial_max_stream_data_bidi_local: Initial flow control for locally-initiated bidi streams
 * @initial_max_stream_data_bidi_remote: Initial flow control for remotely-initiated bidi streams
 * @initial_max_stream_data_uni: Initial flow control for unidirectional streams
 * @initial_max_streams_bidi: Initial maximum bidirectional streams
 * @initial_max_streams_uni: Initial maximum unidirectional streams
 * @ack_delay_exponent: ACK delay exponent (default 3)
 * @max_ack_delay: Maximum ACK delay in milliseconds (default 25)
 * @disable_active_migration: Disable connection migration
 * @preferred_address: Server's preferred address
 * @preferred_address_present: Whether preferred_address is set
 * @active_connection_id_limit: Maximum connection IDs to store
 * @enable_multipath: Enable multipath support (WAN bonding extension)
 *
 * This structure contains all QUIC transport parameters as defined in
 * RFC 9000 Section 18.2, plus the enable_multipath extension for
 * WAN bonding support (RFC 9369).
 */
struct tquic_transport_params {
	/* Connection IDs */
	struct tquic_cid original_dcid;
	bool original_dcid_present;

	struct tquic_cid initial_scid;
	bool initial_scid_present;

	struct tquic_cid retry_scid;
	bool retry_scid_present;

	/* Timing parameters */
	u64 max_idle_timeout;		/* milliseconds, 0 = disabled */
	u8 ack_delay_exponent;		/* default 3, max 20 */
	u32 max_ack_delay;		/* milliseconds, default 25, max 2^14 */

	/* Stateless reset token (server only) */
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	bool stateless_reset_token_present;

	/* Size limits */
	u64 max_udp_payload_size;	/* minimum 1200, default 65527 */

	/* Connection-level flow control */
	u64 initial_max_data;

	/* Stream-level flow control */
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;

	/* Stream limits */
	u64 initial_max_streams_bidi;	/* max 2^60 */
	u64 initial_max_streams_uni;	/* max 2^60 */

	/* Migration */
	bool disable_active_migration;

	/* Preferred address (server only) */
	struct tquic_preferred_address preferred_address;
	bool preferred_address_present;

	/* Connection ID management */
	u64 active_connection_id_limit;	/* minimum 2 */

	/* Multipath extension for WAN bonding */
	bool enable_multipath;
};

/**
 * struct tquic_negotiated_params - Result of transport parameter negotiation
 * @idle_timeout: Negotiated idle timeout (minimum of both, or non-zero value)
 * @max_udp_payload_size: Minimum of both peers' max_udp_payload_size
 * @max_data_send: Maximum data we can send (from remote's initial_max_data)
 * @max_data_recv: Maximum data we can receive (from local's initial_max_data)
 * @max_stream_data_bidi_local_send: Max data on locally-init bidi streams we send
 * @max_stream_data_bidi_local_recv: Max data on locally-init bidi streams we recv
 * @max_stream_data_bidi_remote_send: Max data on remotely-init bidi streams we send
 * @max_stream_data_bidi_remote_recv: Max data on remotely-init bidi streams we recv
 * @max_stream_data_uni_send: Max data on uni streams we send
 * @max_stream_data_uni_recv: Max data on uni streams we receive
 * @max_streams_bidi_send: Max bidi streams we can initiate
 * @max_streams_bidi_recv: Max bidi streams remote can initiate
 * @max_streams_uni_send: Max uni streams we can initiate
 * @max_streams_uni_recv: Max uni streams remote can initiate
 * @peer_ack_delay_exponent: Remote peer's ACK delay exponent
 * @peer_max_ack_delay: Remote peer's max ACK delay
 * @migration_disabled: True if either peer disabled migration
 * @active_cid_limit: How many CIDs we can send to peer
 * @multipath_enabled: True if both peers support multipath
 * @preferred_address: Server's preferred address (if provided)
 * @preferred_address_present: Whether preferred_address is valid
 * @peer_stateless_reset_token: Peer's stateless reset token
 * @peer_stateless_reset_token_present: Whether token is valid
 *
 * This structure contains the effective transport parameters after
 * negotiation between two endpoints.
 */
struct tquic_negotiated_params {
	/* Timing */
	u64 idle_timeout;

	/* Sizes */
	u64 max_udp_payload_size;

	/* Connection-level flow control */
	u64 max_data_send;
	u64 max_data_recv;

	/* Stream-level flow control */
	u64 max_stream_data_bidi_local_send;
	u64 max_stream_data_bidi_local_recv;
	u64 max_stream_data_bidi_remote_send;
	u64 max_stream_data_bidi_remote_recv;
	u64 max_stream_data_uni_send;
	u64 max_stream_data_uni_recv;

	/* Stream limits */
	u64 max_streams_bidi_send;
	u64 max_streams_bidi_recv;
	u64 max_streams_uni_send;
	u64 max_streams_uni_recv;

	/* ACK handling */
	u8 peer_ack_delay_exponent;
	u32 peer_max_ack_delay;

	/* Migration */
	bool migration_disabled;

	/* Connection ID management */
	u64 active_cid_limit;

	/* Multipath (WAN bonding) */
	bool multipath_enabled;

	/* Server preferred address */
	struct tquic_preferred_address preferred_address;
	bool preferred_address_present;

	/* Stateless reset */
	u8 peer_stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	bool peer_stateless_reset_token_present;
};

/*
 * Transport Parameters API
 */

/**
 * tquic_tp_init - Initialize transport parameters with default values
 * @params: Transport parameters structure to initialize
 */
void tquic_tp_init(struct tquic_transport_params *params);

/**
 * tquic_tp_set_defaults_client - Set recommended defaults for a client
 * @params: Transport parameters structure
 */
void tquic_tp_set_defaults_client(struct tquic_transport_params *params);

/**
 * tquic_tp_set_defaults_server - Set recommended defaults for a server
 * @params: Transport parameters structure
 */
void tquic_tp_set_defaults_server(struct tquic_transport_params *params);

/**
 * tquic_tp_encode - Encode transport parameters to wire format
 * @params: Transport parameters to encode
 * @is_server: True if encoding for server, false for client
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Return: Number of bytes written, or negative error code
 */
ssize_t tquic_tp_encode(const struct tquic_transport_params *params,
			bool is_server, u8 *buf, size_t buflen);

/**
 * tquic_tp_decode - Decode transport parameters from wire format
 * @buf: Input buffer
 * @buflen: Buffer length
 * @is_server: True if decoding parameters from server
 * @params: Output transport parameters structure
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_decode(const u8 *buf, size_t buflen, bool is_server,
		    struct tquic_transport_params *params);

/**
 * tquic_tp_validate - Validate transport parameters
 * @params: Transport parameters to validate
 * @is_server: True if validating parameters from server
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_tp_validate(const struct tquic_transport_params *params,
		      bool is_server);

/**
 * tquic_tp_negotiate - Negotiate transport parameters between peers
 * @local: Local transport parameters
 * @remote: Remote peer's transport parameters
 * @result: Negotiated parameters result
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_negotiate(const struct tquic_transport_params *local,
		       const struct tquic_transport_params *remote,
		       struct tquic_negotiated_params *result);

/**
 * tquic_tp_apply - Apply negotiated parameters to a connection
 * @conn: Connection to apply parameters to
 * @negotiated: Negotiated parameters
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_apply(struct tquic_connection *conn,
		   const struct tquic_negotiated_params *negotiated);

/**
 * tquic_tp_copy - Copy transport parameters
 * @dst: Destination
 * @src: Source
 */
void tquic_tp_copy(struct tquic_transport_params *dst,
		   const struct tquic_transport_params *src);

/**
 * tquic_tp_generate_stateless_reset_token - Generate a stateless reset token
 * @conn: Connection
 * @cid: Connection ID
 * @token: Output buffer (16 bytes)
 */
void tquic_tp_generate_stateless_reset_token(struct tquic_connection *conn,
					     const struct tquic_cid *cid,
					     u8 *token);

/**
 * tquic_tp_cmp_cid - Compare two connection IDs
 * @a: First connection ID
 * @b: Second connection ID
 *
 * Return: true if equal, false otherwise
 */
bool tquic_tp_cmp_cid(const struct tquic_cid *a, const struct tquic_cid *b);

/**
 * tquic_tp_validate_cids - Validate connection IDs from transport parameters
 * @params: Received transport parameters
 * @expected_scid: Expected initial_source_connection_id
 * @original_dcid: Original destination_connection_id (for server validation)
 * @is_server: True if validating server's parameters
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_tp_validate_cids(const struct tquic_transport_params *params,
			   const struct tquic_cid *expected_scid,
			   const struct tquic_cid *original_dcid,
			   bool is_server);

/**
 * tquic_tp_encoded_size - Calculate the encoded size of transport parameters
 * @params: Transport parameters
 * @is_server: True if encoding for server
 *
 * Return: Size in bytes needed for encoding
 */
size_t tquic_tp_encoded_size(const struct tquic_transport_params *params,
			     bool is_server);

/**
 * tquic_tp_debug_print - Print transport parameters for debugging
 * @params: Transport parameters to print
 * @prefix: Prefix for log messages
 */
void tquic_tp_debug_print(const struct tquic_transport_params *params,
			  const char *prefix);

/*
 * Error codes specific to transport parameters
 */
#define TQUIC_TP_ERR_INVALID_VALUE	1  /* Invalid parameter value */
#define TQUIC_TP_ERR_MISSING_PARAM	2  /* Required parameter missing */
#define TQUIC_TP_ERR_CID_MISMATCH	3  /* Connection ID mismatch */
#define TQUIC_TP_ERR_VERSION_MISMATCH	4  /* Version mismatch */
#define TQUIC_TP_ERR_DECODE_FAILED	5  /* Decoding failed */

#endif /* _TQUIC_TRANSPORT_PARAMS_H */
