/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC - Transport Parameters Header
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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

/*
 * Version Information Transport Parameter (RFC 9368)
 *
 * Transport parameter ID: 0x11
 * Used for Compatible Version Negotiation to indicate the chosen version
 * and the list of versions the endpoint supports.
 */
#define TQUIC_TP_VERSION_INFORMATION	0x11

/* Maximum number of available versions in version_info */
#define TQUIC_MAX_AVAILABLE_VERSIONS	16

/**
 * struct tquic_version_info - Version Information transport parameter (RFC 9368)
 * @chosen_version: The QUIC version selected for the connection
 * @available_versions: Array of versions the endpoint supports
 * @num_versions: Number of entries in available_versions array
 *
 * The Chosen Version field contains the version that the endpoint has chosen
 * for this connection. For a client, this is the version used in the long
 * header of the first Initial packet. For a server, this is the version
 * negotiated for the connection.
 *
 * The Available Versions field contains all versions the endpoint supports,
 * ordered by preference (most preferred first). The list MUST include the
 * Chosen Version.
 *
 * Version 0 is reserved for Version Negotiation and MUST NOT appear in
 * either Chosen Version or Available Versions.
 */
#ifndef TQUIC_VERSION_INFO_DEFINED
#define TQUIC_VERSION_INFO_DEFINED
struct tquic_version_info {
	u32 chosen_version;
	u32 available_versions[TQUIC_MAX_AVAILABLE_VERSIONS];
	size_t num_versions;
};
#endif /* TQUIC_VERSION_INFO_DEFINED */

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
#ifndef TQUIC_PREFERRED_ADDRESS_DEFINED
#define TQUIC_PREFERRED_ADDRESS_DEFINED
struct tquic_preferred_address {
	u8 ipv4_addr[4];
	u16 ipv4_port;
	u8 ipv6_addr[16];
	u16 ipv6_port;
	struct tquic_cid cid;
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
};
#endif /* TQUIC_PREFERRED_ADDRESS_DEFINED */

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
#ifndef TQUIC_TRANSPORT_PARAMS_DEFINED
#define TQUIC_TRANSPORT_PARAMS_DEFINED
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

	/* Multipath extension for WAN bonding (RFC 9369) */
	bool enable_multipath;

	/* RFC 9369 Multipath transport parameters */
	u64 initial_max_paths;		/* Maximum concurrent paths (0x0f01) */

	/* draft-ietf-quic-multipath initial_max_path_id */
	u64 initial_max_path_id;	/* Maximum Path ID (0x0f02) */
	bool initial_max_path_id_present;

	/* DATAGRAM frame support (RFC 9221) */
	u64 max_datagram_frame_size;	/* 0 = disabled, >0 = max size */

	/* GREASE support (RFC 9287) */
	bool grease_quic_bit;		/* Willing to receive GREASE'd packets */

	/* ACK Frequency (draft-ietf-quic-ack-frequency) */
	u64 min_ack_delay;		/* Minimum ACK delay in microseconds (0x0e) */
	bool min_ack_delay_present;	/* Whether min_ack_delay was advertised */

	/* Version Information (RFC 9368 - Compatible Version Negotiation) */
	struct tquic_version_info *version_info;	/* Version information parameter */
	bool version_info_present;	/* Whether version_info was advertised */

	/* Receive Timestamps (draft-smith-quic-receive-ts-03) */
	u64 max_receive_timestamps_per_ack;	/* Max timestamps in ACK (0xff0a002) */
	bool max_receive_timestamps_per_ack_present;
	u8 receive_timestamps_exponent;		/* Timestamp delta exponent (0xff0a003) */
	bool receive_timestamps_exponent_present;

	/* Address Discovery (draft-ietf-quic-address-discovery) */
	bool enable_address_discovery;	/* Supports OBSERVED_ADDRESS frames (0x9f01) */

	/* Reliable Stream Reset (draft-ietf-quic-reliable-stream-reset-07) */
	bool reliable_stream_reset;	/* Supports RESET_STREAM_AT frame (0x17cd) */

	/* Extended Key Update (draft-ietf-quic-extended-key-update-01) */
	u64 extended_key_update;	/* Max outstanding requests (0 = disabled) */
	bool extended_key_update_present;

	/* Additional Addresses (draft-piraux-quic-additional-addresses) */
	void *additional_addresses;	/* Pointer to tquic_additional_addresses */
	bool additional_addresses_present;

	/* BDP Frame Extension (draft-kuhn-quic-bdpframe-extension-05) */
	bool enable_bdp_frame;		/* Supports BDP Frame extension */

	/* Deadline-Aware Multipath Scheduling (draft-tjohn-quic-multipath-dmtp-01) */
	bool enable_deadline_aware;	/* Enable deadline-aware scheduling (0x0f10) */
	bool enable_deadline_aware_present;
	u32 deadline_granularity;	/* Time granularity in microseconds (0x0f11) */
	bool deadline_granularity_present;
	u32 max_deadline_streams;	/* Max streams with deadlines (0x0f12) */
	bool max_deadline_streams_present;
	u8 deadline_miss_policy;	/* Policy for missed deadlines (0x0f13) */
	bool deadline_miss_policy_present;

	/* Forward Error Correction (draft-zheng-quic-fec-extension-01) */
	bool enable_fec;		/* FEC is supported (0xff0f000) */
	bool enable_fec_present;	/* Whether FEC was advertised */
	u8 fec_scheme;			/* Preferred FEC scheme (0xff0f001) */
	bool fec_scheme_present;
	u8 max_source_symbols;		/* Max source symbols per block (0xff0f002) */
	bool max_source_symbols_present;

	/* Congestion Control Data Exchange (draft-yuan-quic-congestion-data-00) */
	bool enable_cong_data;		/* CC data exchange supported (0xff0cd002) */
	bool enable_cong_data_present;	/* Whether enable_cong_data was advertised */

	/* One-Way Delay Measurement (draft-huitema-quic-1wd) */
	u64 enable_one_way_delay;	/* Timestamp resolution in us (0xff02de1a) */
	bool enable_one_way_delay_present;
};
#endif /* TQUIC_TRANSPORT_PARAMS_DEFINED */

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

	/* Multipath (WAN bonding - RFC 9369) */
	bool multipath_enabled;
	u64 max_paths;			/* Negotiated maximum concurrent paths */
	u64 max_path_id;		/* Negotiated maximum Path ID */

	/* DATAGRAM support (RFC 9221) */
	u64 max_datagram_frame_size;	/* Negotiated max size, 0 = disabled */
	bool datagram_enabled;		/* True if both peers support datagrams */

	/* GREASE support (RFC 9287) */
	bool peer_grease_quic_bit;	/* Peer supports GREASE'd fixed bit */

	/* Server preferred address */
	struct tquic_preferred_address preferred_address;
	bool preferred_address_present;

	/* Stateless reset */
	u8 peer_stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	bool peer_stateless_reset_token_present;

	/* ACK Frequency (draft-ietf-quic-ack-frequency) */
	bool ack_frequency_enabled;	/* Both peers support ACK frequency */
	u64 peer_min_ack_delay;		/* Peer's min_ack_delay in microseconds */

	/* Receive Timestamps (draft-smith-quic-receive-ts-03) */
	bool receive_timestamps_enabled;	/* Both peers support receive timestamps */
	u64 max_receive_timestamps;		/* Negotiated max timestamps per ACK */
	u8 receive_timestamps_exponent;		/* Negotiated timestamp exponent */

	/* Address Discovery (draft-ietf-quic-address-discovery) */
	bool address_discovery_enabled;	/* Both peers support address discovery */

	/* Reliable Stream Reset (draft-ietf-quic-reliable-stream-reset-07) */
	bool reliable_reset_enabled;	/* Both peers support RESET_STREAM_AT */

	/* Extended Key Update (draft-ietf-quic-extended-key-update-01) */
	bool extended_key_update_enabled;  /* Both peers support EKU */
	u64 extended_key_update_max;	   /* Negotiated max outstanding requests */

	/* Additional Addresses (draft-piraux-quic-additional-addresses) */
	bool additional_addresses_enabled; /* Both peers support additional addresses */
	void *peer_additional_addresses;   /* Peer's additional addresses list */

	/* BDP Frame Extension (draft-kuhn-quic-bdpframe-extension-05) */
	bool bdp_frame_enabled;		/* Both peers support BDP Frame extension */

	/* Deadline-Aware Multipath Scheduling (draft-tjohn-quic-multipath-dmtp-01) */
	bool deadline_aware_enabled;	/* Both peers support deadline scheduling */
	u32 deadline_granularity;	/* Negotiated time granularity (us) */
	u32 max_deadline_streams;	/* Negotiated max deadline streams */
	u8 deadline_miss_policy;	/* Negotiated miss policy */

	/* Forward Error Correction (draft-zheng-quic-fec-extension-01) */
	bool fec_enabled;		/* Both peers support FEC */
	u8 fec_scheme;			/* Negotiated FEC scheme */
	u8 max_source_symbols;		/* Negotiated max source symbols */

	/* Congestion Control Data Exchange (draft-yuan-quic-congestion-data-00) */
	bool cong_data_enabled;		/* Both peers support CC data exchange */

	/* One-Way Delay Measurement (draft-huitema-quic-1wd) */
	bool one_way_delay_enabled;	/* Both peers support OWD measurement */
	u64 one_way_delay_resolution;	/* Negotiated timestamp resolution (us) */
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

/*
 * QUIC Transport Error Codes (RFC 9000 Section 20.1)
 * VERSION_NEGOTIATION_ERROR added by RFC 9368
 */
#define TQUIC_ERR_VERSION_NEGOTIATION	0x11  /* Version negotiation error (RFC 9368) */

/*
 * Version Information API (RFC 9368 - Compatible Version Negotiation)
 */

/**
 * tquic_version_info_alloc - Allocate a version_info structure
 * @gfp: Memory allocation flags
 *
 * Return: Pointer to allocated structure, or NULL on failure
 */
struct tquic_version_info *tquic_version_info_alloc(gfp_t gfp);

/**
 * tquic_version_info_free - Free a version_info structure
 * @info: Structure to free (may be NULL)
 */
void tquic_version_info_free(struct tquic_version_info *info);

/**
 * tquic_encode_version_info - Encode version_information transport parameter
 * @buf: Output buffer
 * @len: Buffer length
 * @chosen: The chosen QUIC version for the connection
 * @available: Array of available/supported versions
 * @count: Number of versions in the available array
 *
 * Encodes the version_information transport parameter as specified in
 * RFC 9368 Section 3. The format is:
 *   - Chosen Version (4 bytes)
 *   - Available Versions (4 bytes each)
 *
 * Return: Number of bytes written on success, negative error code on failure
 *         -EINVAL if chosen is 0 or any available version is 0
 *         -ENOSPC if buffer is too small
 */
ssize_t tquic_encode_version_info(u8 *buf, size_t len,
				  u32 chosen, const u32 *available, size_t count);

/**
 * tquic_decode_version_info - Decode version_information transport parameter
 * @buf: Input buffer containing the parameter value
 * @len: Length of the parameter value
 * @info: Output structure to populate
 *
 * Decodes the version_information transport parameter value. The caller
 * should have already parsed the parameter ID and length fields.
 *
 * Return: 0 on success, negative error code on failure
 *         -EINVAL if the parameter is malformed
 *         -EPROTO if validation fails (version 0 present)
 */
int tquic_decode_version_info(const u8 *buf, size_t len,
			      struct tquic_version_info *info);

/**
 * tquic_validate_version_info - Validate version_information parameter
 * @info: Version information to validate
 * @connection_version: The version used on the connection
 * @is_client: True if validating a client's version_info
 *
 * Validates the version_information transport parameter according to
 * RFC 9368 requirements:
 *   - Chosen Version must not be 0
 *   - No Available Version can be 0
 *   - For clients: Chosen Version must match the connection version
 *   - Chosen Version should appear in Available Versions (warning if not)
 *
 * Return: 0 if valid, negative error code if invalid
 *         -TQUIC_ERR_VERSION_NEGOTIATION on validation failure
 */
int tquic_validate_version_info(const struct tquic_version_info *info,
				u32 connection_version, bool is_client);

/**
 * tquic_version_info_contains - Check if version is in available versions
 * @info: Version information structure
 * @version: Version to search for
 *
 * Return: true if version is found in available_versions, false otherwise
 */
bool tquic_version_info_contains(const struct tquic_version_info *info,
				 u32 version);

/**
 * tquic_tp_set_version_info - Set version_info in transport parameters
 * @params: Transport parameters structure
 * @chosen: Chosen version for the connection
 * @available: Array of available versions
 * @count: Number of available versions
 * @gfp: Memory allocation flags
 *
 * Convenience function to set up version_information in transport parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_set_version_info(struct tquic_transport_params *params,
			      u32 chosen, const u32 *available, size_t count,
			      gfp_t gfp);

/**
 * tquic_tp_clear_version_info - Clear version_info from transport parameters
 * @params: Transport parameters structure
 *
 * Frees and clears any version_info present in the transport parameters.
 */
void tquic_tp_clear_version_info(struct tquic_transport_params *params);

#endif /* _TQUIC_TRANSPORT_PARAMS_H */
