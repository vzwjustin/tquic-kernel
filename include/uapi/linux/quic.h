/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Linux kernel QUIC implementation based on RFC 9000, RFC 9001, RFC 9002
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _UAPI_LINUX_QUIC_H
#define _UAPI_LINUX_QUIC_H

#include <linux/types.h>
#include <linux/socket.h>

/* QUIC protocol version numbers */
#define QUIC_VERSION_1		0x00000001	/* RFC 9000 */
#define QUIC_VERSION_2		0x6b3343cf	/* RFC 9369 */
#define QUIC_VERSION_NEGOTIATION 0x00000000

/* QUIC socket options */
#define QUIC_SOCKOPT_EVENT			1
#define QUIC_SOCKOPT_STREAM_OPEN		2
#define QUIC_SOCKOPT_STREAM_RESET		3
#define QUIC_SOCKOPT_STREAM_STOP_SENDING	4
#define QUIC_SOCKOPT_CONNECTION_CLOSE		5
#define QUIC_SOCKOPT_CONNECTION_MIGRATION	6
#define QUIC_SOCKOPT_KEY_UPDATE			7
#define QUIC_SOCKOPT_TRANSPORT_PARAM		8
#define QUIC_SOCKOPT_TOKEN			9
#define QUIC_SOCKOPT_ALPN			10
#define QUIC_SOCKOPT_SESSION_TICKET		11
#define QUIC_SOCKOPT_CRYPTO_SECRET		12
#define QUIC_SOCKOPT_CRYPTO_KEY			13
#define QUIC_SOCKOPT_CONGESTION			14
#define QUIC_SOCKOPT_CONFIG			15
#define QUIC_SOCKOPT_SNI			16	/* Server Name Indication hostname */
#define QUIC_SOCKOPT_ALPN_SELECTED		17	/* Get negotiated ALPN (read-only) */
#define QUIC_SOCKOPT_STREAM_PRIORITY		18	/* Set/get stream priority */

/* QUIC socket option levels */
#define QUIC_SO_STREAM		1
#define QUIC_SO_CONNECTION	2

/* QUIC stream types */
#define QUIC_STREAM_TYPE_CLIENT_BIDI	0x00
#define QUIC_STREAM_TYPE_SERVER_BIDI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

/* QUIC stream flags */
#define QUIC_STREAM_FLAG_NEW		(1 << 0)
#define QUIC_STREAM_FLAG_FIN		(1 << 1)
#define QUIC_STREAM_FLAG_RESET		(1 << 2)
#define QUIC_STREAM_FLAG_STOP_SENDING	(1 << 3)
#define QUIC_STREAM_FLAG_UNI		(1 << 4)
#define QUIC_STREAM_FLAG_BIDI		(1 << 5)
#define QUIC_STREAM_FLAG_ASYNC		(1 << 6)

/* QUIC frame types per RFC 9000 */
#define QUIC_FRAME_PADDING		0x00
#define QUIC_FRAME_PING			0x01
#define QUIC_FRAME_ACK			0x02
#define QUIC_FRAME_ACK_ECN		0x03
#define QUIC_FRAME_RESET_STREAM		0x04
#define QUIC_FRAME_STOP_SENDING		0x05
#define QUIC_FRAME_CRYPTO		0x06
#define QUIC_FRAME_NEW_TOKEN		0x07
#define QUIC_FRAME_STREAM		0x08
#define QUIC_FRAME_STREAM_FIN		0x09
#define QUIC_FRAME_STREAM_LEN		0x0a
#define QUIC_FRAME_STREAM_OFF		0x0c
#define QUIC_FRAME_MAX_DATA		0x10
#define QUIC_FRAME_MAX_STREAM_DATA	0x11
#define QUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define QUIC_FRAME_MAX_STREAMS_UNI	0x13
#define QUIC_FRAME_DATA_BLOCKED		0x14
#define QUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define QUIC_FRAME_STREAMS_BLOCKED_BIDI	0x16
#define QUIC_FRAME_STREAMS_BLOCKED_UNI	0x17
#define QUIC_FRAME_NEW_CONNECTION_ID	0x18
#define QUIC_FRAME_RETIRE_CONNECTION_ID	0x19
#define QUIC_FRAME_PATH_CHALLENGE	0x1a
#define QUIC_FRAME_PATH_RESPONSE	0x1b
#define QUIC_FRAME_CONNECTION_CLOSE	0x1c
#define QUIC_FRAME_CONNECTION_CLOSE_APP	0x1d
#define QUIC_FRAME_HANDSHAKE_DONE	0x1e
#define QUIC_FRAME_DATAGRAM		0x30
#define QUIC_FRAME_DATAGRAM_LEN		0x31

/* QUIC packet types */
#define QUIC_PACKET_INITIAL		0
#define QUIC_PACKET_0RTT		1
#define QUIC_PACKET_HANDSHAKE		2
#define QUIC_PACKET_RETRY		3
#define QUIC_PACKET_1RTT		4

/* QUIC encryption levels */
#define QUIC_CRYPTO_INITIAL		0
#define QUIC_CRYPTO_HANDSHAKE		1
#define QUIC_CRYPTO_APPLICATION		2
#define QUIC_CRYPTO_EARLY_DATA		3
#define QUIC_CRYPTO_MAX			4

/* QUIC transport error codes (RFC 9000 Section 20.1) */
#define QUIC_ERROR_NO_ERROR			0x00
#define QUIC_ERROR_INTERNAL_ERROR		0x01
#define QUIC_ERROR_CONNECTION_REFUSED		0x02
#define QUIC_ERROR_FLOW_CONTROL_ERROR		0x03
#define QUIC_ERROR_STREAM_LIMIT_ERROR		0x04
#define QUIC_ERROR_STREAM_STATE_ERROR		0x05
#define QUIC_ERROR_FINAL_SIZE_ERROR		0x06
#define QUIC_ERROR_FRAME_ENCODING_ERROR		0x07
#define QUIC_ERROR_TRANSPORT_PARAMETER_ERROR	0x08
#define QUIC_ERROR_CONNECTION_ID_LIMIT_ERROR	0x09
#define QUIC_ERROR_PROTOCOL_VIOLATION		0x0a
#define QUIC_ERROR_INVALID_TOKEN		0x0b
#define QUIC_ERROR_APPLICATION_ERROR		0x0c
#define QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED	0x0d
#define QUIC_ERROR_KEY_UPDATE_ERROR		0x0e
#define QUIC_ERROR_AEAD_LIMIT_REACHED		0x0f
#define QUIC_ERROR_NO_VIABLE_PATH		0x10
#define QUIC_ERROR_CRYPTO_BASE			0x100

/* QUIC connection states */
enum quic_state {
	QUIC_STATE_IDLE		= 0,
	QUIC_STATE_CONNECTING	= 1,
	QUIC_STATE_HANDSHAKE	= 2,
	QUIC_STATE_CONNECTED	= 3,
	QUIC_STATE_CLOSING	= 4,
	QUIC_STATE_DRAINING	= 5,
	QUIC_STATE_CLOSED	= 6,
};

/* QUIC stream states */
enum quic_stream_state {
	QUIC_STREAM_STATE_IDLE		= 0,
	QUIC_STREAM_STATE_OPEN		= 1,
	QUIC_STREAM_STATE_SEND		= 2,
	QUIC_STREAM_STATE_RECV		= 3,
	QUIC_STREAM_STATE_DATA_SENT	= 4,
	QUIC_STREAM_STATE_DATA_RECVD	= 5,
	QUIC_STREAM_STATE_RESET_SENT	= 6,
	QUIC_STREAM_STATE_RESET_RECVD	= 7,
	QUIC_STREAM_STATE_CLOSED	= 8,
};

/* QUIC congestion control algorithms */
enum quic_cc_algo {
	QUIC_CC_RENO	= 0,
	QUIC_CC_CUBIC	= 1,
	QUIC_CC_BBR	= 2,
	QUIC_CC_BBR2	= 3,
};

/* QUIC events for socket notification */
enum quic_event_type {
	QUIC_EVENT_NONE			= 0,
	QUIC_EVENT_STREAM_UPDATE	= 1,
	QUIC_EVENT_CONNECTION_CLOSE	= 2,
	QUIC_EVENT_KEY_UPDATE		= 3,
	QUIC_EVENT_NEW_TOKEN		= 4,
	QUIC_EVENT_CONNECTION_MIGRATION	= 5,
	QUIC_EVENT_PATH_VALIDATED	= 6,
	QUIC_EVENT_HANDSHAKE_COMPLETE	= 7,
	QUIC_EVENT_DATAGRAM_RECEIVED	= 8,
};

/* QUIC connection ID structure */
struct quic_connection_id {
	__u8	len;
	__u8	data[20];
};

/* QUIC transport parameters (RFC 9000 Section 18.2) */
struct quic_transport_params {
	__u64	original_destination_connection_id_len;
	__u64	max_idle_timeout;
	__u8	stateless_reset_token[16];
	__u64	max_udp_payload_size;
	__u64	initial_max_data;
	__u64	initial_max_stream_data_bidi_local;
	__u64	initial_max_stream_data_bidi_remote;
	__u64	initial_max_stream_data_uni;
	__u64	initial_max_streams_bidi;
	__u64	initial_max_streams_uni;
	__u64	ack_delay_exponent;
	__u64	max_ack_delay;
	__u8	disable_active_migration;
	__u64	preferred_address_present;
	__u64	active_connection_id_limit;
	__u64	initial_source_connection_id_len;
	__u64	retry_source_connection_id_len;
	__u64	max_datagram_frame_size;
	__u8	grease_quic_bit;
};

/* QUIC stream information for sendmsg/recvmsg cmsg */
struct quic_stream_info {
	__u64	stream_id;
	__u32	stream_flags;
	__u32	reserved;
};

/* QUIC event information */
struct quic_event_info {
	__u32	type;
	__u32	error_code;
	__u64	stream_id;
	__u8	data[64];
	__u32	data_len;
};

/* QUIC connection close information */
struct quic_connection_close_info {
	__u64	error_code;
	__u64	frame_type;
	__u8	reason[256];
	__u32	reason_len;
	__u8	is_app_error;
};

/* QUIC stream reset information */
struct quic_stream_reset_info {
	__u64	stream_id;
	__u64	error_code;
	__u64	final_size;
};

/* QUIC key update info */
struct quic_key_update_info {
	__u8	phase;
	__u8	key_material[64];
	__u32	key_len;
};

/* QUIC path information */
struct quic_path_info {
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	remote_addr;
	__u32	mtu;
	__u32	rtt;
	__u8	validated;
};

/* QUIC statistics */
struct quic_stats {
	__u64	bytes_sent;
	__u64	bytes_received;
	__u64	packets_sent;
	__u64	packets_received;
	__u64	packets_lost;
	__u64	packets_retransmitted;
	__u64	frames_sent;
	__u64	frames_received;
	__u64	streams_opened;
	__u64	streams_closed;
	__u64	handshake_time_us;
	__u32	min_rtt_us;
	__u32	smoothed_rtt_us;
	__u32	rtt_variance_us;
	__u32	latest_rtt_us;
	__u64	cwnd;
	__u64	bytes_in_flight;
	__u32	congestion_events;
	__u8	congestion_state;
};

/* QUIC configuration */
struct quic_config {
	__u32	version;
	__u32	validate_peer_address;
	__u32	grease_enabled;
	__u32	max_connection_ids;
	__u32	initial_rtt_ms;
	__u32	max_retries;
	__u64	max_idle_timeout_ms;
	__u64	handshake_timeout_ms;
	__u64	initial_max_data;
	__u64	initial_max_stream_data_bidi_local;
	__u64	initial_max_stream_data_bidi_remote;
	__u64	initial_max_stream_data_uni;
	__u64	initial_max_streams_bidi;
	__u64	initial_max_streams_uni;
	__u32	ack_delay_exponent;
	__u32	max_ack_delay_ms;
	__u8	disable_active_migration;
	__u8	enable_datagram;
	__u64	max_datagram_size;
};

/* QUIC cryptographic context info for crypto API integration */
struct quic_crypto_info {
	__u16	version;
	__u16	cipher_type;
	__u8	tx_key[32];
	__u8	rx_key[32];
	__u8	tx_iv[12];
	__u8	rx_iv[12];
	__u8	tx_hp_key[32];
	__u8	rx_hp_key[32];
	__u32	key_len;
	__u32	iv_len;
	__u32	hp_key_len;
};

/* Cipher types for QUIC TLS 1.3 */
#define QUIC_CIPHER_AES_128_GCM_SHA256		1
#define QUIC_CIPHER_AES_256_GCM_SHA384		2
#define QUIC_CIPHER_CHACHA20_POLY1305_SHA256	3

/* QUIC cmsg types for ancillary data */
#define QUIC_CMSG_STREAM_INFO	1
#define QUIC_CMSG_EVENT		2
#define QUIC_CMSG_ECN		3
#define QUIC_CMSG_DATAGRAM	4

/* QUIC sysctl tunables */
#define QUIC_SYSCTL_MEM_MIN		0
#define QUIC_SYSCTL_MEM_PRESSURE	1
#define QUIC_SYSCTL_MEM_MAX		2

/* Max sizes */
#define QUIC_MAX_CONNECTION_ID_LEN	20
#define QUIC_MIN_CONNECTION_ID_LEN	0
#define QUIC_STATELESS_RESET_TOKEN_LEN	16
#define QUIC_MAX_ALPN_LEN		255
#define QUIC_MAX_SNI_LEN		255	/* Maximum server name length (RFC 6066) */
#define QUIC_MAX_TOKEN_LEN		512
#define QUIC_MAX_PACKET_SIZE		1500
#define QUIC_MIN_PACKET_SIZE		1200
#define QUIC_MAX_STREAMS		(1ULL << 60)
#define QUIC_MAX_DATA			(1ULL << 62)
#define QUIC_MAX_SESSION_TICKET_LEN	4096	/* Maximum session ticket size */

/*
 * QUIC Session Ticket (RFC 9001 Section 4.6.1)
 *
 * Stores the TLS 1.3 session ticket data for 0-RTT resumption.
 * The ticket is received via NEW_SESSION_TICKET and contains
 * the PSK identity and associated parameters for resumption.
 */
struct quic_session_ticket {
	__u8	ticket[QUIC_MAX_SESSION_TICKET_LEN];	/* Ticket data */
	__u32	ticket_len;				/* Length of ticket */
	__u8	resumption_secret[64];			/* Resumption secret for 0-RTT */
	__u32	resumption_secret_len;			/* Length of resumption secret */
	__u16	cipher_type;				/* Cipher suite for 0-RTT */
	__u32	max_early_data;				/* Max early data allowed */
	__u64	lifetime;				/* Ticket lifetime in ms */
	__u64	issued_time;				/* When ticket was issued */
}

/* QUIC ioctl commands */
#define QUIC_IOC_MAGIC		'Q'
#define QUIC_IOC_GET_STATS	_IOR(QUIC_IOC_MAGIC, 1, struct quic_stats)
#define QUIC_IOC_GET_CONFIG	_IOR(QUIC_IOC_MAGIC, 2, struct quic_config)
#define QUIC_IOC_SET_CONFIG	_IOW(QUIC_IOC_MAGIC, 3, struct quic_config)
#define QUIC_IOC_GET_PATH	_IOR(QUIC_IOC_MAGIC, 4, struct quic_path_info)

#endif /* _UAPI_LINUX_QUIC_H */
