// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// Package netlink provides communication with the TQUIC kernel module
// via generic netlink.
package netlink

import (
	"net"
	"time"
)

// TQUIC generic netlink family name
const FamilyName = "TQUIC"

// TQUIC netlink commands (must match kernel tquic_netlink.c)
const (
	CmdUnspec = iota
	CmdRegisterClient
	CmdUnregisterClient
	CmdGetPathStats
	CmdGetClientStats
	CmdSetBlocklist
	CmdGetBlocklist
	CmdConnectionEvent // Multicast event
)

// TQUIC netlink attributes (must match kernel tquic_netlink.c)
const (
	AttrUnspec = iota
	AttrClientName
	AttrClientPSK
	AttrPortRangeStart
	AttrPortRangeEnd
	AttrBandwidthLimit
	AttrConnRateLimit
	AttrPathID
	AttrTxBytes
	AttrRxBytes
	AttrRttMin
	AttrRttAvg
	AttrRttMax
	AttrLossRate
	AttrJitter
	AttrConnCount
	AttrTotalBytes
	AttrBlocklistIP
	AttrBlocklistCIDR
	AttrEventType
	AttrSourceIP
	AttrSourcePort
	AttrDestIP
	AttrDestPort
	AttrDurationMs
	AttrTrafficClass
	AttrTimestamp
	AttrPad
)

// TQUIC netlink multicast groups
const (
	McgrpEvents = "events"
)

// Connection event types (must match kernel)
const (
	EventConnOpen    = 1 // TQUIC_EVENT_CONN_OPEN
	EventConnClose   = 2 // TQUIC_EVENT_CONN_CLOSE
	EventConnMigrate = 3 // TQUIC_EVENT_CONN_MIGRATE
)

// PathStats contains per-path statistics from the kernel.
type PathStats struct {
	ClientName string
	PathID     uint32
	TxBytes    uint64
	RxBytes    uint64
	RttMin     uint32 // microseconds
	RttAvg     uint32 // microseconds
	RttMax     uint32 // microseconds
	LossRate   uint32 // per mille (0-1000 = 0-100%)
	Jitter     uint32 // microseconds
}

// RttMinSeconds returns minimum RTT in seconds.
func (p *PathStats) RttMinSeconds() float64 {
	return float64(p.RttMin) / 1e6
}

// RttAvgSeconds returns average RTT in seconds.
func (p *PathStats) RttAvgSeconds() float64 {
	return float64(p.RttAvg) / 1e6
}

// RttMaxSeconds returns maximum RTT in seconds.
func (p *PathStats) RttMaxSeconds() float64 {
	return float64(p.RttMax) / 1e6
}

// LossRatio returns loss rate as a ratio (0.0-1.0).
func (p *PathStats) LossRatio() float64 {
	return float64(p.LossRate) / 1000.0
}

// JitterSeconds returns jitter in seconds.
func (p *PathStats) JitterSeconds() float64 {
	return float64(p.Jitter) / 1e6
}

// ClientStats contains per-client statistics from the kernel.
type ClientStats struct {
	ClientName      string
	ConnectionCount uint32
	TotalBytes      uint64
	PathCount       uint32
}

// ConnectionEvent represents a connection lifecycle event from the kernel.
type ConnectionEvent struct {
	Type         int       // EventConnOpen, EventConnClose, EventConnMigrate
	ClientID     string    // Client identity (PSK identity)
	SourceIP     net.IP    // Client's source IP
	SourcePort   uint16    // Client's source port
	DestIP       net.IP    // Destination IP (outbound connection)
	DestPort     uint16    // Destination port
	BytesTx      uint64    // Bytes transmitted
	BytesRx      uint64    // Bytes received
	DurationMs   uint64    // Connection duration in milliseconds
	TrafficClass uint8     // QoS traffic class (0=realtime, 1=interactive, 2=bulk, 3=background)
	Timestamp    time.Time // When the event occurred
}

// TypeName returns a human-readable name for the event type.
func (e *ConnectionEvent) TypeName() string {
	switch e.Type {
	case EventConnOpen:
		return "open"
	case EventConnClose:
		return "close"
	case EventConnMigrate:
		return "migrate"
	default:
		return "unknown"
	}
}

// TrafficClassName returns the human-readable traffic class name.
func (e *ConnectionEvent) TrafficClassName() string {
	switch e.TrafficClass {
	case 0:
		return "realtime"
	case 1:
		return "interactive"
	case 2:
		return "bulk"
	case 3:
		return "background"
	default:
		return "unknown"
	}
}

// BlocklistEntry represents an entry in the blocklist.
type BlocklistEntry struct {
	IP   string // Single IP address
	CIDR string // CIDR range (e.g., "10.0.0.0/8")
}

// RegisterClientRequest contains parameters for registering a client.
type RegisterClientRequest struct {
	Name           string
	PSK            []byte
	PortRangeStart uint16
	PortRangeEnd   uint16
	BandwidthLimit uint64 // bits per second
	ConnRateLimit  int    // connections per second
}
