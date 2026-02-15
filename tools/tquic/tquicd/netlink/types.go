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
const FamilyName = "tquic"

// TQUIC netlink commands (must match kernel tquic_netlink.c enum)
const (
	CmdUnspec   = iota
	CmdPathAdd  // 1: Add a path manually
	CmdPathRemove // 2: Remove a path
	CmdPathSet  // 3: Modify path settings
	CmdPathGet  // 4: Get path information
	CmdPathList // 5: List all paths (dump)
	CmdSchedSet // 6: Set scheduler
	CmdSchedGet // 7: Get current scheduler
	CmdStatsGet // 8: Get statistics
	CmdConnGet  // 9: Get connection info
)

// TQUIC netlink attributes (must match kernel tquic_netlink.c enum)
const (
	AttrUnspec         = iota
	AttrPathID         // 1: u32 - Path identifier
	AttrPathLocalAddr  // 2: binary - Local sockaddr_storage
	AttrPathRemoteAddr // 3: binary - Remote sockaddr_storage
	AttrPathIfindex    // 4: s32 - Interface index
	AttrPathState      // 5: u8 - Path state
	AttrPathRTT        // 6: u32 - Round-trip time in us
	AttrPathBandwidth  // 7: u64 - Estimated bandwidth in bps
	AttrPathLossRate   // 8: u32 - Loss rate in 0.01% units
	AttrPathWeight     // 9: u32 - Path weight for scheduling
	AttrPathPriority   // 10: u8 - Path priority
	AttrPathFlags      // 11: u32 - Path flags
	AttrSchedName      // 12: string - Scheduler name
	AttrConnID         // 13: u64 - Connection ID
	AttrPathListNested // 14: nested - List of paths
	AttrPathEntry      // 15: nested - Single path entry
	AttrStats          // 16: nested - Statistics
	AttrLocalAddr4     // 17: in_addr - IPv4 local address
	AttrLocalAddr6     // 18: in6_addr - IPv6 local address
	AttrRemoteAddr4    // 19: in_addr - IPv4 remote address
	AttrRemoteAddr6    // 20: in6_addr - IPv6 remote address
	AttrLocalPort      // 21: u16 - Local port
	AttrRemotePort     // 22: u16 - Remote port
	AttrFamily         // 23: u16 - Address family

	// Statistics attributes
	AttrStatsTxPackets // 24: u64
	AttrStatsRxPackets // 25: u64
	AttrStatsTxBytes   // 26: u64
	AttrStatsRxBytes   // 27: u64
	AttrStatsRetrans   // 28: u64
	AttrStatsSpurious  // 29: u64
	AttrStatsCwnd      // 30: u32
	AttrStatsSRTT      // 31: u32
	AttrStatsRTTVar    // 32: u32

	// Event-specific attributes
	AttrEventType   // 33: u8
	AttrEventReason // 34: u32
	AttrOldPathID   // 35: u32
	AttrNewPathID   // 36: u32

	// Padding
	AttrPad // 37
)

// TQUIC netlink multicast groups
const (
	McgrpEvents = "events"
)

// Event types (must match kernel tquic_event_type enum)
const (
	EventPathUp    = 1 // TQUIC_EVENT_PATH_UP
	EventPathDown  = 2 // TQUIC_EVENT_PATH_DOWN
	EventPathChange = 3 // TQUIC_EVENT_PATH_CHANGE
	EventMigration = 4 // TQUIC_EVENT_MIGRATION
)

// Path states (must match kernel tquic_nl_path_state enum)
const (
	PathStateUnknown    = 0
	PathStateValidating = 1
	PathStateValidated  = 2
	PathStateActive     = 3
	PathStateStandby    = 4
	PathStateDegraded   = 5
	PathStateFailed     = 6
)

// PathInfo contains path information from the kernel.
type PathInfo struct {
	PathID    uint32
	State     uint8
	Priority  uint8
	Family    uint16
	Ifindex   int32
	Flags     uint32
	Weight    uint32
	RTT       uint32 // microseconds
	Bandwidth uint64 // bps
	LossRate  uint32 // 0.01% units
	LocalIP   net.IP
	RemoteIP  net.IP
	LocalPort  uint16
	RemotePort uint16
}

// StateName returns a human-readable path state name.
func (p *PathInfo) StateName() string {
	switch p.State {
	case PathStateUnknown:
		return "unknown"
	case PathStateValidating:
		return "validating"
	case PathStateValidated:
		return "validated"
	case PathStateActive:
		return "active"
	case PathStateStandby:
		return "standby"
	case PathStateDegraded:
		return "degraded"
	case PathStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// RTTSeconds returns RTT in seconds.
func (p *PathInfo) RTTSeconds() float64 {
	return float64(p.RTT) / 1e6
}

// LossRatio returns loss rate as a ratio (0.0-1.0).
func (p *PathInfo) LossRatio() float64 {
	return float64(p.LossRate) / 10000.0
}

// PathStats contains per-path statistics from the kernel.
type PathStats struct {
	PathID     uint32
	TxPackets  uint64
	RxPackets  uint64
	TxBytes    uint64
	RxBytes    uint64
	Retrans    uint64
	Spurious   uint64
	Cwnd       uint32
	SRTT       uint32 // microseconds
	RTTVar     uint32 // microseconds
}

// SRTTSeconds returns smoothed RTT in seconds.
func (p *PathStats) SRTTSeconds() float64 {
	return float64(p.SRTT) / 1e6
}

// PathEvent represents a path lifecycle event from the kernel.
type PathEvent struct {
	Type      int    // EventPathUp, EventPathDown, etc.
	Reason    uint32 // Event reason code
	PathID    uint32 // Affected path
	OldPathID uint32 // Old path (for migration)
	NewPathID uint32 // New path (for migration)
	Timestamp time.Time
}

// TypeName returns a human-readable name for the event type.
func (e *PathEvent) TypeName() string {
	switch e.Type {
	case EventPathUp:
		return "path_up"
	case EventPathDown:
		return "path_down"
	case EventPathChange:
		return "path_change"
	case EventMigration:
		return "migration"
	default:
		return "unknown"
	}
}
