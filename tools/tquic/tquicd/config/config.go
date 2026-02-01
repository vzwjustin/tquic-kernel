// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// Package config provides configuration types and validation for tquicd.
package config

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Config represents the complete tquicd configuration loaded from
// /etc/tquic.d/*.conf files.
type Config struct {
	Global    GlobalConfig
	Clients   map[string]*ClientConfig
	Blocklist BlocklistConfig
}

// GlobalConfig contains daemon-wide settings.
type GlobalConfig struct {
	// ListenPort is the TQUIC listen port (default: 443)
	ListenPort int

	// MetricsPort is the Prometheus metrics port (default: 9100)
	MetricsPort int

	// DashboardPort is the web dashboard port (default: 8080, localhost only)
	DashboardPort int

	// LogFile is the path to the main daemon log file
	LogFile string

	// ConnLogFile is the path to the detailed per-connection JSON log file
	ConnLogFile string

	// SessionTTL is the session lifetime in seconds for router reconnects
	SessionTTL int

	// Interface is the outbound network interface for NAT masquerade
	Interface string

	// EnableTFO enables TCP Fast Open for outbound connections
	EnableTFO bool

	// EnableGRO enables Generic Receive Offload
	EnableGRO bool

	// EnableGSO enables Generic Segmentation Offload
	EnableGSO bool

	// QueueTimeout is seconds to queue packets when all paths are down
	QueueTimeout int

	// HairpinEnabled allows router-to-router traffic via VPS
	HairpinEnabled bool
}

// ClientConfig contains per-client (router) settings.
type ClientConfig struct {
	// Name is the unique client identifier (matches PSK identity)
	Name string

	// PSK is the pre-shared key for authentication (raw bytes)
	PSK []byte

	// PSKBase64 is the base64-encoded PSK (for config file)
	PSKBase64 string

	// PortRangeStart is the beginning of the assigned NAT port range
	PortRangeStart uint16

	// PortRangeEnd is the end of the assigned NAT port range
	PortRangeEnd uint16

	// BandwidthLimit is the per-client bandwidth limit (e.g., "100mbit")
	BandwidthLimit string

	// ConnRateLimit is the maximum connections per second (default: 10)
	ConnRateLimit int

	// TrafficClasses maps class names to bandwidth percentage
	// e.g., {"realtime": 30, "interactive": 30, "bulk": 30, "background": 10}
	TrafficClasses map[string]int

	// Enabled indicates if this client configuration is active
	Enabled bool
}

// BlocklistConfig contains IP blocklist settings.
type BlocklistConfig struct {
	// IPs contains individual blocked IP addresses
	IPs []string

	// CIDRs contains blocked CIDR ranges
	CIDRs []string

	// PersistFile is the path to persistent blocklist file
	PersistFile string

	// Enabled indicates if blocklist checking is active
	Enabled bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			ListenPort:     443,
			MetricsPort:    9100,
			DashboardPort:  8080,
			LogFile:        "/var/log/tquic/tquicd.log",
			ConnLogFile:    "/var/log/tquic/connections.log",
			SessionTTL:     120,
			Interface:      "eth0",
			EnableTFO:      true,
			EnableGRO:      true,
			EnableGSO:      true,
			QueueTimeout:   30,
			HairpinEnabled: true,
		},
		Clients: make(map[string]*ClientConfig),
		Blocklist: BlocklistConfig{
			IPs:         make([]string, 0),
			CIDRs:       make([]string, 0),
			PersistFile: "/etc/tquic.d/blocklist.txt",
			Enabled:     true,
		},
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if err := c.Global.Validate(); err != nil {
		return fmt.Errorf("global config: %w", err)
	}

	// Check for overlapping port ranges
	for name1, client1 := range c.Clients {
		if err := client1.Validate(); err != nil {
			return fmt.Errorf("client %s: %w", name1, err)
		}

		for name2, client2 := range c.Clients {
			if name1 >= name2 {
				continue
			}
			if portsOverlap(client1.PortRangeStart, client1.PortRangeEnd,
				client2.PortRangeStart, client2.PortRangeEnd) {
				return fmt.Errorf("port ranges overlap: %s (%d-%d) and %s (%d-%d)",
					name1, client1.PortRangeStart, client1.PortRangeEnd,
					name2, client2.PortRangeStart, client2.PortRangeEnd)
			}
		}
	}

	return nil
}

// Validate checks GlobalConfig for errors.
func (g *GlobalConfig) Validate() error {
	if g.ListenPort < 1 || g.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be 1-65535, got %d", g.ListenPort)
	}
	if g.MetricsPort < 1 || g.MetricsPort > 65535 {
		return fmt.Errorf("metrics_port must be 1-65535, got %d", g.MetricsPort)
	}
	if g.DashboardPort < 1 || g.DashboardPort > 65535 {
		return fmt.Errorf("dashboard_port must be 1-65535, got %d", g.DashboardPort)
	}
	if g.SessionTTL < 1 {
		return fmt.Errorf("session_ttl must be positive, got %d", g.SessionTTL)
	}
	if g.QueueTimeout < 0 {
		return fmt.Errorf("queue_timeout cannot be negative, got %d", g.QueueTimeout)
	}
	return nil
}

// Validate checks ClientConfig for errors.
func (c *ClientConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Decode PSK from base64 if provided as string
	if c.PSKBase64 != "" && len(c.PSK) == 0 {
		decoded, err := base64.StdEncoding.DecodeString(c.PSKBase64)
		if err != nil {
			return fmt.Errorf("invalid PSK base64: %w", err)
		}
		c.PSK = decoded
	}

	if len(c.PSK) == 0 {
		return fmt.Errorf("PSK is required")
	}

	if c.PortRangeStart > c.PortRangeEnd {
		return fmt.Errorf("port_range_start (%d) > port_range_end (%d)",
			c.PortRangeStart, c.PortRangeEnd)
	}

	if c.PortRangeStart < 1024 {
		return fmt.Errorf("port_range_start must be >= 1024, got %d", c.PortRangeStart)
	}

	if c.BandwidthLimit != "" {
		if _, err := ParseBandwidth(c.BandwidthLimit); err != nil {
			return fmt.Errorf("invalid bandwidth_limit: %w", err)
		}
	}

	if c.ConnRateLimit < 0 {
		return fmt.Errorf("conn_rate_limit cannot be negative, got %d", c.ConnRateLimit)
	}

	// Validate traffic classes sum to 100 if specified
	if len(c.TrafficClasses) > 0 {
		total := 0
		for class, pct := range c.TrafficClasses {
			if pct < 0 || pct > 100 {
				return fmt.Errorf("traffic class %s percentage must be 0-100, got %d",
					class, pct)
			}
			total += pct
		}
		if total != 100 {
			return fmt.Errorf("traffic class percentages must sum to 100, got %d", total)
		}
	}

	return nil
}

// portsOverlap returns true if two port ranges overlap.
func portsOverlap(start1, end1, start2, end2 uint16) bool {
	return start1 <= end2 && start2 <= end1
}

// bandwidthRegex matches bandwidth strings like "100mbit", "1gbit", "500kbit"
var bandwidthRegex = regexp.MustCompile(`^(\d+)(k|m|g)?bit$`)

// ParseBandwidth parses a bandwidth string like "100mbit" into bits per second.
func ParseBandwidth(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	matches := bandwidthRegex.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid bandwidth format: %s (expected: NNNkbit/mbit/gbit)", s)
	}

	value, _ := strconv.ParseUint(matches[1], 10, 64)
	multiplier := uint64(1)

	switch matches[2] {
	case "k":
		multiplier = 1000
	case "m":
		multiplier = 1000000
	case "g":
		multiplier = 1000000000
	case "":
		multiplier = 1
	}

	return value * multiplier, nil
}

// FormatBandwidth formats bits per second as a human-readable string.
func FormatBandwidth(bps uint64) string {
	switch {
	case bps >= 1000000000:
		return fmt.Sprintf("%dgbit", bps/1000000000)
	case bps >= 1000000:
		return fmt.Sprintf("%dmbit", bps/1000000)
	case bps >= 1000:
		return fmt.Sprintf("%dkbit", bps/1000)
	default:
		return fmt.Sprintf("%dbit", bps)
	}
}

// TrafficClass represents a QoS traffic class.
type TrafficClass int

const (
	TrafficClassRealtime    TrafficClass = 0
	TrafficClassInteractive TrafficClass = 1
	TrafficClassBulk        TrafficClass = 2
	TrafficClassBackground  TrafficClass = 3
)

// TrafficClassNames maps class IDs to human-readable names.
var TrafficClassNames = map[TrafficClass]string{
	TrafficClassRealtime:    "realtime",
	TrafficClassInteractive: "interactive",
	TrafficClassBulk:        "bulk",
	TrafficClassBackground:  "background",
}

// TrafficClassFromName converts a name to a TrafficClass.
func TrafficClassFromName(name string) (TrafficClass, bool) {
	switch strings.ToLower(name) {
	case "realtime":
		return TrafficClassRealtime, true
	case "interactive":
		return TrafficClassInteractive, true
	case "bulk":
		return TrafficClassBulk, true
	case "background":
		return TrafficClassBackground, true
	default:
		return 0, false
	}
}
