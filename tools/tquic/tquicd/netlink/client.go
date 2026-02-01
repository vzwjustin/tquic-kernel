// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package netlink

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/linux/tquicd/config"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// Client communicates with the TQUIC kernel module via generic netlink.
type Client struct {
	conn     *genetlink.Conn
	family   genetlink.Family
	mu       sync.Mutex
	closed   bool
	eventsCh chan ConnectionEvent
}

// NewClient creates a new netlink client connected to the TQUIC family.
func NewClient() (*Client, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial genetlink: %w", err)
	}

	family, err := conn.GetFamily(FamilyName)
	if err != nil {
		conn.Close()
		// Return a client that can be used for graceful degradation
		// when kernel module isn't loaded
		return &Client{
			conn:     nil,
			eventsCh: make(chan ConnectionEvent, 100),
		}, nil
	}

	return &Client{
		conn:     conn,
		family:   family,
		eventsCh: make(chan ConnectionEvent, 100),
	}, nil
}

// Close closes the netlink connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	close(c.eventsCh)

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// RegisterClient registers a client configuration with the kernel.
func (c *Client) RegisterClient(cfg *config.ClientConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	// Build netlink message
	ae := netlink.NewAttributeEncoder()
	ae.String(AttrClientName, cfg.Name)
	ae.Bytes(AttrClientPSK, cfg.PSK)
	ae.Uint16(AttrPortRangeStart, cfg.PortRangeStart)
	ae.Uint16(AttrPortRangeEnd, cfg.PortRangeEnd)

	if cfg.BandwidthLimit != "" {
		if bps, err := config.ParseBandwidth(cfg.BandwidthLimit); err == nil {
			ae.Uint64(AttrBandwidthLimit, bps)
		}
	}

	ae.Uint32(AttrConnRateLimit, uint32(cfg.ConnRateLimit))

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdRegisterClient,
			Version: 1,
		},
		Data: attrs,
	}

	// Send and receive response
	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("execute register: %w", err)
	}

	// Check for errors in response
	if len(msgs) > 0 {
		// Success - kernel acknowledged
		return nil
	}

	return nil
}

// UnregisterClient removes a client registration from the kernel.
func (c *Client) UnregisterClient(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.String(AttrClientName, name)

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdUnregisterClient,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// GetPathStats retrieves per-path statistics from the kernel.
// If clientName is empty, returns stats for all clients.
func (c *Client) GetPathStats(clientName string) ([]PathStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	if clientName != "" {
		ae.String(AttrClientName, clientName)
	}

	attrs, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdGetPathStats,
			Version: 1,
		},
		Data: attrs,
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("execute get path stats: %w", err)
	}

	var stats []PathStats
	for _, m := range msgs {
		ps, err := parsePathStats(m.Data)
		if err != nil {
			continue
		}
		stats = append(stats, ps)
	}

	return stats, nil
}

// GetClientStats retrieves per-client statistics from the kernel.
func (c *Client) GetClientStats() ([]ClientStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("kernel module not loaded")
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdGetClientStats,
			Version: 1,
		},
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("execute get client stats: %w", err)
	}

	var stats []ClientStats
	for _, m := range msgs {
		cs, err := parseClientStats(m.Data)
		if err != nil {
			continue
		}
		stats = append(stats, cs)
	}

	return stats, nil
}

// SetBlocklist updates the kernel blocklist.
func (c *Client) SetBlocklist(ips []string, cidrs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()

	// Add individual IPs
	for _, ip := range ips {
		ae.String(AttrBlocklistIP, ip)
	}

	// Add CIDR ranges
	for _, cidr := range cidrs {
		ae.String(AttrBlocklistCIDR, cidr)
	}

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdSetBlocklist,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// SubscribeConnectionEvents subscribes to kernel connection events via multicast.
// The handler is called for each event. This function blocks until context is cancelled
// or an error occurs.
func (c *Client) SubscribeConnectionEvents(handler func(ConnectionEvent)) error {
	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	// Find the multicast group
	var mcGroup uint32
	for _, g := range c.family.Groups {
		if g.Name == McgrpEvents {
			mcGroup = g.ID
			break
		}
	}

	if mcGroup == 0 {
		return fmt.Errorf("events multicast group not found")
	}

	// Create a new connection for multicast
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial for multicast: %w", err)
	}
	defer conn.Close()

	// Join the multicast group
	if err := conn.JoinGroup(mcGroup); err != nil {
		return fmt.Errorf("join multicast group: %w", err)
	}

	// Receive events
	for {
		msgs, _, err := conn.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}

		for _, msg := range msgs {
			if msg.Header.Command != CmdConnectionEvent {
				continue
			}

			event, err := parseConnectionEvent(msg.Data)
			if err != nil {
				continue
			}

			handler(event)
		}
	}
}

// SubscribeConnectionEventsContext subscribes with context for cancellation.
func (c *Client) SubscribeConnectionEventsContext(ctx context.Context, handler func(ConnectionEvent)) error {
	errCh := make(chan error, 1)

	go func() {
		errCh <- c.SubscribeConnectionEvents(handler)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parsePathStats parses netlink attributes into PathStats.
func parsePathStats(data []byte) (PathStats, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return PathStats{}, err
	}

	var ps PathStats
	for ad.Next() {
		switch ad.Type() {
		case AttrClientName:
			ps.ClientName = ad.String()
		case AttrPathID:
			ps.PathID = ad.Uint32()
		case AttrTxBytes:
			ps.TxBytes = ad.Uint64()
		case AttrRxBytes:
			ps.RxBytes = ad.Uint64()
		case AttrRttMin:
			ps.RttMin = ad.Uint32()
		case AttrRttAvg:
			ps.RttAvg = ad.Uint32()
		case AttrRttMax:
			ps.RttMax = ad.Uint32()
		case AttrLossRate:
			ps.LossRate = ad.Uint32()
		case AttrJitter:
			ps.Jitter = ad.Uint32()
		}
	}

	return ps, ad.Err()
}

// parseClientStats parses netlink attributes into ClientStats.
func parseClientStats(data []byte) (ClientStats, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return ClientStats{}, err
	}

	var cs ClientStats
	for ad.Next() {
		switch ad.Type() {
		case AttrClientName:
			cs.ClientName = ad.String()
		case AttrConnCount:
			cs.ConnectionCount = ad.Uint32()
		case AttrTotalBytes:
			cs.TotalBytes = ad.Uint64()
		}
	}

	return cs, ad.Err()
}

// parseConnectionEvent parses netlink attributes into ConnectionEvent.
func parseConnectionEvent(data []byte) (ConnectionEvent, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return ConnectionEvent{}, err
	}

	var event ConnectionEvent
	event.Timestamp = time.Now() // Default if not provided

	for ad.Next() {
		switch ad.Type() {
		case AttrEventType:
			event.Type = int(ad.Uint32())
		case AttrClientName:
			event.ClientID = ad.String()
		case AttrSourceIP:
			event.SourceIP = net.IP(ad.Bytes())
		case AttrSourcePort:
			event.SourcePort = ad.Uint16()
		case AttrDestIP:
			event.DestIP = net.IP(ad.Bytes())
		case AttrDestPort:
			event.DestPort = ad.Uint16()
		case AttrTxBytes:
			event.BytesTx = ad.Uint64()
		case AttrRxBytes:
			event.BytesRx = ad.Uint64()
		case AttrDurationMs:
			event.DurationMs = ad.Uint64()
		case AttrTrafficClass:
			event.TrafficClass = ad.Uint8()
		case AttrTimestamp:
			// Unix timestamp in seconds
			ts := ad.Uint64()
			event.Timestamp = time.Unix(int64(ts), 0)
		}
	}

	return event, ad.Err()
}
