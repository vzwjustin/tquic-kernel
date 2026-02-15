// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package netlink

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// Client communicates with the TQUIC kernel module via generic netlink.
type Client struct {
	conn     *genetlink.Conn
	family   genetlink.Family
	mu       sync.Mutex
	closed   bool
	eventsCh chan PathEvent
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
			eventsCh: make(chan PathEvent, 100),
		}, nil
	}

	return &Client{
		conn:     conn,
		family:   family,
		eventsCh: make(chan PathEvent, 100),
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

// AddPath adds a new path to the kernel for multipath bonding.
func (c *Client) AddPath(connID uint64, ifindex int32, localIP, remoteIP net.IP, family uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint64(AttrConnID, connID)
	ae.Int32(AttrPathIfindex, ifindex)
	ae.Uint16(AttrFamily, family)

	if family == syscall.AF_INET {
		ae.Bytes(AttrLocalAddr4, localIP.To4())
		ae.Bytes(AttrRemoteAddr4, remoteIP.To4())
	} else {
		ae.Bytes(AttrLocalAddr6, localIP.To16())
		ae.Bytes(AttrRemoteAddr6, remoteIP.To16())
	}

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdPathAdd,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("execute path add: %w", err)
	}

	return nil
}

// RemovePath removes a path from the kernel.
func (c *Client) RemovePath(pathID uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrPathID, pathID)

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdPathRemove,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// SetPathWeight updates a path's scheduling weight.
func (c *Client) SetPathWeight(pathID, weight uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrPathID, pathID)
	ae.Uint32(AttrPathWeight, weight)

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdPathSet,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// GetPath retrieves information about a specific path.
func (c *Client) GetPath(pathID uint32) (*PathInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrPathID, pathID)

	attrs, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdPathGet,
			Version: 1,
		},
		Data: attrs,
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request)
	if err != nil {
		return nil, fmt.Errorf("execute path get: %w", err)
	}

	if len(msgs) == 0 {
		return nil, fmt.Errorf("no response for path %d", pathID)
	}

	return parsePathInfo(msgs[0].Data)
}

// ListPaths retrieves all paths for a connection from the kernel.
func (c *Client) ListPaths() ([]PathInfo, error) {
	return c.ListPathsForConn(0)
}

// ListPathsForConn retrieves paths for a specific connection.
func (c *Client) ListPathsForConn(connID uint64) ([]PathInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint64(AttrConnID, connID)

	attrs, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdPathList,
			Version: 1,
		},
		Data: attrs,
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("execute path list: %w", err)
	}

	var paths []PathInfo
	for _, m := range msgs {
		pi, err := parsePathInfo(m.Data)
		if err != nil {
			continue
		}
		paths = append(paths, *pi)
	}

	return paths, nil
}

// SetScheduler sets the multipath scheduler for a connection.
func (c *Client) SetScheduler(connID uint64, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint64(AttrConnID, connID)
	ae.String(AttrSchedName, name)

	attrs, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdSchedSet,
			Version: 1,
		},
		Data: attrs,
	}

	_, err = c.conn.Execute(msg, c.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// GetScheduler returns the current scheduler name for a connection.
func (c *Client) GetScheduler(connID uint64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint64(AttrConnID, connID)

	attrs, err := ae.Encode()
	if err != nil {
		return "", fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdSchedGet,
			Version: 1,
		},
		Data: attrs,
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request)
	if err != nil {
		return "", fmt.Errorf("execute sched get: %w", err)
	}

	if len(msgs) == 0 {
		return "", fmt.Errorf("no response")
	}

	ad, err := netlink.NewAttributeDecoder(msgs[0].Data)
	if err != nil {
		return "", err
	}

	for ad.Next() {
		if ad.Type() == AttrSchedName {
			return ad.String(), nil
		}
	}

	return "", fmt.Errorf("scheduler name not found in response")
}

// GetStats retrieves statistics for a connection from the kernel.
func (c *Client) GetStats() ([]PathStats, error) {
	return c.GetStatsForConn(0)
}

// GetStatsForConn retrieves stats for a specific connection.
func (c *Client) GetStatsForConn(connID uint64) ([]PathStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("kernel module not loaded")
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint64(AttrConnID, connID)

	attrs, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: CmdStatsGet,
			Version: 1,
		},
		Data: attrs,
	}

	msgs, err := c.conn.Execute(msg, c.family.ID, netlink.Request)
	if err != nil {
		return nil, fmt.Errorf("execute stats get: %w", err)
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

// GetPathStats is an alias for GetStats for backward compatibility with the collector.
func (c *Client) GetPathStats(_ string) ([]PathStats, error) {
	return c.GetStats()
}

// SubscribePathEvents subscribes to kernel path events via multicast.
func (c *Client) SubscribePathEvents(handler func(PathEvent)) error {
	if c.conn == nil {
		return fmt.Errorf("kernel module not loaded")
	}

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

	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial for multicast: %w", err)
	}
	defer conn.Close()

	if err := conn.JoinGroup(mcGroup); err != nil {
		return fmt.Errorf("join multicast group: %w", err)
	}

	for {
		msgs, _, err := conn.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}

		for _, msg := range msgs {
			event, err := parsePathEvent(msg.Data)
			if err != nil {
				continue
			}
			handler(event)
		}
	}
}

// SubscribePathEventsContext subscribes with context for cancellation.
func (c *Client) SubscribePathEventsContext(ctx context.Context, handler func(PathEvent)) error {
	errCh := make(chan error, 1)

	go func() {
		errCh <- c.SubscribePathEvents(handler)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// decodePathAttrs fills a PathInfo from a netlink attribute decoder.
func decodePathAttrs(ad *netlink.AttributeDecoder, pi *PathInfo) {
	for ad.Next() {
		switch ad.Type() {
		case AttrPathID:
			pi.PathID = ad.Uint32()
		case AttrPathState:
			pi.State = ad.Uint8()
		case AttrPathPriority:
			pi.Priority = ad.Uint8()
		case AttrFamily:
			pi.Family = ad.Uint16()
		case AttrPathIfindex:
			pi.Ifindex = ad.Int32()
		case AttrPathFlags:
			pi.Flags = ad.Uint32()
		case AttrPathWeight:
			pi.Weight = ad.Uint32()
		case AttrPathRTT:
			pi.RTT = ad.Uint32()
		case AttrPathBandwidth:
			pi.Bandwidth = ad.Uint64()
		case AttrPathLossRate:
			pi.LossRate = ad.Uint32()
		case AttrLocalAddr4:
			pi.LocalIP = net.IP(ad.Bytes())
		case AttrRemoteAddr4:
			pi.RemoteIP = net.IP(ad.Bytes())
		case AttrLocalAddr6:
			pi.LocalIP = net.IP(ad.Bytes())
		case AttrRemoteAddr6:
			pi.RemoteIP = net.IP(ad.Bytes())
		case AttrLocalPort:
			pi.LocalPort = ad.Uint16()
		case AttrRemotePort:
			pi.RemotePort = ad.Uint16()
		}
	}
}

// parsePathInfo parses netlink attributes into PathInfo.
// Handles both flat attributes and nested PATH_ENTRY from dump responses.
func parsePathInfo(data []byte) (*PathInfo, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}

	var pi PathInfo
	for ad.Next() {
		if ad.Type() == AttrPathEntry {
			// Nested path entry from dump handler
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				decodePathAttrs(nad, &pi)
				return nad.Err()
			})
		}
	}

	// If no nested entry was found, try flat parsing (e.g., from GetPath)
	if pi.PathID == 0 && pi.Ifindex == 0 && pi.State == 0 {
		ad2, err := netlink.NewAttributeDecoder(data)
		if err != nil {
			return nil, err
		}
		decodePathAttrs(ad2, &pi)
		if err := ad2.Err(); err != nil {
			return nil, err
		}
	}

	return &pi, ad.Err()
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
		case AttrPathID:
			ps.PathID = ad.Uint32()
		case AttrStatsTxPackets:
			ps.TxPackets = ad.Uint64()
		case AttrStatsRxPackets:
			ps.RxPackets = ad.Uint64()
		case AttrStatsTxBytes:
			ps.TxBytes = ad.Uint64()
		case AttrStatsRxBytes:
			ps.RxBytes = ad.Uint64()
		case AttrStatsRetrans:
			ps.Retrans = ad.Uint64()
		case AttrStatsSpurious:
			ps.Spurious = ad.Uint64()
		case AttrStatsCwnd:
			ps.Cwnd = ad.Uint32()
		case AttrStatsSRTT:
			ps.SRTT = ad.Uint32()
		case AttrStatsRTTVar:
			ps.RTTVar = ad.Uint32()
		}
	}

	return ps, ad.Err()
}

// parsePathEvent parses netlink attributes into PathEvent.
func parsePathEvent(data []byte) (PathEvent, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return PathEvent{}, err
	}

	var event PathEvent
	event.Timestamp = time.Now()

	for ad.Next() {
		switch ad.Type() {
		case AttrEventType:
			event.Type = int(ad.Uint8())
		case AttrEventReason:
			event.Reason = ad.Uint32()
		case AttrPathID:
			event.PathID = ad.Uint32()
		case AttrOldPathID:
			event.OldPathID = ad.Uint32()
		case AttrNewPathID:
			event.NewPathID = ad.Uint32()
		}
	}

	return event, ad.Err()
}
