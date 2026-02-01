// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package netlink

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/genetlink"
	mnl "github.com/mdlayher/netlink"
)

// EventSubscriber handles subscription to kernel connection events
// via netlink multicast groups.
type EventSubscriber struct {
	familyID   uint16
	mcGroupID  uint32
	conn       *genetlink.Conn
	handler    func(ConnectionEvent)
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
	eventsCh   chan ConnectionEvent
	bufferSize int
}

// Connection event types emitted by kernel.
const (
	TQUIC_EVENT_CONN_OPEN    = 1 // Connection opened
	TQUIC_EVENT_CONN_CLOSE   = 2 // Connection closed
	TQUIC_EVENT_CONN_MIGRATE = 3 // Connection migrated to new path
)

// EventTypeNames maps event types to human-readable names.
var EventTypeNames = map[int]string{
	TQUIC_EVENT_CONN_OPEN:    "open",
	TQUIC_EVENT_CONN_CLOSE:   "close",
	TQUIC_EVENT_CONN_MIGRATE: "migrate",
}

// NewEventSubscriber creates a new event subscriber for the given family.
func NewEventSubscriber(familyID uint16, mcGroupID uint32) *EventSubscriber {
	return &EventSubscriber{
		familyID:   familyID,
		mcGroupID:  mcGroupID,
		stopCh:     make(chan struct{}),
		eventsCh:   make(chan ConnectionEvent, 1000),
		bufferSize: 1000,
	}
}

// Start begins listening for events in the background.
// Events are passed to the handler function.
func (s *EventSubscriber) Start(ctx context.Context, handler func(ConnectionEvent)) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("subscriber already running")
	}
	s.running = true
	s.handler = handler
	s.mu.Unlock()

	// Create connection for multicast
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial genetlink for events: %w", err)
	}
	s.conn = conn

	// Join multicast group
	if err := conn.JoinGroup(s.mcGroupID); err != nil {
		conn.Close()
		return fmt.Errorf("join multicast group %d: %w", s.mcGroupID, err)
	}

	// Start event loop
	go s.eventLoop(ctx)

	return nil
}

// eventLoop reads events from netlink and dispatches to handler.
func (s *EventSubscriber) eventLoop(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.running = false
		if s.conn != nil {
			s.conn.Close()
			s.conn = nil
		}
		s.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		// Set read deadline to allow periodic checking of stop signal
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		msgs, _, err := s.conn.Receive()
		if err != nil {
			// Timeout is expected, continue
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Real error, log and continue
			continue
		}

		for _, msg := range msgs {
			// Only process connection events
			if msg.Header.Command != CmdConnectionEvent {
				continue
			}

			event, err := s.parseEvent(msg.Data)
			if err != nil {
				continue
			}

			// Call handler in goroutine to avoid blocking
			if s.handler != nil {
				go s.handler(event)
			}

			// Also send to channel for buffered access
			select {
			case s.eventsCh <- event:
			default:
				// Buffer full, drop oldest
				select {
				case <-s.eventsCh:
				default:
				}
				s.eventsCh <- event
			}
		}
	}
}

// parseEvent parses a netlink message into a ConnectionEvent.
func (s *EventSubscriber) parseEvent(data []byte) (ConnectionEvent, error) {
	ad, err := mnl.NewAttributeDecoder(data)
	if err != nil {
		return ConnectionEvent{}, fmt.Errorf("decode attributes: %w", err)
	}

	var event ConnectionEvent
	event.Timestamp = time.Now()

	for ad.Next() {
		switch ad.Type() {
		case AttrEventType:
			event.Type = int(ad.Uint32())
		case AttrClientName:
			event.ClientID = ad.String()
		case AttrSourceIP:
			ipBytes := ad.Bytes()
			if len(ipBytes) == 4 || len(ipBytes) == 16 {
				event.SourceIP = net.IP(ipBytes)
			}
		case AttrSourcePort:
			event.SourcePort = ad.Uint16()
		case AttrDestIP:
			ipBytes := ad.Bytes()
			if len(ipBytes) == 4 || len(ipBytes) == 16 {
				event.DestIP = net.IP(ipBytes)
			}
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
			ts := ad.Uint64()
			if ts > 0 {
				event.Timestamp = time.Unix(int64(ts), 0)
			}
		}
	}

	if err := ad.Err(); err != nil {
		return ConnectionEvent{}, fmt.Errorf("parse attributes: %w", err)
	}

	return event, nil
}

// Stop stops the event subscriber.
func (s *EventSubscriber) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
}

// Events returns a channel of buffered events.
// This is an alternative to the handler callback.
func (s *EventSubscriber) Events() <-chan ConnectionEvent {
	return s.eventsCh
}

// RecentEvents returns the last n events from the buffer.
func (s *EventSubscriber) RecentEvents(n int) []ConnectionEvent {
	events := make([]ConnectionEvent, 0, n)

	// Drain channel into slice
	for {
		select {
		case e := <-s.eventsCh:
			events = append(events, e)
			if len(events) >= n {
				return events
			}
		default:
			return events
		}
	}
}

// ConnectionEventBuffer provides a ring buffer for connection events.
type ConnectionEventBuffer struct {
	events   []ConnectionEvent
	head     int
	count    int
	capacity int
	mu       sync.RWMutex
}

// NewConnectionEventBuffer creates a new event buffer.
func NewConnectionEventBuffer(capacity int) *ConnectionEventBuffer {
	return &ConnectionEventBuffer{
		events:   make([]ConnectionEvent, capacity),
		capacity: capacity,
	}
}

// Add adds an event to the buffer.
func (b *ConnectionEventBuffer) Add(event ConnectionEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events[b.head] = event
	b.head = (b.head + 1) % b.capacity
	if b.count < b.capacity {
		b.count++
	}
}

// Recent returns the n most recent events (newest first).
func (b *ConnectionEventBuffer) Recent(n int) []ConnectionEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n > b.count {
		n = b.count
	}

	result := make([]ConnectionEvent, n)
	for i := 0; i < n; i++ {
		// Work backwards from head
		idx := (b.head - 1 - i + b.capacity) % b.capacity
		result[i] = b.events[idx]
	}

	return result
}

// Count returns the number of events in the buffer.
func (b *ConnectionEventBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}
