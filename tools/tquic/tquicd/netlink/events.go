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

// EventSubscriber handles subscription to kernel path events
// via netlink multicast groups.
type EventSubscriber struct {
	familyID   uint16
	mcGroupID  uint32
	conn       *genetlink.Conn
	handler    func(PathEvent)
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
	eventsCh   chan PathEvent
	bufferSize int
}

// EventTypeNames maps event types to human-readable names.
var EventTypeNames = map[int]string{
	EventPathUp:    "path_up",
	EventPathDown:  "path_down",
	EventPathChange: "path_change",
	EventMigration: "migration",
}

// NewEventSubscriber creates a new event subscriber for the given family.
func NewEventSubscriber(familyID uint16, mcGroupID uint32) *EventSubscriber {
	return &EventSubscriber{
		familyID:   familyID,
		mcGroupID:  mcGroupID,
		stopCh:     make(chan struct{}),
		eventsCh:   make(chan PathEvent, 1000),
		bufferSize: 1000,
	}
}

// Start begins listening for events in the background.
func (s *EventSubscriber) Start(ctx context.Context, handler func(PathEvent)) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("subscriber already running")
	}
	s.running = true
	s.handler = handler
	s.mu.Unlock()

	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial genetlink for events: %w", err)
	}
	s.conn = conn

	if err := conn.JoinGroup(s.mcGroupID); err != nil {
		conn.Close()
		return fmt.Errorf("join multicast group %d: %w", s.mcGroupID, err)
	}

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

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		msgs, _, err := s.conn.Receive()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		for _, msg := range msgs {
			event, err := s.parseEvent(msg.Data)
			if err != nil {
				continue
			}

			if s.handler != nil {
				go s.handler(event)
			}

			select {
			case s.eventsCh <- event:
			default:
				select {
				case <-s.eventsCh:
				default:
				}
				s.eventsCh <- event
			}
		}
	}
}

// parseEvent parses a netlink message into a PathEvent.
func (s *EventSubscriber) parseEvent(data []byte) (PathEvent, error) {
	ad, err := mnl.NewAttributeDecoder(data)
	if err != nil {
		return PathEvent{}, fmt.Errorf("decode attributes: %w", err)
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

	if err := ad.Err(); err != nil {
		return PathEvent{}, fmt.Errorf("parse attributes: %w", err)
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
func (s *EventSubscriber) Events() <-chan PathEvent {
	return s.eventsCh
}

// PathEventBuffer provides a ring buffer for path events.
type PathEventBuffer struct {
	events   []PathEvent
	head     int
	count    int
	capacity int
	mu       sync.RWMutex
}

// NewPathEventBuffer creates a new event buffer.
func NewPathEventBuffer(capacity int) *PathEventBuffer {
	return &PathEventBuffer{
		events:   make([]PathEvent, capacity),
		capacity: capacity,
	}
}

// Add adds an event to the buffer.
func (b *PathEventBuffer) Add(event PathEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events[b.head] = event
	b.head = (b.head + 1) % b.capacity
	if b.count < b.capacity {
		b.count++
	}
}

// Recent returns the n most recent events (newest first).
func (b *PathEventBuffer) Recent(n int) []PathEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n > b.count {
		n = b.count
	}

	result := make([]PathEvent, n)
	for i := 0; i < n; i++ {
		idx := (b.head - 1 - i + b.capacity) % b.capacity
		result[i] = b.events[idx]
	}

	return result
}

// Count returns the number of events in the buffer.
func (b *PathEventBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}
