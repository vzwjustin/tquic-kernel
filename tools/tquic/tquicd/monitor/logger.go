// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package monitor

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"sync"
	"time"

	"github.com/linux/tquicd/netlink"
)

// PathEventLogEntry represents a single path event in the log.
type PathEventLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	PathID    uint32    `json:"path_id"`
	Reason    uint32    `json:"reason,omitempty"`
	OldPathID uint32    `json:"old_path_id,omitempty"`
	NewPathID uint32    `json:"new_path_id,omitempty"`
}

// EventActionNames maps event types to action names.
var EventActionNames = map[int]string{
	netlink.EventPathUp:    "path_up",
	netlink.EventPathDown:  "path_down",
	netlink.EventPathChange: "path_change",
	netlink.EventMigration: "migration",
}

// ConnectionLogger logs path events to both syslog and a JSON file.
type ConnectionLogger struct {
	syslog *syslog.Writer
	file   *os.File
	mu     sync.Mutex

	recent   []PathEventLogEntry
	recentMu sync.RWMutex
	maxRecent int
}

// NewConnectionLogger creates a new connection logger.
func NewConnectionLogger(syslogWriter *syslog.Writer, filePath string) (*ConnectionLogger, error) {
	var file *os.File
	var err error

	if filePath != "" {
		file, err = os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
	}

	return &ConnectionLogger{
		syslog:    syslogWriter,
		file:      file,
		recent:    make([]PathEventLogEntry, 0, 100),
		maxRecent: 100,
	}, nil
}

// LogPathEvent logs a path event.
func (l *ConnectionLogger) LogPathEvent(event netlink.PathEvent) {
	entry := PathEventLogEntry{
		Timestamp: event.Timestamp,
		EventType: event.TypeName(),
		PathID:    event.PathID,
		Reason:    event.Reason,
		OldPathID: event.OldPathID,
		NewPathID: event.NewPathID,
	}

	l.logToSyslog(entry)
	l.logToFile(entry)
	l.addToRecent(entry)
}

func (l *ConnectionLogger) logToSyslog(entry PathEventLogEntry) {
	if l.syslog == nil {
		return
	}

	msg := fmt.Sprintf("TQUIC %s: path=%d reason=%d",
		entry.EventType, entry.PathID, entry.Reason)

	if entry.OldPathID != 0 || entry.NewPathID != 0 {
		msg += fmt.Sprintf(" old_path=%d new_path=%d", entry.OldPathID, entry.NewPathID)
	}

	l.syslog.Info(msg)
}

func (l *ConnectionLogger) logToFile(entry PathEventLogEntry) {
	if l.file == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	json.NewEncoder(l.file).Encode(entry)
}

func (l *ConnectionLogger) addToRecent(entry PathEventLogEntry) {
	l.recentMu.Lock()
	defer l.recentMu.Unlock()

	if len(l.recent) >= l.maxRecent {
		l.recent = l.recent[1:]
	}
	l.recent = append(l.recent, entry)
}

// GetRecent returns the n most recent events.
func (l *ConnectionLogger) GetRecent(n int) []PathEventLogEntry {
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	if n > len(l.recent) {
		n = len(l.recent)
	}

	result := make([]PathEventLogEntry, n)
	for i := 0; i < n; i++ {
		result[i] = l.recent[len(l.recent)-1-i]
	}
	return result
}

// GetStats returns statistics about logged events.
func (l *ConnectionLogger) GetStats() EventLogStats {
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	stats := EventLogStats{
		TotalLogged: len(l.recent),
		ByEventType: make(map[string]int),
	}

	for _, entry := range l.recent {
		stats.ByEventType[entry.EventType]++
	}

	return stats
}

// EventLogStats contains statistics about logged events.
type EventLogStats struct {
	TotalLogged int
	ByEventType map[string]int
}

// Close closes the logger.
func (l *ConnectionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Flush ensures all data is written to disk.
func (l *ConnectionLogger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Sync()
	}
	return nil
}
