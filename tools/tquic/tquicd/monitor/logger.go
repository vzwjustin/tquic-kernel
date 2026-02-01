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

// ConnectionLogEntry represents a single connection event in the log.
type ConnectionLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientID     string    `json:"client_id"`
	SourceIP     string    `json:"source_ip"`
	SourcePort   uint16    `json:"source_port"`
	DestIP       string    `json:"dest_ip"`
	DestPort     uint16    `json:"dest_port"`
	BytesTx      uint64    `json:"bytes_tx"`
	BytesRx      uint64    `json:"bytes_rx"`
	DurationMs   uint64    `json:"duration_ms"`
	TrafficClass string    `json:"traffic_class"`
	Action       string    `json:"action"`
}

// TrafficClassNames maps numeric traffic classes to names.
var TrafficClassNames = map[uint8]string{
	0: "realtime",
	1: "interactive",
	2: "bulk",
	3: "background",
}

// EventTypeNames maps event types to action names.
var EventActionNames = map[int]string{
	netlink.EventConnOpen:    "open",
	netlink.EventConnClose:   "close",
	netlink.EventConnMigrate: "migrate",
}

// ConnectionLogger logs connection events to both syslog and a JSON file.
type ConnectionLogger struct {
	syslog *syslog.Writer
	file   *os.File
	mu     sync.Mutex

	// Ring buffer for recent connections
	recent   []ConnectionLogEntry
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
		recent:    make([]ConnectionLogEntry, 0, 100),
		maxRecent: 100,
	}, nil
}

// LogConnection logs a connection event.
func (l *ConnectionLogger) LogConnection(event netlink.ConnectionEvent) {
	entry := ConnectionLogEntry{
		Timestamp:    event.Timestamp,
		ClientID:     event.ClientID,
		SourceIP:     event.SourceIP.String(),
		SourcePort:   event.SourcePort,
		DestIP:       event.DestIP.String(),
		DestPort:     event.DestPort,
		BytesTx:      event.BytesTx,
		BytesRx:      event.BytesRx,
		DurationMs:   event.DurationMs,
		TrafficClass: getTrafficClassName(event.TrafficClass),
		Action:       getActionName(event.Type),
	}

	// Log to syslog with structured message
	l.logToSyslog(entry)

	// Log to JSON file
	l.logToFile(entry)

	// Add to recent buffer
	l.addToRecent(entry)
}

// logToSyslog writes a structured log entry to syslog.
func (l *ConnectionLogger) logToSyslog(entry ConnectionLogEntry) {
	if l.syslog == nil {
		return
	}

	msg := fmt.Sprintf("TQUIC %s: client=%s src=%s:%d dst=%s:%d tx=%d rx=%d dur=%dms class=%s",
		entry.Action,
		entry.ClientID,
		entry.SourceIP, entry.SourcePort,
		entry.DestIP, entry.DestPort,
		entry.BytesTx, entry.BytesRx,
		entry.DurationMs,
		entry.TrafficClass)

	l.syslog.Info(msg)
}

// logToFile writes a JSON log entry to the log file.
func (l *ConnectionLogger) logToFile(entry ConnectionLogEntry) {
	if l.file == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	encoder := json.NewEncoder(l.file)
	encoder.Encode(entry)
}

// addToRecent adds an entry to the recent buffer (ring buffer).
func (l *ConnectionLogger) addToRecent(entry ConnectionLogEntry) {
	l.recentMu.Lock()
	defer l.recentMu.Unlock()

	if len(l.recent) >= l.maxRecent {
		// Remove oldest entry
		l.recent = l.recent[1:]
	}
	l.recent = append(l.recent, entry)
}

// GetRecent returns the n most recent connection events.
func (l *ConnectionLogger) GetRecent(n int) []ConnectionLogEntry {
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	if n > len(l.recent) {
		n = len(l.recent)
	}

	// Return newest first
	result := make([]ConnectionLogEntry, n)
	for i := 0; i < n; i++ {
		result[i] = l.recent[len(l.recent)-1-i]
	}
	return result
}

// GetRecentByClient returns recent events for a specific client.
func (l *ConnectionLogger) GetRecentByClient(clientID string, n int) []ConnectionLogEntry {
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	result := make([]ConnectionLogEntry, 0, n)
	for i := len(l.recent) - 1; i >= 0 && len(result) < n; i-- {
		if l.recent[i].ClientID == clientID {
			result = append(result, l.recent[i])
		}
	}
	return result
}

// GetStats returns statistics about logged connections.
func (l *ConnectionLogger) GetStats() ConnectionLogStats {
	l.recentMu.RLock()
	defer l.recentMu.RUnlock()

	stats := ConnectionLogStats{
		TotalLogged:    len(l.recent),
		ByAction:       make(map[string]int),
		ByTrafficClass: make(map[string]int),
		ByClient:       make(map[string]int),
	}

	var totalBytes uint64
	var totalDuration uint64

	for _, entry := range l.recent {
		stats.ByAction[entry.Action]++
		stats.ByTrafficClass[entry.TrafficClass]++
		stats.ByClient[entry.ClientID]++
		totalBytes += entry.BytesTx + entry.BytesRx
		totalDuration += entry.DurationMs
	}

	if len(l.recent) > 0 {
		stats.AvgBytesPerConn = totalBytes / uint64(len(l.recent))
		stats.AvgDurationMs = totalDuration / uint64(len(l.recent))
	}

	return stats
}

// ConnectionLogStats contains statistics about logged connections.
type ConnectionLogStats struct {
	TotalLogged     int
	ByAction        map[string]int
	ByTrafficClass  map[string]int
	ByClient        map[string]int
	AvgBytesPerConn uint64
	AvgDurationMs   uint64
}

// Close closes the logger and flushes any buffered data.
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

// getTrafficClassName returns the name for a traffic class.
func getTrafficClassName(class uint8) string {
	if name, ok := TrafficClassNames[class]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", class)
}

// getActionName returns the name for an event type.
func getActionName(eventType int) string {
	if name, ok := EventActionNames[eventType]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", eventType)
}
