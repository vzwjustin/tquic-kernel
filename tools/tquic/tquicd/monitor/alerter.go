// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package monitor

import (
	"fmt"
	"log/syslog"
	"sync"

	"github.com/linux/tquicd/netlink"
)

// AlertThresholds defines thresholds for path degradation alerts.
type AlertThresholds struct {
	// LossPercent triggers alert when loss exceeds this percentage (default: 5)
	LossPercent float64

	// RttMs triggers alert when RTT exceeds this in milliseconds (default: 500)
	RttMs float64

	// JitterMs triggers alert when jitter exceeds this in milliseconds (default: 100)
	JitterMs float64
}

// DefaultAlertThresholds returns default alert thresholds.
func DefaultAlertThresholds() AlertThresholds {
	return AlertThresholds{
		LossPercent: 5.0,
		RttMs:       500.0,
		JitterMs:    100.0,
	}
}

// Alerter monitors path statistics and generates alerts for degradation.
type Alerter struct {
	syslog     *syslog.Writer
	thresholds AlertThresholds

	// Track alert state to avoid repeated alerts
	alertedPaths map[string]bool
	mu           sync.Mutex
}

// NewAlerter creates a new alerter with default thresholds.
func NewAlerter(syslogWriter *syslog.Writer) *Alerter {
	return &Alerter{
		syslog:       syslogWriter,
		thresholds:   DefaultAlertThresholds(),
		alertedPaths: make(map[string]bool),
	}
}

// NewAlerterWithThresholds creates a new alerter with custom thresholds.
func NewAlerterWithThresholds(syslogWriter *syslog.Writer, thresholds AlertThresholds) *Alerter {
	return &Alerter{
		syslog:       syslogWriter,
		thresholds:   thresholds,
		alertedPaths: make(map[string]bool),
	}
}

// SetThresholds updates the alert thresholds.
func (a *Alerter) SetThresholds(thresholds AlertThresholds) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.thresholds = thresholds
}

// CheckPaths checks all paths for degradation and returns alert messages.
// It also logs alerts to syslog.
func (a *Alerter) CheckPaths(stats []netlink.PathStats) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var alerts []string

	for _, ps := range stats {
		pathKey := fmt.Sprintf("%s:%d", ps.ClientName, ps.PathID)

		// Check loss threshold
		lossPercent := ps.LossRatio() * 100
		if lossPercent > a.thresholds.LossPercent {
			alert := a.generateAlert(pathKey, ps, "high_loss",
				fmt.Sprintf("loss %.1f%% exceeds %.1f%%", lossPercent, a.thresholds.LossPercent))
			if alert != "" {
				alerts = append(alerts, alert)
			}
		}

		// Check RTT threshold
		rttMs := float64(ps.RttAvg) / 1000.0
		if rttMs > a.thresholds.RttMs {
			alert := a.generateAlert(pathKey, ps, "high_rtt",
				fmt.Sprintf("RTT %.1fms exceeds %.1fms", rttMs, a.thresholds.RttMs))
			if alert != "" {
				alerts = append(alerts, alert)
			}
		}

		// Check jitter threshold
		jitterMs := float64(ps.Jitter) / 1000.0
		if jitterMs > a.thresholds.JitterMs {
			alert := a.generateAlert(pathKey, ps, "high_jitter",
				fmt.Sprintf("jitter %.1fms exceeds %.1fms", jitterMs, a.thresholds.JitterMs))
			if alert != "" {
				alerts = append(alerts, alert)
			}
		}

		// Clear alert state if path is now healthy
		if lossPercent <= a.thresholds.LossPercent &&
			rttMs <= a.thresholds.RttMs &&
			jitterMs <= a.thresholds.JitterMs {
			if a.alertedPaths[pathKey] {
				delete(a.alertedPaths, pathKey)
				msg := fmt.Sprintf("TQUIC path recovered: %s path %d",
					ps.ClientName, ps.PathID)
				a.logInfo(msg)
				alerts = append(alerts, msg)
			}
		}
	}

	return alerts
}

// generateAlert creates an alert message and logs to syslog.
// Returns empty string if this path is already alerting for this reason.
func (a *Alerter) generateAlert(pathKey string, ps netlink.PathStats, reason, detail string) string {
	// Skip if already alerting
	alertKey := fmt.Sprintf("%s:%s", pathKey, reason)
	if a.alertedPaths[alertKey] {
		return ""
	}

	a.alertedPaths[alertKey] = true

	msg := fmt.Sprintf("TQUIC path degraded: %s path %d - %s (%s)",
		ps.ClientName, ps.PathID, reason, detail)

	a.logWarning(msg)
	return msg
}

// ClearAlert clears the alert state for a path.
func (a *Alerter) ClearAlert(clientName string, pathID uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pathKey := fmt.Sprintf("%s:%d", clientName, pathID)

	// Clear all alert types for this path
	for key := range a.alertedPaths {
		if len(key) > len(pathKey) && key[:len(pathKey)+1] == pathKey+":" {
			delete(a.alertedPaths, key)
		}
	}
}

// GetAlertedPaths returns a list of currently alerted paths.
func (a *Alerter) GetAlertedPaths() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	paths := make([]string, 0, len(a.alertedPaths))
	for key := range a.alertedPaths {
		paths = append(paths, key)
	}
	return paths
}

// logWarning logs a warning message to syslog.
func (a *Alerter) logWarning(msg string) {
	if a.syslog != nil {
		a.syslog.Warning(msg)
	}
}

// logInfo logs an info message to syslog.
func (a *Alerter) logInfo(msg string) {
	if a.syslog != nil {
		a.syslog.Info(msg)
	}
}
