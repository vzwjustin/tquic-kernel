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
	// RTTMs triggers alert when SRTT exceeds this in milliseconds (default: 500)
	RTTMs float64

	// RetransThreshold triggers alert when retrans exceeds this per interval
	RetransThreshold uint64
}

// DefaultAlertThresholds returns default alert thresholds.
func DefaultAlertThresholds() AlertThresholds {
	return AlertThresholds{
		RTTMs:            500.0,
		RetransThreshold: 100,
	}
}

// Alerter monitors path statistics and generates alerts for degradation.
type Alerter struct {
	syslog     *syslog.Writer
	thresholds AlertThresholds

	alertedPaths map[string]bool
	lastStats    map[uint32]netlink.PathStats
	mu           sync.Mutex
}

// NewAlerter creates a new alerter with default thresholds.
func NewAlerter(syslogWriter *syslog.Writer) *Alerter {
	return &Alerter{
		syslog:       syslogWriter,
		thresholds:   DefaultAlertThresholds(),
		alertedPaths: make(map[string]bool),
		lastStats:    make(map[uint32]netlink.PathStats),
	}
}

// SetThresholds updates the alert thresholds.
func (a *Alerter) SetThresholds(thresholds AlertThresholds) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.thresholds = thresholds
}

// CheckPaths checks all paths for degradation and returns alert messages.
func (a *Alerter) CheckPaths(stats []netlink.PathStats) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var alerts []string

	for _, ps := range stats {
		pathKey := fmt.Sprintf("path:%d", ps.PathID)

		// Check RTT threshold
		rttMs := float64(ps.SRTT) / 1000.0
		if rttMs > a.thresholds.RTTMs {
			alert := a.generateAlert(pathKey, ps.PathID, "high_rtt",
				fmt.Sprintf("SRTT %.1fms exceeds %.1fms", rttMs, a.thresholds.RTTMs))
			if alert != "" {
				alerts = append(alerts, alert)
			}
		}

		// Check retransmission spike
		if last, ok := a.lastStats[ps.PathID]; ok {
			retransDelta := ps.Retrans - last.Retrans
			if retransDelta > a.thresholds.RetransThreshold {
				alert := a.generateAlert(pathKey, ps.PathID, "high_retrans",
					fmt.Sprintf("%d retransmissions in interval", retransDelta))
				if alert != "" {
					alerts = append(alerts, alert)
				}
			}
		}

		// Clear alert state if path is now healthy
		rttOk := rttMs <= a.thresholds.RTTMs
		if rttOk {
			if a.alertedPaths[pathKey+":high_rtt"] {
				delete(a.alertedPaths, pathKey+":high_rtt")
				msg := fmt.Sprintf("TQUIC path recovered: path %d", ps.PathID)
				a.logInfo(msg)
				alerts = append(alerts, msg)
			}
		}

		a.lastStats[ps.PathID] = ps
	}

	return alerts
}

// generateAlert creates an alert message and logs to syslog.
func (a *Alerter) generateAlert(pathKey string, pathID uint32, reason, detail string) string {
	alertKey := fmt.Sprintf("%s:%s", pathKey, reason)
	if a.alertedPaths[alertKey] {
		return ""
	}

	a.alertedPaths[alertKey] = true

	msg := fmt.Sprintf("TQUIC path degraded: path %d - %s (%s)", pathID, reason, detail)
	a.logWarning(msg)
	return msg
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

func (a *Alerter) logWarning(msg string) {
	if a.syslog != nil {
		a.syslog.Warning(msg)
	}
}

func (a *Alerter) logInfo(msg string) {
	if a.syslog != nil {
		a.syslog.Info(msg)
	}
}
