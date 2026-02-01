// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// Package monitor provides Prometheus metrics collection and alerting
// for the TQUIC daemon.
package monitor

import (
	"fmt"
	"sync"

	"github.com/linux/tquicd/netlink"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector gathers metrics from the TQUIC kernel module and exposes
// them via Prometheus.
type Collector struct {
	nlClient *netlink.Client

	// Connection metrics
	connectionsTotal *prometheus.CounterVec
	connectionsActive *prometheus.GaugeVec

	// Path metrics
	pathBytesTotal   *prometheus.CounterVec
	pathRttSeconds   *prometheus.GaugeVec
	pathLossRatio    *prometheus.GaugeVec
	pathJitterSeconds *prometheus.GaugeVec
	pathBandwidthBytes *prometheus.GaugeVec

	// Client metrics
	clientConnectionCount *prometheus.GaugeVec
	clientBytesTotal      *prometheus.CounterVec

	// Alert metrics
	pathDegradedTotal *prometheus.CounterVec

	// Internal state
	lastPathStats map[string]netlink.PathStats
	mu            sync.Mutex
}

// NewCollector creates a new Prometheus metrics collector.
func NewCollector(nlClient *netlink.Client) *Collector {
	c := &Collector{
		nlClient:      nlClient,
		lastPathStats: make(map[string]netlink.PathStats),

		connectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "connections_total",
				Help:      "Total number of TQUIC connections",
			},
			[]string{"client", "traffic_class"},
		),

		connectionsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "connections_active",
				Help:      "Number of active TQUIC connections",
			},
			[]string{"client"},
		),

		pathBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_bytes_total",
				Help:      "Total bytes transferred per path",
			},
			[]string{"client", "path_id", "direction"},
		),

		pathRttSeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_rtt_seconds",
				Help:      "Round-trip time per path in seconds",
			},
			[]string{"client", "path_id", "stat"}, // stat: min, avg, max
		),

		pathLossRatio: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_loss_ratio",
				Help:      "Packet loss ratio per path (0.0-1.0)",
			},
			[]string{"client", "path_id"},
		),

		pathJitterSeconds: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_jitter_seconds",
				Help:      "RTT jitter per path in seconds",
			},
			[]string{"client", "path_id"},
		),

		pathBandwidthBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_bandwidth_bytes",
				Help:      "Estimated bandwidth per path in bytes per second",
			},
			[]string{"client", "path_id"},
		),

		clientConnectionCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "client_connection_count",
				Help:      "Number of connections per client",
			},
			[]string{"client"},
		),

		clientBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "client_bytes_total",
				Help:      "Total bytes transferred per client",
			},
			[]string{"client"},
		),

		pathDegradedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_degraded_total",
				Help:      "Total number of path degradation events",
			},
			[]string{"client", "path_id", "reason"},
		),
	}

	// Register all metrics
	prometheus.MustRegister(c.connectionsTotal)
	prometheus.MustRegister(c.connectionsActive)
	prometheus.MustRegister(c.pathBytesTotal)
	prometheus.MustRegister(c.pathRttSeconds)
	prometheus.MustRegister(c.pathLossRatio)
	prometheus.MustRegister(c.pathJitterSeconds)
	prometheus.MustRegister(c.pathBandwidthBytes)
	prometheus.MustRegister(c.clientConnectionCount)
	prometheus.MustRegister(c.clientBytesTotal)
	prometheus.MustRegister(c.pathDegradedTotal)

	return c
}

// UpdatePathStats updates Prometheus metrics with the latest path statistics.
func (c *Collector) UpdatePathStats(stats []netlink.PathStats) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ps := range stats {
		pathID := formatPathID(ps.PathID)

		// Update byte counters
		c.pathBytesTotal.WithLabelValues(ps.ClientName, pathID, "tx").Add(
			float64(ps.TxBytes) - c.getLastTxBytes(ps.ClientName, ps.PathID),
		)
		c.pathBytesTotal.WithLabelValues(ps.ClientName, pathID, "rx").Add(
			float64(ps.RxBytes) - c.getLastRxBytes(ps.ClientName, ps.PathID),
		)

		// Update RTT gauges
		c.pathRttSeconds.WithLabelValues(ps.ClientName, pathID, "min").Set(ps.RttMinSeconds())
		c.pathRttSeconds.WithLabelValues(ps.ClientName, pathID, "avg").Set(ps.RttAvgSeconds())
		c.pathRttSeconds.WithLabelValues(ps.ClientName, pathID, "max").Set(ps.RttMaxSeconds())

		// Update loss and jitter
		c.pathLossRatio.WithLabelValues(ps.ClientName, pathID).Set(ps.LossRatio())
		c.pathJitterSeconds.WithLabelValues(ps.ClientName, pathID).Set(ps.JitterSeconds())

		// Calculate and update bandwidth estimate
		// bandwidth = (tx_bytes + rx_bytes) / rtt_avg
		if ps.RttAvg > 0 {
			totalBytes := float64(ps.TxBytes + ps.RxBytes)
			rttSec := float64(ps.RttAvg) / 1e6
			bandwidth := totalBytes / rttSec
			c.pathBandwidthBytes.WithLabelValues(ps.ClientName, pathID).Set(bandwidth)
		}

		// Store for delta calculation
		c.lastPathStats[formatPathKey(ps.ClientName, ps.PathID)] = ps
	}
}

// UpdateClientStats updates Prometheus metrics with client statistics.
func (c *Collector) UpdateClientStats(stats []netlink.ClientStats) {
	for _, cs := range stats {
		c.clientConnectionCount.WithLabelValues(cs.ClientName).Set(float64(cs.ConnectionCount))
		c.connectionsActive.WithLabelValues(cs.ClientName).Set(float64(cs.ConnectionCount))
	}
}

// RecordConnection records a new connection event.
func (c *Collector) RecordConnection(event netlink.ConnectionEvent) {
	trafficClass := event.TrafficClassName()
	c.connectionsTotal.WithLabelValues(event.ClientID, trafficClass).Inc()
}

// RecordPathDegraded records a path degradation event.
func (c *Collector) RecordPathDegraded(clientName string, pathID uint32, reason string) {
	c.pathDegradedTotal.WithLabelValues(clientName, formatPathID(pathID), reason).Inc()
}

// getLastTxBytes returns the last known TxBytes for a path.
func (c *Collector) getLastTxBytes(client string, pathID uint32) float64 {
	key := formatPathKey(client, pathID)
	if ps, ok := c.lastPathStats[key]; ok {
		return float64(ps.TxBytes)
	}
	return 0
}

// getLastRxBytes returns the last known RxBytes for a path.
func (c *Collector) getLastRxBytes(client string, pathID uint32) float64 {
	key := formatPathKey(client, pathID)
	if ps, ok := c.lastPathStats[key]; ok {
		return float64(ps.RxBytes)
	}
	return 0
}

// formatPathID converts a path ID to a string for labels.
func formatPathID(id uint32) string {
	return fmt.Sprintf("%d", id)
}

// formatPathKey creates a unique key for a client+path combination.
func formatPathKey(client string, pathID uint32) string {
	return fmt.Sprintf("%s:%d", client, pathID)
}
