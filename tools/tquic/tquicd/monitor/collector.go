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

	// Path metrics
	pathTxBytes    *prometheus.CounterVec
	pathRxBytes    *prometheus.CounterVec
	pathTxPackets  *prometheus.CounterVec
	pathRxPackets  *prometheus.CounterVec
	pathRetrans    *prometheus.CounterVec
	pathSRTT       *prometheus.GaugeVec
	pathRTTVar     *prometheus.GaugeVec
	pathCwnd       *prometheus.GaugeVec
	pathState      *prometheus.GaugeVec

	// Event metrics
	pathEventsTotal *prometheus.CounterVec

	// Internal state
	lastPathStats map[uint32]netlink.PathStats
	mu            sync.Mutex
}

// NewCollector creates a new Prometheus metrics collector.
func NewCollector(nlClient *netlink.Client) *Collector {
	c := &Collector{
		nlClient:      nlClient,
		lastPathStats: make(map[uint32]netlink.PathStats),

		pathTxBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_tx_bytes_total",
				Help:      "Total bytes transmitted per path",
			},
			[]string{"path_id"},
		),

		pathRxBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_rx_bytes_total",
				Help:      "Total bytes received per path",
			},
			[]string{"path_id"},
		),

		pathTxPackets: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_tx_packets_total",
				Help:      "Total packets transmitted per path",
			},
			[]string{"path_id"},
		),

		pathRxPackets: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_rx_packets_total",
				Help:      "Total packets received per path",
			},
			[]string{"path_id"},
		),

		pathRetrans: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_retransmissions_total",
				Help:      "Total retransmissions per path",
			},
			[]string{"path_id"},
		),

		pathSRTT: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_srtt_seconds",
				Help:      "Smoothed round-trip time per path in seconds",
			},
			[]string{"path_id"},
		),

		pathRTTVar: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_rttvar_seconds",
				Help:      "RTT variance per path in seconds",
			},
			[]string{"path_id"},
		),

		pathCwnd: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_cwnd",
				Help:      "Congestion window per path",
			},
			[]string{"path_id"},
		),

		pathState: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "tquic",
				Name:      "path_state",
				Help:      "Path state (0=unknown, 1=validating, 2=validated, 3=active, 4=standby, 5=degraded, 6=failed)",
			},
			[]string{"path_id"},
		),

		pathEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "tquic",
				Name:      "path_events_total",
				Help:      "Total path events by type",
			},
			[]string{"event_type"},
		),
	}

	prometheus.MustRegister(c.pathTxBytes)
	prometheus.MustRegister(c.pathRxBytes)
	prometheus.MustRegister(c.pathTxPackets)
	prometheus.MustRegister(c.pathRxPackets)
	prometheus.MustRegister(c.pathRetrans)
	prometheus.MustRegister(c.pathSRTT)
	prometheus.MustRegister(c.pathRTTVar)
	prometheus.MustRegister(c.pathCwnd)
	prometheus.MustRegister(c.pathState)
	prometheus.MustRegister(c.pathEventsTotal)

	return c
}

// UpdatePathStats updates Prometheus metrics with the latest path statistics.
func (c *Collector) UpdatePathStats(stats []netlink.PathStats) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ps := range stats {
		pathID := formatPathID(ps.PathID)

		// Update counters (delta from last)
		if last, ok := c.lastPathStats[ps.PathID]; ok {
			if ps.TxBytes > last.TxBytes {
				c.pathTxBytes.WithLabelValues(pathID).Add(float64(ps.TxBytes - last.TxBytes))
			}
			if ps.RxBytes > last.RxBytes {
				c.pathRxBytes.WithLabelValues(pathID).Add(float64(ps.RxBytes - last.RxBytes))
			}
			if ps.TxPackets > last.TxPackets {
				c.pathTxPackets.WithLabelValues(pathID).Add(float64(ps.TxPackets - last.TxPackets))
			}
			if ps.RxPackets > last.RxPackets {
				c.pathRxPackets.WithLabelValues(pathID).Add(float64(ps.RxPackets - last.RxPackets))
			}
			if ps.Retrans > last.Retrans {
				c.pathRetrans.WithLabelValues(pathID).Add(float64(ps.Retrans - last.Retrans))
			}
		}

		// Update gauges
		c.pathSRTT.WithLabelValues(pathID).Set(ps.SRTTSeconds())
		c.pathRTTVar.WithLabelValues(pathID).Set(float64(ps.RTTVar) / 1e6)
		c.pathCwnd.WithLabelValues(pathID).Set(float64(ps.Cwnd))

		c.lastPathStats[ps.PathID] = ps
	}
}

// UpdatePathInfo updates path state metrics from PathInfo.
func (c *Collector) UpdatePathInfo(paths []netlink.PathInfo) {
	for _, pi := range paths {
		pathID := formatPathID(pi.PathID)
		c.pathState.WithLabelValues(pathID).Set(float64(pi.State))
	}
}

// RecordPathEvent records a path event.
func (c *Collector) RecordPathEvent(event netlink.PathEvent) {
	c.pathEventsTotal.WithLabelValues(event.TypeName()).Inc()
}

// formatPathID converts a path ID to a string for labels.
func formatPathID(id uint32) string {
	return fmt.Sprintf("%d", id)
}
