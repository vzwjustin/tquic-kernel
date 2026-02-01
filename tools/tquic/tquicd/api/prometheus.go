// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// Package api provides HTTP handlers for Prometheus metrics,
// web dashboard, and blocklist management.
package api

import (
	"net/http"

	"github.com/linux/tquicd/monitor"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusHandler wraps the standard Prometheus HTTP handler.
type PrometheusHandler struct {
	collector *monitor.Collector
	handler   http.Handler
}

// NewPrometheusHandler creates a new Prometheus metrics handler.
func NewPrometheusHandler(collector *monitor.Collector) *PrometheusHandler {
	return &PrometheusHandler{
		collector: collector,
		handler:   promhttp.Handler(),
	}
}

// ServeHTTP implements http.Handler.
func (h *PrometheusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Metrics are exposed at /metrics
	// No authentication - internal network only per CONTEXT.md
	h.handler.ServeHTTP(w, r)
}
