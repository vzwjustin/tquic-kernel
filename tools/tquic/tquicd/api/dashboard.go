// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/linux/tquicd/config"
	"github.com/linux/tquicd/monitor"
	"github.com/linux/tquicd/netlink"
)

// DashboardHandler serves the web dashboard and API endpoints.
type DashboardHandler struct {
	nlClient     *netlink.Client
	configLoader *config.Loader
	connLogger   *monitor.ConnectionLogger
}

// NewDashboardHandler creates a new dashboard handler.
func NewDashboardHandler(nlClient *netlink.Client, configLoader *config.Loader, connLogger *monitor.ConnectionLogger) *DashboardHandler {
	return &DashboardHandler{
		nlClient:     nlClient,
		configLoader: configLoader,
		connLogger:   connLogger,
	}
}

// ServeHTTP implements http.Handler.
func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/" || r.URL.Path == "/dashboard":
		h.serveDashboard(w, r)
	case r.URL.Path == "/api/stats":
		h.serveStats(w, r)
	case r.URL.Path == "/api/connections/recent":
		h.serveRecentConnections(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveDashboard serves the main dashboard HTML page.
func (h *DashboardHandler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

// serveStats serves the /api/stats JSON endpoint.
func (h *DashboardHandler) serveStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get path stats from kernel
	pathStats, err := h.nlClient.GetPathStats("")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Get client stats
	clientStats, err := h.nlClient.GetClientStats()
	if err != nil {
		clientStats = nil // Non-fatal
	}

	// Get config for client info
	cfg := h.configLoader.Config()

	// Build response
	resp := StatsResponse{
		Timestamp: time.Now().UTC(),
		Paths:     make([]PathStatsJSON, 0, len(pathStats)),
		Clients:   make([]ClientStatsJSON, 0, len(clientStats)),
	}

	for _, ps := range pathStats {
		health := "healthy"
		if ps.LossRatio() > 0.05 {
			health = "degraded"
		}
		if ps.LossRatio() > 0.20 || ps.RttAvgSeconds() > 1.0 {
			health = "failed"
		}

		resp.Paths = append(resp.Paths, PathStatsJSON{
			ClientName: ps.ClientName,
			PathID:     ps.PathID,
			TxBytes:    ps.TxBytes,
			RxBytes:    ps.RxBytes,
			RttMinMs:   float64(ps.RttMin) / 1000.0,
			RttAvgMs:   float64(ps.RttAvg) / 1000.0,
			RttMaxMs:   float64(ps.RttMax) / 1000.0,
			LossPercent: ps.LossRatio() * 100,
			JitterMs:   float64(ps.Jitter) / 1000.0,
			Health:     health,
		})
	}

	for _, cs := range clientStats {
		var bandwidthLimit string
		if clientCfg, ok := cfg.Clients[cs.ClientName]; ok {
			bandwidthLimit = clientCfg.BandwidthLimit
		}

		resp.Clients = append(resp.Clients, ClientStatsJSON{
			Name:            cs.ClientName,
			ConnectionCount: cs.ConnectionCount,
			TotalBytes:      cs.TotalBytes,
			PathCount:       cs.PathCount,
			BandwidthLimit:  bandwidthLimit,
		})
	}

	json.NewEncoder(w).Encode(resp)
}

// serveRecentConnections serves the /api/connections/recent endpoint.
func (h *DashboardHandler) serveRecentConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	recent := h.connLogger.GetRecent(100)

	resp := RecentConnectionsResponse{
		Connections: make([]ConnectionJSON, 0, len(recent)),
	}

	for _, entry := range recent {
		resp.Connections = append(resp.Connections, ConnectionJSON{
			Timestamp:    entry.Timestamp.UTC(),
			ClientID:     entry.ClientID,
			SourceIP:     entry.SourceIP,
			SourcePort:   entry.SourcePort,
			DestIP:       entry.DestIP,
			DestPort:     entry.DestPort,
			BytesTx:      entry.BytesTx,
			BytesRx:      entry.BytesRx,
			DurationMs:   entry.DurationMs,
			TrafficClass: entry.TrafficClass,
			Action:       entry.Action,
		})
	}

	json.NewEncoder(w).Encode(resp)
}

// StatsResponse is the JSON response for /api/stats.
type StatsResponse struct {
	Timestamp time.Time         `json:"timestamp"`
	Paths     []PathStatsJSON   `json:"paths"`
	Clients   []ClientStatsJSON `json:"clients"`
}

// PathStatsJSON is the JSON representation of path statistics.
type PathStatsJSON struct {
	ClientName  string  `json:"client_name"`
	PathID      uint32  `json:"path_id"`
	TxBytes     uint64  `json:"tx_bytes"`
	RxBytes     uint64  `json:"rx_bytes"`
	RttMinMs    float64 `json:"rtt_min_ms"`
	RttAvgMs    float64 `json:"rtt_avg_ms"`
	RttMaxMs    float64 `json:"rtt_max_ms"`
	LossPercent float64 `json:"loss_percent"`
	JitterMs    float64 `json:"jitter_ms"`
	Health      string  `json:"health"` // "healthy", "degraded", "failed"
}

// ClientStatsJSON is the JSON representation of client statistics.
type ClientStatsJSON struct {
	Name            string `json:"name"`
	ConnectionCount uint32 `json:"connection_count"`
	TotalBytes      uint64 `json:"total_bytes"`
	PathCount       uint32 `json:"path_count"`
	BandwidthLimit  string `json:"bandwidth_limit,omitempty"`
}

// RecentConnectionsResponse is the JSON response for /api/connections/recent.
type RecentConnectionsResponse struct {
	Connections []ConnectionJSON `json:"connections"`
}

// ConnectionJSON is the JSON representation of a connection event.
type ConnectionJSON struct {
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

// dashboardHTML is the complete dashboard HTML with inline CSS and JS.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TQUIC Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 14px; text-transform: uppercase; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
        }
        .card-title {
            font-weight: 600;
            color: #f0f6fc;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }
        .status.healthy { background: #3fb950; }
        .status.degraded { background: #d29922; }
        .status.failed { background: #f85149; }
        .metric { display: flex; justify-content: space-between; padding: 4px 0; }
        .metric-label { color: #8b949e; }
        .metric-value { font-family: monospace; color: #c9d1d9; }
        .connections-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        .connections-table th, .connections-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        .connections-table th { color: #8b949e; font-weight: 500; }
        .action-open { color: #3fb950; }
        .action-close { color: #8b949e; }
        .action-migrate { color: #58a6ff; }
        .timestamp { color: #8b949e; font-size: 12px; }
        .refresh-info { color: #8b949e; font-size: 12px; margin-top: 10px; }
        .error { color: #f85149; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <h1>TQUIC Dashboard</h1>
    <p class="timestamp" id="last-update"></p>

    <h2>Path Statistics</h2>
    <div class="grid" id="paths-grid">
        <div class="card"><p>Loading...</p></div>
    </div>

    <h2>Client Statistics</h2>
    <div class="grid" id="clients-grid">
        <div class="card"><p>Loading...</p></div>
    </div>

    <h2>Recent Connections</h2>
    <div class="card">
        <table class="connections-table" id="connections-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Client</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Tx/Rx</th>
                    <th>Duration</th>
                    <th>Class</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="connections-body">
                <tr><td colspan="8">Loading...</td></tr>
            </tbody>
        </table>
    </div>

    <p class="refresh-info">Auto-refreshes every 5 seconds</p>

    <script>
        function formatBytes(bytes) {
            if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB';
            if (bytes >= 1e6) return (bytes / 1e6).toFixed(2) + ' MB';
            if (bytes >= 1e3) return (bytes / 1e3).toFixed(2) + ' KB';
            return bytes + ' B';
        }

        function formatDuration(ms) {
            if (ms >= 60000) return (ms / 60000).toFixed(1) + 'm';
            if (ms >= 1000) return (ms / 1000).toFixed(1) + 's';
            return ms + 'ms';
        }

        function formatTime(ts) {
            return new Date(ts).toLocaleTimeString();
        }

        function renderPath(path) {
            return ` + "`" + `
                <div class="card">
                    <div class="card-title">
                        <span class="status ${path.health}"></span>
                        ${path.client_name} - Path ${path.path_id}
                    </div>
                    <div class="metric">
                        <span class="metric-label">Tx</span>
                        <span class="metric-value">${formatBytes(path.tx_bytes)}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Rx</span>
                        <span class="metric-value">${formatBytes(path.rx_bytes)}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">RTT (min/avg/max)</span>
                        <span class="metric-value">${path.rtt_min_ms.toFixed(1)} / ${path.rtt_avg_ms.toFixed(1)} / ${path.rtt_max_ms.toFixed(1)} ms</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Loss</span>
                        <span class="metric-value">${path.loss_percent.toFixed(2)}%</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Jitter</span>
                        <span class="metric-value">${path.jitter_ms.toFixed(2)} ms</span>
                    </div>
                </div>
            ` + "`" + `;
        }

        function renderClient(client) {
            return ` + "`" + `
                <div class="card">
                    <div class="card-title">${client.name}</div>
                    <div class="metric">
                        <span class="metric-label">Connections</span>
                        <span class="metric-value">${client.connection_count}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Total Traffic</span>
                        <span class="metric-value">${formatBytes(client.total_bytes)}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Paths</span>
                        <span class="metric-value">${client.path_count}</span>
                    </div>
                    ${client.bandwidth_limit ? ` + "`" + `
                    <div class="metric">
                        <span class="metric-label">Bandwidth Limit</span>
                        <span class="metric-value">${client.bandwidth_limit}</span>
                    </div>
                    ` + "`" + ` : ''}
                </div>
            ` + "`" + `;
        }

        function renderConnection(conn) {
            return ` + "`" + `
                <tr>
                    <td>${formatTime(conn.timestamp)}</td>
                    <td>${conn.client_id}</td>
                    <td>${conn.source_ip}:${conn.source_port}</td>
                    <td>${conn.dest_ip}:${conn.dest_port}</td>
                    <td>${formatBytes(conn.bytes_tx)} / ${formatBytes(conn.bytes_rx)}</td>
                    <td>${formatDuration(conn.duration_ms)}</td>
                    <td>${conn.traffic_class}</td>
                    <td class="action-${conn.action}">${conn.action}</td>
                </tr>
            ` + "`" + `;
        }

        async function refresh() {
            try {
                // Fetch stats
                const statsResp = await fetch('/api/stats');
                const stats = await statsResp.json();

                if (stats.error) {
                    document.getElementById('paths-grid').innerHTML =
                        '<div class="card error">' + stats.error + '</div>';
                } else {
                    document.getElementById('last-update').textContent =
                        'Last update: ' + new Date(stats.timestamp).toLocaleString();

                    if (stats.paths && stats.paths.length > 0) {
                        document.getElementById('paths-grid').innerHTML =
                            stats.paths.map(renderPath).join('');
                    } else {
                        document.getElementById('paths-grid').innerHTML =
                            '<div class="card">No paths connected</div>';
                    }

                    if (stats.clients && stats.clients.length > 0) {
                        document.getElementById('clients-grid').innerHTML =
                            stats.clients.map(renderClient).join('');
                    } else {
                        document.getElementById('clients-grid').innerHTML =
                            '<div class="card">No clients connected</div>';
                    }
                }

                // Fetch recent connections
                const connResp = await fetch('/api/connections/recent');
                const connData = await connResp.json();

                if (connData.connections && connData.connections.length > 0) {
                    document.getElementById('connections-body').innerHTML =
                        connData.connections.slice(0, 20).map(renderConnection).join('');
                } else {
                    document.getElementById('connections-body').innerHTML =
                        '<tr><td colspan="8">No recent connections</td></tr>';
                }
            } catch (err) {
                console.error('Refresh error:', err);
            }
        }

        // Initial load
        refresh();

        // Auto-refresh every 5 seconds
        setInterval(refresh, 5000);
    </script>
</body>
</html>
`

// formatBytes formats bytes for human readability (Go version).
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// init registers handler functions
func init() {
	// Remove unused import warning
	_ = strings.TrimSpace
}
