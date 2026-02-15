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
	case r.URL.Path == "/api/paths":
		h.servePaths(w, r)
	case r.URL.Path == "/api/events/recent":
		h.serveRecentEvents(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *DashboardHandler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

func (h *DashboardHandler) serveStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats, err := h.nlClient.GetStats()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	resp := StatsResponse{
		Timestamp: time.Now().UTC(),
		Paths:     make([]PathStatsJSON, 0, len(stats)),
	}

	for _, ps := range stats {
		resp.Paths = append(resp.Paths, PathStatsJSON{
			PathID:     ps.PathID,
			TxBytes:    ps.TxBytes,
			RxBytes:    ps.RxBytes,
			TxPackets:  ps.TxPackets,
			RxPackets:  ps.RxPackets,
			Retrans:    ps.Retrans,
			SRTTMs:     float64(ps.SRTT) / 1000.0,
			RTTVarMs:   float64(ps.RTTVar) / 1000.0,
			Cwnd:       ps.Cwnd,
		})
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *DashboardHandler) servePaths(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	paths, err := h.nlClient.ListPaths()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	resp := PathsResponse{
		Timestamp: time.Now().UTC(),
		Paths:     make([]PathInfoJSON, 0, len(paths)),
	}

	for _, pi := range paths {
		var localIP, remoteIP string
		if pi.LocalIP != nil {
			localIP = pi.LocalIP.String()
		}
		if pi.RemoteIP != nil {
			remoteIP = pi.RemoteIP.String()
		}

		resp.Paths = append(resp.Paths, PathInfoJSON{
			PathID:     pi.PathID,
			State:      pi.StateName(),
			Ifindex:    pi.Ifindex,
			LocalIP:    localIP,
			RemoteIP:   remoteIP,
			LocalPort:  pi.LocalPort,
			RemotePort: pi.RemotePort,
			RTTMs:      float64(pi.RTT) / 1000.0,
			Bandwidth:  pi.Bandwidth,
			LossRate:   pi.LossRatio() * 100,
			Weight:     pi.Weight,
			Priority:   pi.Priority,
		})
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *DashboardHandler) serveRecentEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	recent := h.connLogger.GetRecent(100)

	resp := RecentEventsResponse{
		Events: make([]EventJSON, 0, len(recent)),
	}

	for _, entry := range recent {
		resp.Events = append(resp.Events, EventJSON{
			Timestamp: entry.Timestamp.UTC(),
			EventType: entry.EventType,
			PathID:    entry.PathID,
			Reason:    entry.Reason,
		})
	}

	json.NewEncoder(w).Encode(resp)
}

// JSON response types

type StatsResponse struct {
	Timestamp time.Time       `json:"timestamp"`
	Paths     []PathStatsJSON `json:"paths"`
}

type PathStatsJSON struct {
	PathID    uint32  `json:"path_id"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxPackets uint64  `json:"tx_packets"`
	RxPackets uint64  `json:"rx_packets"`
	Retrans   uint64  `json:"retransmissions"`
	SRTTMs    float64 `json:"srtt_ms"`
	RTTVarMs  float64 `json:"rttvar_ms"`
	Cwnd      uint32  `json:"cwnd"`
}

type PathsResponse struct {
	Timestamp time.Time      `json:"timestamp"`
	Paths     []PathInfoJSON `json:"paths"`
}

type PathInfoJSON struct {
	PathID     uint32  `json:"path_id"`
	State      string  `json:"state"`
	Ifindex    int32   `json:"ifindex"`
	LocalIP    string  `json:"local_ip,omitempty"`
	RemoteIP   string  `json:"remote_ip,omitempty"`
	LocalPort  uint16  `json:"local_port,omitempty"`
	RemotePort uint16  `json:"remote_port,omitempty"`
	RTTMs      float64 `json:"rtt_ms"`
	Bandwidth  uint64  `json:"bandwidth_bps"`
	LossRate   float64 `json:"loss_percent"`
	Weight     uint32  `json:"weight"`
	Priority   uint8   `json:"priority"`
}

type RecentEventsResponse struct {
	Events []EventJSON `json:"events"`
}

type EventJSON struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	PathID    uint32    `json:"path_id"`
	Reason    uint32    `json:"reason,omitempty"`
}

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
        .status { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .status.active, .status.validated { background: #3fb950; }
        .status.validating, .status.standby { background: #d29922; }
        .status.degraded, .status.failed { background: #f85149; }
        .status.unknown { background: #8b949e; }
        .metric { display: flex; justify-content: space-between; padding: 4px 0; }
        .metric-label { color: #8b949e; }
        .metric-value { font-family: monospace; color: #c9d1d9; }
        .timestamp { color: #8b949e; font-size: 12px; }
        .refresh-info { color: #8b949e; font-size: 12px; margin-top: 10px; }
        .error { color: #f85149; padding: 20px; text-align: center; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 500; }
    </style>
</head>
<body>
    <h1>TQUIC Dashboard</h1>
    <p class="timestamp" id="last-update"></p>

    <h2>Paths</h2>
    <div class="grid" id="paths-grid">
        <div class="card"><p>Loading...</p></div>
    </div>

    <h2>Path Statistics</h2>
    <div class="grid" id="stats-grid">
        <div class="card"><p>Loading...</p></div>
    </div>

    <h2>Recent Events</h2>
    <div class="card">
        <table id="events-table">
            <thead><tr><th>Time</th><th>Event</th><th>Path</th><th>Reason</th></tr></thead>
            <tbody id="events-body"><tr><td colspan="4">Loading...</td></tr></tbody>
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

        function renderPath(p) {
            return '<div class="card"><div class="card-title"><span class="status ' + p.state + '"></span>Path ' + p.path_id + ' (' + p.state + ')</div>' +
                '<div class="metric"><span class="metric-label">Interface</span><span class="metric-value">ifindex ' + p.ifindex + '</span></div>' +
                (p.local_ip ? '<div class="metric"><span class="metric-label">Local</span><span class="metric-value">' + p.local_ip + '</span></div>' : '') +
                (p.remote_ip ? '<div class="metric"><span class="metric-label">Remote</span><span class="metric-value">' + p.remote_ip + '</span></div>' : '') +
                '<div class="metric"><span class="metric-label">RTT</span><span class="metric-value">' + p.rtt_ms.toFixed(1) + ' ms</span></div>' +
                '<div class="metric"><span class="metric-label">Loss</span><span class="metric-value">' + p.loss_percent.toFixed(2) + '%</span></div>' +
                '<div class="metric"><span class="metric-label">Weight</span><span class="metric-value">' + p.weight + '</span></div>' +
                '</div>';
        }

        function renderStats(s) {
            return '<div class="card"><div class="card-title">Path ' + s.path_id + '</div>' +
                '<div class="metric"><span class="metric-label">Tx</span><span class="metric-value">' + formatBytes(s.tx_bytes) + ' (' + s.tx_packets + ' pkts)</span></div>' +
                '<div class="metric"><span class="metric-label">Rx</span><span class="metric-value">' + formatBytes(s.rx_bytes) + ' (' + s.rx_packets + ' pkts)</span></div>' +
                '<div class="metric"><span class="metric-label">SRTT</span><span class="metric-value">' + s.srtt_ms.toFixed(1) + ' ms</span></div>' +
                '<div class="metric"><span class="metric-label">Retrans</span><span class="metric-value">' + s.retransmissions + '</span></div>' +
                '<div class="metric"><span class="metric-label">CWND</span><span class="metric-value">' + s.cwnd + '</span></div>' +
                '</div>';
        }

        async function refresh() {
            try {
                const [pathsResp, statsResp, eventsResp] = await Promise.all([
                    fetch('/api/paths'), fetch('/api/stats'), fetch('/api/events/recent')
                ]);
                const paths = await pathsResp.json();
                const stats = await statsResp.json();
                const events = await eventsResp.json();

                document.getElementById('last-update').textContent = 'Last update: ' + new Date().toLocaleString();

                if (paths.paths && paths.paths.length > 0) {
                    document.getElementById('paths-grid').innerHTML = paths.paths.map(renderPath).join('');
                } else {
                    document.getElementById('paths-grid').innerHTML = '<div class="card">No paths</div>';
                }

                if (stats.paths && stats.paths.length > 0) {
                    document.getElementById('stats-grid').innerHTML = stats.paths.map(renderStats).join('');
                } else {
                    document.getElementById('stats-grid').innerHTML = '<div class="card">No stats</div>';
                }

                if (events.events && events.events.length > 0) {
                    document.getElementById('events-body').innerHTML = events.events.slice(0, 20).map(e =>
                        '<tr><td>' + new Date(e.timestamp).toLocaleTimeString() + '</td><td>' + e.event_type + '</td><td>' + e.path_id + '</td><td>' + (e.reason || '-') + '</td></tr>'
                    ).join('');
                } else {
                    document.getElementById('events-body').innerHTML = '<tr><td colspan="4">No events</td></tr>';
                }
            } catch (err) { console.error('Refresh error:', err); }
        }

        refresh();
        setInterval(refresh, 5000);
    </script>
</body>
</html>
`

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

func init() {
	_ = strings.TrimSpace
}
