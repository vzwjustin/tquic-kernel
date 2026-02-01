// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// tquicd is the userspace control daemon for TQUIC VPS endpoints.
// It manages configuration, exposes Prometheus metrics, provides a web dashboard,
// and logs detailed connection information.
//
// Usage:
//
//	tquicd [-c /etc/tquic.d] [-v]
//
// Configuration is loaded from /etc/tquic.d/*.conf files.
// The daemon supports hot reload via SIGHUP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/linux/tquicd/api"
	"github.com/linux/tquicd/config"
	"github.com/linux/tquicd/monitor"
	"github.com/linux/tquicd/netlink"
	"github.com/linux/tquicd/qos"
)

const (
	// DefaultConfigDir is the default configuration directory
	DefaultConfigDir = "/etc/tquic.d"

	// Version is the daemon version
	Version = "1.0.0"
)

var (
	configDir   = flag.String("c", DefaultConfigDir, "Configuration directory")
	verbose     = flag.Bool("v", false, "Verbose logging")
	showVersion = flag.Bool("version", false, "Show version and exit")
)

// Daemon represents the tquicd daemon instance.
type Daemon struct {
	configLoader *config.Loader
	nlClient     *netlink.Client
	collector    *monitor.Collector
	alerter      *monitor.Alerter
	connLogger   *monitor.ConnectionLogger

	metricsServer   *http.Server
	dashboardServer *http.Server

	syslogWriter *syslog.Writer

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("tquicd version %s\n", Version)
		os.Exit(0)
	}

	// Initialize syslog
	syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "tquicd")
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %v", err)
	}
	defer syslogWriter.Close()

	syslogWriter.Info("Starting tquicd daemon")

	// Create daemon instance
	d := &Daemon{
		syslogWriter: syslogWriter,
	}

	// Run daemon
	if err := d.Run(); err != nil {
		syslogWriter.Err(fmt.Sprintf("Daemon error: %v", err))
		log.Fatalf("Daemon error: %v", err)
	}
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run() error {
	d.ctx, d.cancel = context.WithCancel(context.Background())
	defer d.cancel()

	// Load configuration
	d.configLoader = config.NewLoader(*configDir)
	if err := d.configLoader.Load(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cfg := d.configLoader.Config()
	d.logInfo("Configuration loaded from %s", *configDir)

	// Ensure log directories exist
	if err := ensureLogDir(cfg.Global.LogFile); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	if err := ensureLogDir(cfg.Global.ConnLogFile); err != nil {
		return fmt.Errorf("create connection log directory: %w", err)
	}

	// Initialize netlink client
	nlClient, err := netlink.NewClient()
	if err != nil {
		return fmt.Errorf("create netlink client: %w", err)
	}
	d.nlClient = nlClient
	d.logInfo("Netlink client connected to TQUIC kernel module")

	// Register clients with kernel
	for name, clientCfg := range cfg.Clients {
		if !clientCfg.Enabled {
			continue
		}
		if err := d.nlClient.RegisterClient(clientCfg); err != nil {
			d.logWarning("Failed to register client %s: %v", name, err)
			// Continue - kernel module might not be loaded yet
		} else {
			d.logInfo("Registered client: %s (ports %d-%d)",
				name, clientCfg.PortRangeStart, clientCfg.PortRangeEnd)
		}
	}

	// Initialize connection logger
	d.connLogger, err = monitor.NewConnectionLogger(
		d.syslogWriter,
		cfg.Global.ConnLogFile,
	)
	if err != nil {
		return fmt.Errorf("create connection logger: %w", err)
	}
	d.logInfo("Connection logging to %s", cfg.Global.ConnLogFile)

	// Initialize Prometheus collector
	d.collector = monitor.NewCollector(d.nlClient)
	d.logInfo("Prometheus metrics collector initialized")

	// Initialize alerter
	d.alerter = monitor.NewAlerter(d.syslogWriter)
	d.logInfo("Path alerter initialized")

	// Subscribe to connection events for logging
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.runConnectionEventHandler()
	}()

	// Start metrics collection loop
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.runMetricsCollector()
	}()

	// Setup QoS (HTB qdisc)
	if err := qos.SetupHTB(cfg.Global.Interface, &cfg.Global); err != nil {
		d.logWarning("Failed to setup QoS: %v (non-fatal)", err)
	} else {
		d.logInfo("QoS HTB qdisc configured on %s", cfg.Global.Interface)
	}

	// Start HTTP servers
	if err := d.startHTTPServers(cfg); err != nil {
		return fmt.Errorf("start HTTP servers: %w", err)
	}

	// Watch for config changes (hot reload)
	if err := d.configLoader.WatchForChanges(d.onConfigChange); err != nil {
		d.logWarning("Failed to setup config watch: %v", err)
	}

	// Notify systemd that we're ready
	if ok, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		d.logWarning("Failed to notify systemd: %v", err)
	} else if ok {
		d.logInfo("Notified systemd: ready")
	}

	d.logInfo("tquicd daemon started (version %s)", Version)
	d.syslogWriter.Info(fmt.Sprintf("tquicd started, listening on ports metrics=%d dashboard=%d",
		cfg.Global.MetricsPort, cfg.Global.DashboardPort))

	// Handle signals
	return d.handleSignals()
}

// startHTTPServers starts the Prometheus metrics and dashboard servers.
func (d *Daemon) startHTTPServers(cfg *config.Config) error {
	// Prometheus metrics server
	metricsHandler := api.NewPrometheusHandler(d.collector)
	d.metricsServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Global.MetricsPort),
		Handler: metricsHandler,
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.logInfo("Prometheus metrics server listening on :%d", cfg.Global.MetricsPort)
		if err := d.metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			d.logError("Metrics server error: %v", err)
		}
	}()

	// Dashboard server (localhost only)
	dashboardHandler := api.NewDashboardHandler(d.nlClient, d.configLoader, d.connLogger)
	blocklistHandler := api.NewBlocklistHandler(d.configLoader, d.nlClient)

	mux := http.NewServeMux()
	mux.Handle("/", dashboardHandler)
	mux.Handle("/api/stats", dashboardHandler)
	mux.Handle("/api/connections/recent", dashboardHandler)
	mux.Handle("/api/blocklist", blocklistHandler)

	d.dashboardServer = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.Global.DashboardPort),
		Handler: mux,
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.logInfo("Dashboard server listening on 127.0.0.1:%d", cfg.Global.DashboardPort)
		if err := d.dashboardServer.ListenAndServe(); err != http.ErrServerClosed {
			d.logError("Dashboard server error: %v", err)
		}
	}()

	return nil
}

// handleSignals handles OS signals for reload and shutdown.
func (d *Daemon) handleSignals() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.logInfo("Received SIGHUP, reloading configuration")
				if err := d.configLoader.Load(); err != nil {
					d.logError("Config reload failed: %v", err)
					d.syslogWriter.Err(fmt.Sprintf("Config reload failed: %v", err))
				} else {
					d.onConfigChange(d.configLoader.Config())
					d.syslogWriter.Info("Configuration reloaded")
				}

			case syscall.SIGTERM, syscall.SIGINT:
				d.logInfo("Received %v, shutting down gracefully", sig)
				d.syslogWriter.Info("Shutting down")
				return d.shutdown()
			}

		case <-d.ctx.Done():
			return nil
		}
	}
}

// onConfigChange handles configuration changes (hot reload).
func (d *Daemon) onConfigChange(cfg *config.Config) {
	d.logInfo("Applying configuration changes")

	// Update registered clients
	for name, clientCfg := range cfg.Clients {
		if !clientCfg.Enabled {
			continue
		}
		if err := d.nlClient.RegisterClient(clientCfg); err != nil {
			d.logWarning("Failed to update client %s: %v", name, err)
		}
	}

	// Update QoS
	if err := qos.SetupHTB(cfg.Global.Interface, &cfg.Global); err != nil {
		d.logWarning("Failed to update QoS: %v", err)
	}

	// Update per-client bandwidth limits
	for name, clientCfg := range cfg.Clients {
		if clientCfg.BandwidthLimit != "" {
			if err := qos.SetClientBandwidth(cfg.Global.Interface, name, clientCfg.BandwidthLimit); err != nil {
				d.logWarning("Failed to set bandwidth for %s: %v", name, err)
			}
		}
	}
}

// runMetricsCollector runs the metrics collection loop (every 5 seconds).
func (d *Daemon) runMetricsCollector() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Collect path stats from kernel
			stats, err := d.nlClient.GetPathStats("")
			if err != nil {
				if *verbose {
					d.logWarning("Failed to collect path stats: %v", err)
				}
				continue
			}

			// Update Prometheus metrics
			d.collector.UpdatePathStats(stats)

			// Check for path degradation
			alerts := d.alerter.CheckPaths(stats)
			for _, alert := range alerts {
				d.logWarning("Path alert: %s", alert)
			}

		case <-d.ctx.Done():
			return
		}
	}
}

// runConnectionEventHandler subscribes to kernel connection events.
func (d *Daemon) runConnectionEventHandler() {
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		err := d.nlClient.SubscribeConnectionEvents(func(event netlink.ConnectionEvent) {
			// Log the connection event
			d.connLogger.LogConnection(event)

			if *verbose {
				d.logInfo("Connection %s: %s -> %s:%d (%d bytes)",
					event.TypeName(), event.ClientID,
					event.DestIP, event.DestPort, event.BytesTx+event.BytesRx)
			}
		})

		if err != nil {
			d.logWarning("Connection event subscription failed: %v", err)
			// Retry after delay
			select {
			case <-time.After(5 * time.Second):
			case <-d.ctx.Done():
				return
			}
		}
	}
}

// shutdown performs graceful shutdown.
func (d *Daemon) shutdown() error {
	// Notify systemd that we're stopping
	daemon.SdNotify(false, daemon.SdNotifyStopping)

	// Cancel context to stop goroutines
	d.cancel()

	// Shutdown HTTP servers with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var shutdownErr error

	if d.metricsServer != nil {
		if err := d.metricsServer.Shutdown(shutdownCtx); err != nil {
			d.logError("Metrics server shutdown error: %v", err)
			shutdownErr = err
		}
	}

	if d.dashboardServer != nil {
		if err := d.dashboardServer.Shutdown(shutdownCtx); err != nil {
			d.logError("Dashboard server shutdown error: %v", err)
			shutdownErr = err
		}
	}

	// Stop config watcher
	d.configLoader.Stop()

	// Close netlink client
	if d.nlClient != nil {
		d.nlClient.Close()
	}

	// Close connection logger
	if d.connLogger != nil {
		d.connLogger.Close()
	}

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		d.logInfo("Shutdown complete")
	case <-shutdownCtx.Done():
		d.logWarning("Shutdown timed out")
	}

	return shutdownErr
}

// Logging helpers

func (d *Daemon) logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Println(msg)
	if d.syslogWriter != nil {
		d.syslogWriter.Info(msg)
	}
}

func (d *Daemon) logWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("WARNING: %s", msg)
	if d.syslogWriter != nil {
		d.syslogWriter.Warning(msg)
	}
}

func (d *Daemon) logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("ERROR: %s", msg)
	if d.syslogWriter != nil {
		d.syslogWriter.Err(msg)
	}
}

// ensureLogDir creates the parent directory for a log file if it doesn't exist.
func ensureLogDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0755)
}

// isLocalAddr returns true if the address is localhost.
func isLocalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
