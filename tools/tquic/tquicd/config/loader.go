// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// Loader handles configuration file loading and hot reload.
type Loader struct {
	dir      string
	config   *Config
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	onChange func(*Config)
	stopCh   chan struct{}
}

// NewLoader creates a new configuration loader for the given directory.
func NewLoader(dir string) *Loader {
	return &Loader{
		dir:    dir,
		config: DefaultConfig(),
		stopCh: make(chan struct{}),
	}
}

// LoadConfigDir loads all *.conf files from the specified directory.
func LoadConfigDir(dir string) (*Config, error) {
	loader := NewLoader(dir)
	if err := loader.Load(); err != nil {
		return nil, err
	}
	return loader.Config(), nil
}

// Load reads all configuration files from the configured directory.
func (l *Loader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	config := DefaultConfig()

	// Find all .conf files
	pattern := filepath.Join(l.dir, "*.conf")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob config files: %w", err)
	}

	for _, file := range files {
		if err := l.loadFile(config, file); err != nil {
			return fmt.Errorf("load %s: %w", file, err)
		}
	}

	// Load blocklist if it exists
	if err := l.loadBlocklist(config); err != nil {
		// Blocklist file is optional
		if !os.IsNotExist(err) {
			return fmt.Errorf("load blocklist: %w", err)
		}
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	l.config = config
	return nil
}

// Config returns the current configuration (thread-safe).
func (l *Loader) Config() *Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// WatchForChanges starts watching config files for changes.
// The onChange callback is called when configuration is reloaded.
func (l *Loader) WatchForChanges(onChange func(*Config)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}

	if err := watcher.Add(l.dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch directory: %w", err)
	}

	l.watcher = watcher
	l.onChange = onChange

	go l.watchLoop()
	return nil
}

// watchLoop handles file system events.
func (l *Loader) watchLoop() {
	for {
		select {
		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}

			// Only reload on write/create/rename of .conf files
			if !strings.HasSuffix(event.Name, ".conf") {
				continue
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				if err := l.Load(); err != nil {
					// Log error but continue watching
					fmt.Fprintf(os.Stderr, "config reload failed: %v\n", err)
					continue
				}
				if l.onChange != nil {
					l.onChange(l.Config())
				}
			}

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "watcher error: %v\n", err)

		case <-l.stopCh:
			return
		}
	}
}

// Stop stops the configuration watcher.
func (l *Loader) Stop() {
	close(l.stopCh)
	if l.watcher != nil {
		l.watcher.Close()
	}
}

// loadFile parses a single INI-style configuration file.
func (l *Loader) loadFile(config *Config, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	section := ""
	var currentClient *ClientConfig

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")

			// Check if it's a client section
			if strings.HasPrefix(section, "client:") {
				clientName := strings.TrimPrefix(section, "client:")
				currentClient = &ClientConfig{
					Name:           clientName,
					ConnRateLimit:  10, // default
					TrafficClasses: make(map[string]int),
					Enabled:        true,
				}
				config.Clients[clientName] = currentClient
			} else {
				currentClient = nil
			}
			continue
		}

		// Key=value pair
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("line %d: invalid format (expected key=value)", lineNum)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		switch section {
		case "global":
			if err := l.parseGlobalKey(config, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}
		case "blocklist":
			if err := l.parseBlocklistKey(config, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}
		default:
			if currentClient != nil {
				if err := l.parseClientKey(currentClient, key, value); err != nil {
					return fmt.Errorf("line %d: %w", lineNum, err)
				}
			}
		}
	}

	return scanner.Err()
}

// parseGlobalKey parses a key-value pair in the [global] section.
func (l *Loader) parseGlobalKey(config *Config, key, value string) error {
	switch key {
	case "listen_port":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid listen_port: %w", err)
		}
		config.Global.ListenPort = v

	case "metrics_port":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid metrics_port: %w", err)
		}
		config.Global.MetricsPort = v

	case "dashboard_port":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid dashboard_port: %w", err)
		}
		config.Global.DashboardPort = v

	case "log_file":
		config.Global.LogFile = value

	case "conn_log_file":
		config.Global.ConnLogFile = value

	case "session_ttl":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid session_ttl: %w", err)
		}
		config.Global.SessionTTL = v

	case "interface":
		config.Global.Interface = value

	case "enable_tfo":
		config.Global.EnableTFO = parseBool(value)

	case "enable_gro":
		config.Global.EnableGRO = parseBool(value)

	case "enable_gso":
		config.Global.EnableGSO = parseBool(value)

	case "queue_timeout":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid queue_timeout: %w", err)
		}
		config.Global.QueueTimeout = v

	case "hairpin_enabled":
		config.Global.HairpinEnabled = parseBool(value)

	default:
		// Unknown keys are ignored for forward compatibility
	}

	return nil
}

// parseClientKey parses a key-value pair in a [client:name] section.
func (l *Loader) parseClientKey(client *ClientConfig, key, value string) error {
	switch key {
	case "psk":
		client.PSKBase64 = value

	case "port_range_start":
		v, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port_range_start: %w", err)
		}
		client.PortRangeStart = uint16(v)

	case "port_range_end":
		v, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port_range_end: %w", err)
		}
		client.PortRangeEnd = uint16(v)

	case "bandwidth_limit":
		client.BandwidthLimit = value

	case "conn_rate_limit":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid conn_rate_limit: %w", err)
		}
		client.ConnRateLimit = v

	case "traffic_class":
		// Format: "realtime:30" or "interactive:30"
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid traffic_class format (expected class:percentage)")
		}
		pct, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid traffic_class percentage: %w", err)
		}
		client.TrafficClasses[parts[0]] = pct

	case "enabled":
		client.Enabled = parseBool(value)

	default:
		// Unknown keys are ignored for forward compatibility
	}

	return nil
}

// parseBlocklistKey parses a key-value pair in the [blocklist] section.
func (l *Loader) parseBlocklistKey(config *Config, key, value string) error {
	switch key {
	case "ip":
		config.Blocklist.IPs = append(config.Blocklist.IPs, value)

	case "cidr":
		config.Blocklist.CIDRs = append(config.Blocklist.CIDRs, value)

	case "persist_file":
		config.Blocklist.PersistFile = value

	case "enabled":
		config.Blocklist.Enabled = parseBool(value)

	default:
		// Unknown keys are ignored for forward compatibility
	}

	return nil
}

// loadBlocklist loads the persistent blocklist file.
func (l *Loader) loadBlocklist(config *Config) error {
	file, err := os.Open(config.Blocklist.PersistFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// CIDR ranges contain a slash
		if strings.Contains(line, "/") {
			config.Blocklist.CIDRs = append(config.Blocklist.CIDRs, line)
		} else {
			config.Blocklist.IPs = append(config.Blocklist.IPs, line)
		}
	}

	return scanner.Err()
}

// parseBool parses a boolean value from various common formats.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "yes", "1", "on":
		return true
	default:
		return false
	}
}

// SaveBlocklist persists the current blocklist to the configured file.
func (l *Loader) SaveBlocklist() error {
	l.mu.RLock()
	config := l.config
	l.mu.RUnlock()

	file, err := os.Create(config.Blocklist.PersistFile)
	if err != nil {
		return fmt.Errorf("create blocklist file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintln(file, "# TQUIC blocklist - auto-generated")
	fmt.Fprintln(file, "# One IP or CIDR per line")
	fmt.Fprintln(file, "")

	// Write IPs
	for _, ip := range config.Blocklist.IPs {
		fmt.Fprintln(file, ip)
	}

	// Write CIDRs
	for _, cidr := range config.Blocklist.CIDRs {
		fmt.Fprintln(file, cidr)
	}

	return nil
}

// AddToBlocklist adds an IP or CIDR to the blocklist.
func (l *Loader) AddToBlocklist(entry string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		l.config.Blocklist.CIDRs = append(l.config.Blocklist.CIDRs, entry)
	} else {
		l.config.Blocklist.IPs = append(l.config.Blocklist.IPs, entry)
	}
}

// RemoveFromBlocklist removes an IP or CIDR from the blocklist.
func (l *Loader) RemoveFromBlocklist(entry string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry = strings.TrimSpace(entry)

	// Try removing from IPs
	for i, ip := range l.config.Blocklist.IPs {
		if ip == entry {
			l.config.Blocklist.IPs = append(
				l.config.Blocklist.IPs[:i],
				l.config.Blocklist.IPs[i+1:]...,
			)
			return true
		}
	}

	// Try removing from CIDRs
	for i, cidr := range l.config.Blocklist.CIDRs {
		if cidr == entry {
			l.config.Blocklist.CIDRs = append(
				l.config.Blocklist.CIDRs[:i],
				l.config.Blocklist.CIDRs[i+1:]...,
			)
			return true
		}
	}

	return false
}

// GetBlocklist returns the current blocklist entries.
func (l *Loader) GetBlocklist() (ips []string, cidrs []string) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Return copies to avoid race conditions
	ips = make([]string, len(l.config.Blocklist.IPs))
	copy(ips, l.config.Blocklist.IPs)

	cidrs = make([]string, len(l.config.Blocklist.CIDRs))
	copy(cidrs, l.config.Blocklist.CIDRs)

	return
}
