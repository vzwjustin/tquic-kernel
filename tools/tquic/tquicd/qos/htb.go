// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

// Package qos provides traffic shaping and QoS configuration using tc HTB.
package qos

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/linux/tquicd/config"
)

// TrafficClass represents a QoS traffic class.
type TrafficClass struct {
	Name     string
	ClassID  string
	Priority int
	Rate     string
	Ceil     string
}

// DefaultTrafficClasses returns the 4 default traffic classes per CONTEXT.md.
var DefaultTrafficClasses = []TrafficClass{
	{Name: "realtime", ClassID: "1:10", Priority: 1, Rate: "30%", Ceil: "100%"},    // VoIP/video
	{Name: "interactive", ClassID: "1:20", Priority: 2, Rate: "30%", Ceil: "100%"}, // Gaming
	{Name: "bulk", ClassID: "1:30", Priority: 3, Rate: "30%", Ceil: "100%"},        // Downloads
	{Name: "background", ClassID: "1:40", Priority: 4, Rate: "10%", Ceil: "50%"},   // Low priority
}

// DSCPMapping maps traffic classes to DSCP values.
var DSCPMapping = map[string]string{
	"realtime":    "ef",    // Expedited Forwarding
	"interactive": "af41",  // Assured Forwarding 41
	"bulk":        "be",    // Best Effort (default)
	"background":  "cs1",   // Class Selector 1 (scavenger)
}

// SetupHTB creates an HTB qdisc on the specified interface with 4 traffic classes.
func SetupHTB(iface string, cfg *config.GlobalConfig) error {
	// First, delete any existing qdisc (ignore errors)
	exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()

	// Create root HTB qdisc
	// tc qdisc add dev eth0 root handle 1: htb default 30
	cmd := exec.Command("tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "30")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc qdisc add: %w: %s", err, string(out))
	}

	// Create root class with overall interface rate
	// For now, use a high ceiling (10gbit) as we don't know the interface speed
	// tc qdisc add dev eth0 parent 1: classid 1:1 htb rate 10gbit
	cmd = exec.Command("tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:1",
		"htb", "rate", "10gbit")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc class add root: %w: %s", err, string(out))
	}

	// Create traffic classes
	for _, tc := range DefaultTrafficClasses {
		if err := createTrafficClass(iface, tc); err != nil {
			return fmt.Errorf("create class %s: %w", tc.Name, err)
		}
	}

	// Add filters to classify traffic based on DSCP
	for _, tc := range DefaultTrafficClasses {
		if err := createDSCPFilter(iface, tc.Name, tc.ClassID); err != nil {
			// Non-fatal - filters can be added later
		}
	}

	return nil
}

// createTrafficClass creates a single HTB class.
func createTrafficClass(iface string, tc TrafficClass) error {
	// Convert percentage rates to actual rates (assume 1gbit for percentages)
	rate := percentToRate(tc.Rate, 1000000000)
	ceil := percentToRate(tc.Ceil, 1000000000)

	// tc class add dev eth0 parent 1:1 classid 1:10 htb rate 300mbit ceil 1gbit prio 1
	cmd := exec.Command("tc", "class", "add", "dev", iface, "parent", "1:1",
		"classid", tc.ClassID, "htb",
		"rate", rate, "ceil", ceil, "prio", fmt.Sprintf("%d", tc.Priority))

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc class add: %w: %s", err, string(out))
	}

	// Add SFQ (Stochastic Fair Queuing) as leaf qdisc for fairness
	// tc qdisc add dev eth0 parent 1:10 handle 10: sfq perturb 10
	classNum := strings.Split(tc.ClassID, ":")[1]
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface, "parent", tc.ClassID,
		"handle", classNum+":", "sfq", "perturb", "10")

	if out, err := cmd.CombinedOutput(); err != nil {
		// Non-fatal
		_ = out
	}

	return nil
}

// createDSCPFilter creates a filter to match DSCP and direct to class.
func createDSCPFilter(iface, className, classID string) error {
	dscp, ok := DSCPMapping[className]
	if !ok {
		return fmt.Errorf("unknown class: %s", className)
	}

	// Map DSCP name to value
	var dscpVal int
	switch dscp {
	case "ef":
		dscpVal = 46 // Expedited Forwarding
	case "af41":
		dscpVal = 34 // Assured Forwarding 41
	case "be":
		dscpVal = 0 // Best Effort
	case "cs1":
		dscpVal = 8 // Class Selector 1
	default:
		return fmt.Errorf("unknown DSCP: %s", dscp)
	}

	// tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
	//   match ip tos 0xb8 0xfc flowid 1:10
	// (0xb8 = EF DSCP << 2)
	tosVal := dscpVal << 2
	tosMask := 0xfc // Match DSCP bits only

	cmd := exec.Command("tc", "filter", "add", "dev", iface, "parent", "1:",
		"protocol", "ip", "prio", "1", "u32",
		"match", "ip", "tos", fmt.Sprintf("0x%02x", tosVal), fmt.Sprintf("0x%02x", tosMask),
		"flowid", classID)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc filter add: %w: %s", err, string(out))
	}

	return nil
}

// SetClientBandwidth sets a per-client bandwidth limit.
func SetClientBandwidth(iface, clientName, limit string) error {
	// Parse bandwidth limit
	bps, err := config.ParseBandwidth(limit)
	if err != nil {
		return fmt.Errorf("parse bandwidth: %w", err)
	}

	// Create a class for this client
	// Use client name hash as class ID (1:100+)
	classNum := 100 + hashString(clientName)%100
	classID := fmt.Sprintf("1:%d", classNum)

	// tc class add dev eth0 parent 1:1 classid 1:100 htb rate 100mbit ceil 100mbit
	rateStr := config.FormatBandwidth(bps)
	cmd := exec.Command("tc", "class", "replace", "dev", iface, "parent", "1:1",
		"classid", classID, "htb", "rate", rateStr, "ceil", rateStr)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc class replace: %w: %s", err, string(out))
	}

	return nil
}

// RemoveClientBandwidth removes a per-client bandwidth limit.
func RemoveClientBandwidth(iface, clientName string) error {
	classNum := 100 + hashString(clientName)%100
	classID := fmt.Sprintf("1:%d", classNum)

	cmd := exec.Command("tc", "class", "del", "dev", iface, "classid", classID)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc class del: %w: %s", err, string(out))
	}

	return nil
}

// percentToRate converts a percentage rate (e.g., "30%") to bits/sec string.
func percentToRate(pct string, totalBps uint64) string {
	pct = strings.TrimSuffix(pct, "%")
	var p int
	fmt.Sscanf(pct, "%d", &p)
	if p <= 0 || p > 100 {
		return "1gbit"
	}
	bps := totalBps * uint64(p) / 100
	return config.FormatBandwidth(bps)
}

// hashString returns a simple hash of a string.
func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = 31*h + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

// ShowQdisc returns the current qdisc configuration for debugging.
func ShowQdisc(iface string) (string, error) {
	cmd := exec.Command("tc", "qdisc", "show", "dev", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tc qdisc show: %w", err)
	}
	return string(out), nil
}

// ShowClass returns the current class configuration for debugging.
func ShowClass(iface string) (string, error) {
	cmd := exec.Command("tc", "class", "show", "dev", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tc class show: %w", err)
	}
	return string(out), nil
}
