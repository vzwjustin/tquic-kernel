// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Linux TQUIC Authors

package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/linux/tquicd/config"
	"github.com/linux/tquicd/netlink"
)

// BlocklistHandler handles blocklist API requests.
type BlocklistHandler struct {
	configLoader *config.Loader
	nlClient     *netlink.Client
}

// NewBlocklistHandler creates a new blocklist handler.
func NewBlocklistHandler(configLoader *config.Loader, nlClient *netlink.Client) *BlocklistHandler {
	return &BlocklistHandler{
		configLoader: configLoader,
		nlClient:     nlClient,
	}
}

// ServeHTTP implements http.Handler.
// Routes:
//   - GET /api/blocklist - List current blocklist
//   - POST /api/blocklist - Add IP/CIDR to blocklist
//   - DELETE /api/blocklist - Remove from blocklist
func (h *BlocklistHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleGet returns the current blocklist.
func (h *BlocklistHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	ips, cidrs := h.configLoader.GetBlocklist()

	resp := BlocklistResponse{
		IPs:   ips,
		CIDRs: cidrs,
	}

	json.NewEncoder(w).Encode(resp)
}

// handlePost adds an entry to the blocklist.
// POST /api/blocklist
// Body: {"ip": "1.2.3.4"} or {"cidr": "10.0.0.0/8"}
func (h *BlocklistHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	var req BlocklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid JSON"})
		return
	}

	entry := req.IP
	if req.CIDR != "" {
		entry = req.CIDR
	}

	if entry == "" {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "ip or cidr required"})
		return
	}

	// Validate entry
	if req.CIDR != "" {
		_, _, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid CIDR: " + err.Error()})
			return
		}
	} else {
		ip := net.ParseIP(req.IP)
		if ip == nil {
			json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid IP address"})
			return
		}
	}

	// Add to config
	h.configLoader.AddToBlocklist(entry)

	// Persist to file
	if err := h.configLoader.SaveBlocklist(); err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to persist: " + err.Error()})
		return
	}

	// Notify kernel
	ips, cidrs := h.configLoader.GetBlocklist()
	if err := h.nlClient.SetBlocklist(ips, cidrs); err != nil {
		// Log but don't fail - kernel might not be ready
	}

	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		Message: "added to blocklist: " + entry,
	})
}

// handleDelete removes an entry from the blocklist.
// DELETE /api/blocklist
// Body: {"ip": "1.2.3.4"} or {"cidr": "10.0.0.0/8"}
func (h *BlocklistHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req BlocklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid JSON"})
		return
	}

	entry := req.IP
	if req.CIDR != "" {
		entry = req.CIDR
	}

	if entry == "" {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "ip or cidr required"})
		return
	}

	// Remove from config
	if !h.configLoader.RemoveFromBlocklist(entry) {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "entry not found"})
		return
	}

	// Persist to file
	if err := h.configLoader.SaveBlocklist(); err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to persist: " + err.Error()})
		return
	}

	// Notify kernel
	ips, cidrs := h.configLoader.GetBlocklist()
	if err := h.nlClient.SetBlocklist(ips, cidrs); err != nil {
		// Log but don't fail
	}

	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		Message: "removed from blocklist: " + entry,
	})
}

// BlocklistRequest is the request body for blocklist operations.
type BlocklistRequest struct {
	IP   string `json:"ip,omitempty"`
	CIDR string `json:"cidr,omitempty"`
}

// BlocklistResponse is the response for GET /api/blocklist.
type BlocklistResponse struct {
	IPs   []string `json:"ips"`
	CIDRs []string `json:"cidrs"`
}

// ErrorResponse is a generic error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// SuccessResponse is a generic success response.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}
