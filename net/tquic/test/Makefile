# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for TQUIC test suite
#
# This Makefile handles both:
# - Kernel unit tests (KUnit, built as part of kernel)
# - Userspace interoperability tests (built separately)

# Default target
.PHONY: all
all: interop-tools

#==============================================================================
# Interoperability Test Tools
#==============================================================================

INTEROP_DIR := $(CURDIR)/interop
TOOLS_DIR := $(INTEROP_DIR)/tools

.PHONY: interop-tools
interop-tools:
	$(MAKE) -C $(TOOLS_DIR)

.PHONY: interop-tools-clean
interop-tools-clean:
	$(MAKE) -C $(TOOLS_DIR) clean

.PHONY: interop-tools-debug
interop-tools-debug:
	$(MAKE) -C $(TOOLS_DIR) debug

.PHONY: interop-tools-asan
interop-tools-asan:
	$(MAKE) -C $(TOOLS_DIR) asan

#==============================================================================
# Interoperability Tests
#==============================================================================

# Directory for test results
RESULTS_DIR := $(INTEROP_DIR)/results

# Create results directory
$(RESULTS_DIR):
	mkdir -p $(RESULTS_DIR)

# Setup test network
.PHONY: interop-setup
interop-setup:
	@echo "Setting up interop test network..."
	sudo $(INTEROP_DIR)/setup_namespaces.sh setup

# Cleanup test network
.PHONY: interop-cleanup
interop-cleanup:
	@echo "Cleaning up interop test network..."
	sudo $(INTEROP_DIR)/setup_namespaces.sh cleanup

# Run all interop tests
.PHONY: interop-test
interop-test: interop-tools $(RESULTS_DIR)
	@echo "Running all interoperability tests..."
	sudo $(INTEROP_DIR)/tquic_interop.sh --all

# Run interop tests against specific peer
.PHONY: interop-test-quiche
interop-test-quiche: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --peer quiche

.PHONY: interop-test-msquic
interop-test-msquic: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --peer msquic

.PHONY: interop-test-ngtcp2
interop-test-ngtcp2: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --peer ngtcp2

.PHONY: interop-test-picoquic
interop-test-picoquic: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --peer picoquic

# Run specific test categories
.PHONY: interop-test-handshake
interop-test-handshake: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --test handshake

.PHONY: interop-test-zerortt
interop-test-zerortt: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --test zerortt

.PHONY: interop-test-migration
interop-test-migration: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --test migration

.PHONY: interop-test-multipath
interop-test-multipath: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --test multipath

.PHONY: interop-test-failover
interop-test-failover: interop-tools $(RESULTS_DIR)
	sudo $(INTEROP_DIR)/tquic_interop.sh --test failover

# Quick interop test (handshake only against available peers)
.PHONY: interop-quick
interop-quick: interop-tools $(RESULTS_DIR)
	@echo "Running quick interop test (handshake only)..."
	sudo $(INTEROP_DIR)/tquic_interop.sh --test handshake

# List available peers
.PHONY: interop-list-peers
interop-list-peers:
	@$(INTEROP_DIR)/tquic_interop.sh --list-peers

# List available tests
.PHONY: interop-list-tests
interop-list-tests:
	@$(INTEROP_DIR)/tquic_interop.sh --list-tests

# Generate test certificates
.PHONY: interop-certs
interop-certs:
	@echo "Generating test certificates..."
	@mkdir -p $(INTEROP_DIR)/certs
	@openssl genrsa -out $(INTEROP_DIR)/certs/ca.key 2048
	@openssl req -x509 -new -nodes -key $(INTEROP_DIR)/certs/ca.key \
		-sha256 -days 365 -out $(INTEROP_DIR)/certs/ca.crt \
		-subj "/CN=TQUIC Test CA"
	@openssl genrsa -out $(INTEROP_DIR)/certs/server.key 2048
	@openssl req -new -key $(INTEROP_DIR)/certs/server.key \
		-out $(INTEROP_DIR)/certs/server.csr \
		-subj "/CN=localhost"
	@openssl x509 -req -in $(INTEROP_DIR)/certs/server.csr \
		-CA $(INTEROP_DIR)/certs/ca.crt \
		-CAkey $(INTEROP_DIR)/certs/ca.key \
		-CAcreateserial -out $(INTEROP_DIR)/certs/server.crt \
		-days 365 -sha256
	@echo "Certificates generated in $(INTEROP_DIR)/certs/"

#==============================================================================
# Peer Installation
#==============================================================================

PEERS_DIR ?= /opt/quic-peers

.PHONY: install-peers
install-peers: install-quiche install-msquic install-ngtcp2 install-picoquic

.PHONY: install-quiche
install-quiche:
	@echo "Installing quiche..."
	TQUIC_INTEROP_PEERS=$(PEERS_DIR) $(INTEROP_DIR)/peers/quiche_peer.sh --install

.PHONY: install-msquic
install-msquic:
	@echo "Installing msquic..."
	TQUIC_INTEROP_PEERS=$(PEERS_DIR) $(INTEROP_DIR)/peers/msquic_peer.sh --install

.PHONY: install-ngtcp2
install-ngtcp2:
	@echo "Installing ngtcp2..."
	TQUIC_INTEROP_PEERS=$(PEERS_DIR) $(INTEROP_DIR)/peers/ngtcp2_peer.sh --install

.PHONY: install-picoquic
install-picoquic:
	@echo "Installing picoquic..."
	TQUIC_INTEROP_PEERS=$(PEERS_DIR) $(INTEROP_DIR)/peers/picoquic_peer.sh --install

#==============================================================================
# Cleanup
#==============================================================================

.PHONY: clean
clean: interop-tools-clean
	rm -rf $(RESULTS_DIR)
	rm -f $(INTEROP_DIR)/certs/*.crt $(INTEROP_DIR)/certs/*.key
	rm -f $(INTEROP_DIR)/certs/*.csr $(INTEROP_DIR)/certs/*.srl
	rm -f $(INTEROP_DIR)/certs/*.ext

.PHONY: distclean
distclean: clean
	rm -rf $(INTEROP_DIR)/certs

#==============================================================================
# Help
#==============================================================================

.PHONY: help
help:
	@echo "TQUIC Test Suite Makefile"
	@echo ""
	@echo "Interop Test Tools:"
	@echo "  interop-tools         - Build userspace interop test tools"
	@echo "  interop-tools-clean   - Clean interop tools"
	@echo "  interop-tools-debug   - Build with debug symbols"
	@echo "  interop-tools-asan    - Build with AddressSanitizer"
	@echo ""
	@echo "Interop Tests:"
	@echo "  interop-test          - Run all interop tests"
	@echo "  interop-quick         - Quick handshake test only"
	@echo "  interop-setup         - Setup test network namespaces"
	@echo "  interop-cleanup       - Cleanup test network"
	@echo ""
	@echo "Peer-specific tests:"
	@echo "  interop-test-quiche   - Test against Cloudflare quiche"
	@echo "  interop-test-msquic   - Test against Microsoft msquic"
	@echo "  interop-test-ngtcp2   - Test against ngtcp2"
	@echo "  interop-test-picoquic - Test against picoquic (multipath)"
	@echo ""
	@echo "Test-specific:"
	@echo "  interop-test-handshake  - Run handshake tests"
	@echo "  interop-test-zerortt    - Run 0-RTT tests"
	@echo "  interop-test-migration  - Run migration tests"
	@echo "  interop-test-multipath  - Run multipath tests (picoquic)"
	@echo "  interop-test-failover   - Run failover tests"
	@echo ""
	@echo "Utilities:"
	@echo "  interop-certs         - Generate test certificates"
	@echo "  interop-list-peers    - List available QUIC peers"
	@echo "  interop-list-tests    - List available test cases"
	@echo ""
	@echo "Peer Installation:"
	@echo "  install-peers         - Install all QUIC peers"
	@echo "  install-quiche        - Install Cloudflare quiche"
	@echo "  install-msquic        - Install Microsoft msquic"
	@echo "  install-ngtcp2        - Install ngtcp2"
	@echo "  install-picoquic      - Install picoquic"
	@echo ""
	@echo "Configuration:"
	@echo "  PEERS_DIR=/path       - Set peer installation directory"
	@echo "                          (default: /opt/quic-peers)"
	@echo ""
	@echo "Examples:"
	@echo "  make interop-tools"
	@echo "  make interop-certs"
	@echo "  make interop-test-quiche"
	@echo "  make PEERS_DIR=/home/user/quic-peers install-quiche"
