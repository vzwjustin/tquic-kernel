#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Cloudflare quiche peer setup for TQUIC interoperability testing
#
# quiche is a QUIC implementation written in Rust by Cloudflare.
# Repository: https://github.com/cloudflare/quiche

QUICHE_DIR="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}/quiche"
QUICHE_SERVER="${QUICHE_DIR}/target/release/examples/quiche-server"
QUICHE_CLIENT="${QUICHE_DIR}/target/release/examples/quiche-client"

#------------------------------------------------------------------------------
# Installation Check
#------------------------------------------------------------------------------

check_quiche_installed() {
    if [[ -x "${QUICHE_SERVER}" ]] && [[ -x "${QUICHE_CLIENT}" ]]; then
        return 0
    fi

    # Check if quiche is in PATH
    if command -v quiche-server &>/dev/null && command -v quiche-client &>/dev/null; then
        QUICHE_SERVER="quiche-server"
        QUICHE_CLIENT="quiche-client"
        return 0
    fi

    return 1
}

get_quiche_version() {
    if [[ -x "${QUICHE_SERVER}" ]]; then
        "${QUICHE_SERVER}" --version 2>&1 | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

#------------------------------------------------------------------------------
# Server Functions
#------------------------------------------------------------------------------

start_quiche_server() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local server_log="${work_dir}/quiche_server.log"
    local pid_file="${work_dir}/quiche_server.pid"

    # Build command
    local cmd="${QUICHE_SERVER}"
    cmd+=" --listen ${addr}:${port}"
    cmd+=" --cert ${cert_dir}/server.crt"
    cmd+=" --key ${cert_dir}/server.key"
    cmd+=" --root ${work_dir}"
    cmd+=" --no-retry"

    # Parse extra args for specific options
    if [[ "${extra_args}" == *"--enable-0rtt"* ]]; then
        cmd+=" --early-data"
    fi

    if [[ "${extra_args}" == *"--enable-migration"* ]]; then
        # quiche supports migration by default
        :
    fi

    if [[ "${extra_args}" == *"--disable-migration"* ]]; then
        cmd+=" --disable-active-migration"
    fi

    # Start server
    log_debug "Starting quiche server: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${server_log}" 2>&1 &
    local pid=$!

    echo "${pid}" > "${pid_file}"
    log_debug "quiche server started with PID ${pid}"

    return 0
}

stop_quiche_server() {
    local work_dir="$1"
    local pid_file="${work_dir}/quiche_server.pid"

    if [[ -f "${pid_file}" ]]; then
        local pid=$(cat "${pid_file}")
        kill "${pid}" 2>/dev/null || true
        sleep 0.5
        kill -9 "${pid}" 2>/dev/null || true
        rm -f "${pid_file}"
    fi
}

#------------------------------------------------------------------------------
# Client Functions
#------------------------------------------------------------------------------

start_quiche_client() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local client_log="${work_dir}/quiche_client.log"

    # Build command
    local cmd="${QUICHE_CLIENT}"
    cmd+=" https://${addr}:${port}/"

    # Add CA certificate if available
    if [[ -f "${cert_dir}/ca.crt" ]]; then
        cmd+=" --root ${cert_dir}/ca.crt"
    else
        cmd+=" --no-verify"
    fi

    # Parse extra args
    if [[ "${extra_args}" == *"--download"* ]]; then
        local download_path=$(echo "${extra_args}" | grep -oP '(?<=--download )\S+')
        cmd+=" --body ${download_path}"
    fi

    if [[ "${extra_args}" == *"--early-data"* ]]; then
        cmd+=" --early-data"
    fi

    # Execute client
    log_debug "Running quiche client: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${client_log}" 2>&1

    return $?
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

stop_quiche() {
    local work_dir="$1"
    stop_quiche_server "${work_dir}"
}

# Parse quiche-specific server options
parse_quiche_server_options() {
    local extra_args="$1"
    local options=""

    case "${extra_args}" in
        *"--enable-session-tickets"*)
            # quiche enables session tickets by default
            ;;
        *"--disable-0rtt"*)
            # No early data flag to disable
            ;;
        *"--serve-dir"*)
            local serve_dir=$(echo "${extra_args}" | grep -oP '(?<=--serve-dir )\S+')
            options+=" --root ${serve_dir}"
            ;;
        *"--preferred-address"*)
            local pref_addr=$(echo "${extra_args}" | grep -oP '(?<=--preferred-address )\S+')
            options+=" --preferred-address ${pref_addr}"
            ;;
    esac

    echo "${options}"
}

#------------------------------------------------------------------------------
# Installation Helper
#------------------------------------------------------------------------------

install_quiche() {
    echo "Installing quiche..."

    local install_dir="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}"
    mkdir -p "${install_dir}"
    cd "${install_dir}"

    # Check for Rust
    if ! command -v cargo &>/dev/null; then
        echo "Rust not found. Installing..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
    fi

    # Clone and build
    if [[ ! -d "quiche" ]]; then
        git clone --recursive https://github.com/cloudflare/quiche
    fi

    cd quiche
    cargo build --release --examples

    echo "quiche installed successfully"
    echo "Server: ${install_dir}/quiche/target/release/examples/quiche-server"
    echo "Client: ${install_dir}/quiche/target/release/examples/quiche-client"
}

# Run installation if executed directly with --install
if [[ "${1:-}" == "--install" ]]; then
    install_quiche
fi
