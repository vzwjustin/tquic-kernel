#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# ngtcp2 peer setup for TQUIC interoperability testing
#
# ngtcp2 is a QUIC implementation in C by the nghttp2 team.
# It's used as a reference implementation for many QUIC features.
# Repository: https://github.com/ngtcp2/ngtcp2

NGTCP2_DIR="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}/ngtcp2"
NGTCP2_SERVER="${NGTCP2_DIR}/examples/server"
NGTCP2_CLIENT="${NGTCP2_DIR}/examples/client"
NGTCP2_H09SERVER="${NGTCP2_DIR}/examples/h09server"
NGTCP2_H09CLIENT="${NGTCP2_DIR}/examples/h09client"

#------------------------------------------------------------------------------
# Installation Check
#------------------------------------------------------------------------------

check_ngtcp2_installed() {
    if [[ -x "${NGTCP2_SERVER}" ]] && [[ -x "${NGTCP2_CLIENT}" ]]; then
        return 0
    fi

    # Check for h09 versions
    if [[ -x "${NGTCP2_H09SERVER}" ]] && [[ -x "${NGTCP2_H09CLIENT}" ]]; then
        NGTCP2_SERVER="${NGTCP2_H09SERVER}"
        NGTCP2_CLIENT="${NGTCP2_H09CLIENT}"
        return 0
    fi

    # Check if in PATH
    if command -v ngtcp2-server &>/dev/null && command -v ngtcp2-client &>/dev/null; then
        NGTCP2_SERVER="ngtcp2-server"
        NGTCP2_CLIENT="ngtcp2-client"
        return 0
    fi

    return 1
}

get_ngtcp2_version() {
    if [[ -x "${NGTCP2_SERVER}" ]]; then
        "${NGTCP2_SERVER}" --version 2>&1 | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

#------------------------------------------------------------------------------
# Server Functions
#------------------------------------------------------------------------------

start_ngtcp2_server() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local server_log="${work_dir}/ngtcp2_server.log"
    local pid_file="${work_dir}/ngtcp2_server.pid"

    # Build command
    local cmd="${NGTCP2_SERVER}"
    cmd+=" ${addr} ${port}"
    cmd+=" ${cert_dir}/server.key ${cert_dir}/server.crt"

    # Parse extra args
    if [[ "${extra_args}" == *"--enable-0rtt"* ]]; then
        cmd+=" --early-data"
    fi

    if [[ "${extra_args}" == *"--enable-session-tickets"* ]]; then
        cmd+=" --session-file ${work_dir}/session.dat"
    fi

    if [[ "${extra_args}" == *"--disable-migration"* ]]; then
        cmd+=" --disable-active-migration"
    fi

    if [[ "${extra_args}" == *"--serve-dir"* ]]; then
        local serve_dir=$(echo "${extra_args}" | grep -oP '(?<=--serve-dir )\S+')
        cmd+=" --htdocs ${serve_dir}"
    fi

    if [[ "${extra_args}" == *"--preferred-address"* ]]; then
        local pref_addr=$(echo "${extra_args}" | grep -oP '(?<=--preferred-address )\S+')
        cmd+=" --preferred-address ${pref_addr}"
    fi

    if [[ "${extra_args}" == *"--ticket-lifetime"* ]]; then
        local lifetime=$(echo "${extra_args}" | grep -oP '(?<=--ticket-lifetime )\S+')
        cmd+=" --ticket-lifetime ${lifetime}"
    fi

    # Verbose output for debugging
    cmd+=" -d"

    # Start server
    log_debug "Starting ngtcp2 server: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${server_log}" 2>&1 &
    local pid=$!

    echo "${pid}" > "${pid_file}"
    log_debug "ngtcp2 server started with PID ${pid}"

    return 0
}

stop_ngtcp2_server() {
    local work_dir="$1"
    local pid_file="${work_dir}/ngtcp2_server.pid"

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

start_ngtcp2_client() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local client_log="${work_dir}/ngtcp2_client.log"

    # Build command
    local cmd="${NGTCP2_CLIENT}"
    cmd+=" ${addr} ${port}"
    cmd+=" https://${addr}:${port}/"

    # Add CA if available
    if [[ -f "${cert_dir}/ca.crt" ]]; then
        cmd+=" --cacert ${cert_dir}/ca.crt"
    fi

    # Parse extra args
    if [[ "${extra_args}" == *"--save-session"* ]]; then
        local session_file=$(echo "${extra_args}" | grep -oP '(?<=--save-session )\S+')
        cmd+=" --session-file ${session_file}"
    fi

    if [[ "${extra_args}" == *"--resume-session"* ]]; then
        local session_file=$(echo "${extra_args}" | grep -oP '(?<=--resume-session )\S+')
        cmd+=" --session-file ${session_file}"
    fi

    if [[ "${extra_args}" == *"--early-data"* ]]; then
        local early_file=$(echo "${extra_args}" | grep -oP '(?<=--early-data )\S+')
        cmd+=" --early-data ${early_file}"
    fi

    if [[ "${extra_args}" == *"--download"* ]]; then
        local download_path=$(echo "${extra_args}" | grep -oP '(?<=--download )\S+')
        cmd+=" https://${addr}:${port}${download_path}"
    fi

    if [[ "${extra_args}" == *"--output"* ]]; then
        local output_file=$(echo "${extra_args}" | grep -oP '(?<=--output )\S+')
        cmd+=" -o ${output_file}"
    fi

    # Verbose output
    cmd+=" -d"

    # Execute client
    log_debug "Running ngtcp2 client: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${client_log}" 2>&1

    return $?
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

stop_ngtcp2() {
    local work_dir="$1"
    stop_ngtcp2_server "${work_dir}"
}

#------------------------------------------------------------------------------
# Installation Helper
#------------------------------------------------------------------------------

install_ngtcp2() {
    echo "Installing ngtcp2..."

    local install_dir="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}"
    mkdir -p "${install_dir}"
    cd "${install_dir}"

    # Check dependencies
    for dep in autoconf automake libtool pkg-config; do
        if ! command -v ${dep} &>/dev/null; then
            echo "${dep} not found. Please install it first."
            return 1
        fi
    done

    # Install nghttp3 (dependency)
    if [[ ! -d "nghttp3" ]]; then
        git clone https://github.com/ngtcp2/nghttp3
        cd nghttp3
        autoreconf -i
        ./configure --prefix="${install_dir}/local" --enable-lib-only
        make -j$(nproc)
        make install
        cd ..
    fi

    # Clone ngtcp2
    if [[ ! -d "ngtcp2" ]]; then
        git clone https://github.com/ngtcp2/ngtcp2
    fi

    cd ngtcp2
    autoreconf -i

    # Configure with OpenSSL
    PKG_CONFIG_PATH="${install_dir}/local/lib/pkgconfig:${PKG_CONFIG_PATH}" \
    ./configure --prefix="${install_dir}/local" \
        --with-openssl \
        --with-libnghttp3

    make -j$(nproc)

    echo "ngtcp2 installed successfully"
    echo "Server: ${install_dir}/ngtcp2/examples/server"
    echo "Client: ${install_dir}/ngtcp2/examples/client"
}

# Create session ticket key file
create_ticket_key() {
    local work_dir="$1"
    local key_file="${work_dir}/ticket.key"

    # Generate 48-byte key for session tickets
    openssl rand -out "${key_file}" 48

    echo "${key_file}"
}

# Run installation if executed directly with --install
if [[ "${1:-}" == "--install" ]]; then
    install_ngtcp2
fi
