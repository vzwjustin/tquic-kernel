#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Microsoft msquic peer setup for TQUIC interoperability testing
#
# msquic is Microsoft's cross-platform QUIC implementation.
# Repository: https://github.com/microsoft/msquic

MSQUIC_DIR="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}/msquic"
MSQUIC_SERVER="${MSQUIC_DIR}/build/bin/Release/quicsample"
MSQUIC_INTEROP="${MSQUIC_DIR}/build/bin/Release/quicinterop"
MSQUIC_SPIN="${MSQUIC_DIR}/build/bin/Release/spinquic"

#------------------------------------------------------------------------------
# Installation Check
#------------------------------------------------------------------------------

check_msquic_installed() {
    if [[ -x "${MSQUIC_SERVER}" ]] || [[ -x "${MSQUIC_INTEROP}" ]]; then
        return 0
    fi

    # Check if msquic tools are in PATH
    if command -v quicsample &>/dev/null; then
        MSQUIC_SERVER="quicsample"
        return 0
    fi

    if command -v quicinterop &>/dev/null; then
        MSQUIC_INTEROP="quicinterop"
        return 0
    fi

    return 1
}

get_msquic_version() {
    if [[ -x "${MSQUIC_INTEROP}" ]]; then
        "${MSQUIC_INTEROP}" --help 2>&1 | grep -i version | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

#------------------------------------------------------------------------------
# Server Functions
#------------------------------------------------------------------------------

start_msquic_server() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local server_log="${work_dir}/msquic_server.log"
    local pid_file="${work_dir}/msquic_server.pid"

    # Use interop tool for testing
    local cmd=""

    if [[ -x "${MSQUIC_INTEROP}" ]]; then
        cmd="${MSQUIC_INTEROP}"
        cmd+=" -server"
        cmd+=" -port:${port}"
        cmd+=" -cert_file:${cert_dir}/server.crt"
        cmd+=" -key_file:${cert_dir}/server.key"
    elif [[ -x "${MSQUIC_SERVER}" ]]; then
        cmd="${MSQUIC_SERVER}"
        cmd+=" -server"
        cmd+=" -port:${port}"
        cmd+=" -cert_file:${cert_dir}/server.crt"
        cmd+=" -key_file:${cert_dir}/server.key"
    else
        log_fail "No msquic server binary found"
        return 1
    fi

    # Parse extra args
    if [[ "${extra_args}" == *"--enable-0rtt"* ]]; then
        cmd+=" -resume"
    fi

    if [[ "${extra_args}" == *"--disable-migration"* ]]; then
        cmd+=" -disable_migration"
    fi

    # Start server
    log_debug "Starting msquic server: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${server_log}" 2>&1 &
    local pid=$!

    echo "${pid}" > "${pid_file}"
    log_debug "msquic server started with PID ${pid}"

    return 0
}

stop_msquic_server() {
    local work_dir="$1"
    local pid_file="${work_dir}/msquic_server.pid"

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

start_msquic_client() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local client_log="${work_dir}/msquic_client.log"

    local cmd=""

    if [[ -x "${MSQUIC_INTEROP}" ]]; then
        cmd="${MSQUIC_INTEROP}"
        cmd+=" -client"
        cmd+=" -target:${addr}"
        cmd+=" -port:${port}"
        cmd+=" -unsecure"  # Accept any certificate
    elif [[ -x "${MSQUIC_SERVER}" ]]; then
        cmd="${MSQUIC_SERVER}"
        cmd+=" -client"
        cmd+=" -target:${addr}"
        cmd+=" -port:${port}"
        cmd+=" -unsecure"
    else
        log_fail "No msquic client binary found"
        return 1
    fi

    # Parse extra args
    if [[ "${extra_args}" == *"--resume-session"* ]]; then
        cmd+=" -resume"
    fi

    # Execute client
    log_debug "Running msquic client: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${client_log}" 2>&1

    return $?
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

stop_msquic() {
    local work_dir="$1"
    stop_msquic_server "${work_dir}"
}

#------------------------------------------------------------------------------
# Installation Helper
#------------------------------------------------------------------------------

install_msquic() {
    echo "Installing msquic..."

    local install_dir="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}"
    mkdir -p "${install_dir}"
    cd "${install_dir}"

    # Check dependencies
    if ! command -v cmake &>/dev/null; then
        echo "cmake not found. Please install cmake first."
        return 1
    fi

    # Clone repository
    if [[ ! -d "msquic" ]]; then
        git clone --recursive https://github.com/microsoft/msquic
    fi

    cd msquic

    # Build
    mkdir -p build
    cd build

    cmake -G 'Unix Makefiles' \
        -DCMAKE_BUILD_TYPE=Release \
        -DQUIC_BUILD_TOOLS=ON \
        -DQUIC_BUILD_TEST=ON \
        -DQUIC_BUILD_PERF=ON \
        ..

    cmake --build . --config Release

    echo "msquic installed successfully"
    echo "Interop tool: ${install_dir}/msquic/build/bin/Release/quicinterop"
    echo "Sample: ${install_dir}/msquic/build/bin/Release/quicsample"
}

# Environment setup for msquic
setup_msquic_env() {
    local work_dir="$1"

    # msquic might need specific environment variables
    export QUIC_TLS=openssl

    # Create any needed configuration
    cat > "${work_dir}/msquic.config" << EOF
{
    "Settings": {
        "MaxWorkerQueueDelayUs": 2500,
        "MaxStatelessOperations": 16,
        "InitialWindowPackets": 10,
        "SendBufferingEnabled": 1,
        "PacingEnabled": 1,
        "MigrationEnabled": 1,
        "DatagramReceiveEnabled": 1,
        "ServerResumptionLevel": 2,
        "MinimumMtu": 1248,
        "MaximumMtu": 1500
    }
}
EOF
}

# Run installation if executed directly with --install
if [[ "${1:-}" == "--install" ]]; then
    install_msquic
fi
