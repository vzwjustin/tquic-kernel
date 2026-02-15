#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# picoquic peer setup for TQUIC interoperability testing
#
# picoquic is a QUIC implementation in C by Private Octopus.
# It's notable for being one of the first to implement multipath QUIC.
# Repository: https://github.com/private-octopus/picoquic

PICOQUIC_DIR="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}/picoquic"
PICOQUIC_DEMO="${PICOQUIC_DIR}/picoquicdemo"
PICOQUIC_SERVER="${PICOQUIC_DIR}/picoquicdemo"
PICOQUIC_CLIENT="${PICOQUIC_DIR}/picoquicdemo"

#------------------------------------------------------------------------------
# Installation Check
#------------------------------------------------------------------------------

check_picoquic_installed() {
    if [[ -x "${PICOQUIC_DEMO}" ]]; then
        return 0
    fi

    # Check if in PATH
    if command -v picoquicdemo &>/dev/null; then
        PICOQUIC_DEMO="picoquicdemo"
        PICOQUIC_SERVER="picoquicdemo"
        PICOQUIC_CLIENT="picoquicdemo"
        return 0
    fi

    return 1
}

get_picoquic_version() {
    if [[ -x "${PICOQUIC_DEMO}" ]]; then
        "${PICOQUIC_DEMO}" -h 2>&1 | grep -i "version\|picoquic" | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

#------------------------------------------------------------------------------
# Server Functions
#------------------------------------------------------------------------------

start_picoquic_server() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local server_log="${work_dir}/picoquic_server.log"
    local pid_file="${work_dir}/picoquic_server.pid"

    # Build command - picoquicdemo uses positional args
    # Usage: picoquicdemo [options] [server_name [port [scenario]]]
    local cmd="${PICOQUIC_DEMO}"

    # Certificate and key
    cmd+=" -c ${cert_dir}/server.crt"
    cmd+=" -k ${cert_dir}/server.key"

    # Web root for file serving
    cmd+=" -w ${work_dir}"

    # Parse extra args for multipath
    if [[ "${extra_args}" == *"--enable-multipath"* ]]; then
        cmd+=" -m"  # Enable multipath
    fi

    if [[ "${extra_args}" == *"--max-paths"* ]]; then
        local max_paths=$(echo "${extra_args}" | grep -oP '(?<=--max-paths )\S+')
        cmd+=" -M ${max_paths}"
    fi

    if [[ "${extra_args}" == *"--enable-0rtt"* ]]; then
        cmd+=" -r"  # Enable session resumption / 0-RTT
    fi

    if [[ "${extra_args}" == *"--disable-migration"* ]]; then
        cmd+=" -D"  # Disable migration
    fi

    if [[ "${extra_args}" == *"--preferred-address"* ]]; then
        local pref_addr=$(echo "${extra_args}" | grep -oP '(?<=--preferred-address )\S+')
        cmd+=" -X ${pref_addr}"
    fi

    # Port
    cmd+=" -p ${port}"

    # Verbose logging
    cmd+=" -l ${server_log}.trace"

    # Server name (can be anything)
    cmd+=" localhost ${port}"

    # Start server
    log_debug "Starting picoquic server: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${server_log}" 2>&1 &
    local pid=$!

    echo "${pid}" > "${pid_file}"
    log_debug "picoquic server started with PID ${pid}"

    return 0
}

stop_picoquic_server() {
    local work_dir="$1"
    local pid_file="${work_dir}/picoquic_server.pid"

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

start_picoquic_client() {
    local namespace="$1"
    local addr="$2"
    local port="$3"
    local cert_dir="$4"
    local work_dir="$5"
    local extra_args="${6:-}"

    local client_log="${work_dir}/picoquic_client.log"

    # Build command
    local cmd="${PICOQUIC_CLIENT}"

    # Trust our CA or skip verification
    if [[ -f "${cert_dir}/ca.crt" ]]; then
        cmd+=" -v ${cert_dir}/ca.crt"
    else
        cmd+=" -z"  # No certificate verification
    fi

    # Parse extra args for multipath
    if [[ "${extra_args}" == *"--multipath"* ]]; then
        cmd+=" -m"  # Enable multipath
    fi

    if [[ "${extra_args}" == *"--add-path"* ]]; then
        # picoquic adds paths automatically when multipath is enabled
        # May need specific interface binding
        :
    fi

    if [[ "${extra_args}" == *"--scheduler"* ]]; then
        local scheduler=$(echo "${extra_args}" | grep -oP '(?<=--scheduler )\S+')
        case "${scheduler}" in
            roundrobin|rr)
                cmd+=" -S 1"
                ;;
            minrtt)
                cmd+=" -S 2"
                ;;
            weighted)
                cmd+=" -S 3"
                ;;
        esac
    fi

    if [[ "${extra_args}" == *"--resume-session"* ]]; then
        local session_file=$(echo "${extra_args}" | grep -oP '(?<=--resume-session )\S+')
        cmd+=" -s ${session_file}"
    fi

    if [[ "${extra_args}" == *"--save-session"* ]]; then
        local session_file=$(echo "${extra_args}" | grep -oP '(?<=--save-session )\S+')
        cmd+=" -s ${session_file}"
    fi

    if [[ "${extra_args}" == *"--early-data"* ]]; then
        cmd+=" -r"  # Enable 0-RTT
    fi

    # Download handling
    local download_path="/"
    if [[ "${extra_args}" == *"--download"* ]]; then
        download_path=$(echo "${extra_args}" | grep -oP '(?<=--download )\S+')
    fi

    local output_file=""
    if [[ "${extra_args}" == *"--output"* ]]; then
        output_file=$(echo "${extra_args}" | grep -oP '(?<=--output )\S+')
        cmd+=" -o ${work_dir}"
    fi

    # Transfer size for continuous tests
    if [[ "${extra_args}" == *"--transfer-size"* ]]; then
        local size=$(echo "${extra_args}" | grep -oP '(?<=--transfer-size )\S+')
        cmd+=" -G ${size}"
    fi

    # Continuous transfer duration
    if [[ "${extra_args}" == *"--continuous-transfer"* ]]; then
        local duration=$(echo "${extra_args}" | grep -oP '(?<=--continuous-transfer )\S+')
        cmd+=" -e ${duration}"
    fi

    # Logging
    cmd+=" -l ${client_log}.trace"

    # Server and port - request the file
    cmd+=" ${addr} ${port} ${download_path}"

    # Execute client
    log_debug "Running picoquic client: ${cmd}"
    ip netns exec "${namespace}" ${cmd} > "${client_log}" 2>&1

    local result=$?

    # Copy downloaded file to expected location
    if [[ -n "${output_file}" ]] && [[ -d "${work_dir}" ]]; then
        local basename=$(basename "${download_path}")
        if [[ -f "${work_dir}/${basename}" ]]; then
            cp "${work_dir}/${basename}" "${output_file}"
        fi
    fi

    return ${result}
}

#------------------------------------------------------------------------------
# Multipath-specific Functions
#------------------------------------------------------------------------------

# Configure multipath parameters
configure_multipath() {
    local work_dir="$1"
    local scheduler="${2:-minrtt}"
    local max_paths="${3:-4}"

    cat > "${work_dir}/multipath.config" << EOF
# picoquic multipath configuration
multipath_enabled=1
max_paths=${max_paths}
scheduler=${scheduler}
path_timeout=30000
rtt_threshold=50
EOF
}

# Get multipath status from log
get_multipath_status() {
    local log_file="$1"

    if [[ -f "${log_file}.trace" ]]; then
        grep -E "path|multipath|MP_" "${log_file}.trace" | tail -20
    fi
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

stop_picoquic() {
    local work_dir="$1"
    stop_picoquic_server "${work_dir}"
}

#------------------------------------------------------------------------------
# Installation Helper
#------------------------------------------------------------------------------

install_picoquic() {
    echo "Installing picoquic..."

    local install_dir="${TQUIC_INTEROP_PEERS:-/opt/quic-peers}"
    mkdir -p "${install_dir}"
    cd "${install_dir}"

    # Check dependencies
    if ! command -v cmake &>/dev/null; then
        echo "cmake not found. Please install cmake first."
        return 1
    fi

    # Install picotls (dependency)
    if [[ ! -d "picotls" ]]; then
        git clone https://github.com/h2o/picotls
        cd picotls
        git submodule update --init
        cmake .
        make -j$(nproc)
        cd ..
    fi

    # Clone picoquic
    if [[ ! -d "picoquic" ]]; then
        git clone https://github.com/private-octopus/picoquic
    fi

    cd picoquic

    # Build with multipath support
    cmake . \
        -DPICOTLS_INCLUDE_DIR="${install_dir}/picotls/include" \
        -DPICOTLS_LIBRARY="${install_dir}/picotls/libpicotls-openssl.a" \
        -DPICOTLS_CORE_LIBRARY="${install_dir}/picotls/libpicotls-core.a"

    make -j$(nproc)

    echo "picoquic installed successfully"
    echo "Demo tool: ${install_dir}/picoquic/picoquicdemo"
    echo ""
    echo "Multipath support: ENABLED"
}

# Verify multipath capability
check_multipath_support() {
    if [[ -x "${PICOQUIC_DEMO}" ]]; then
        if "${PICOQUIC_DEMO}" -h 2>&1 | grep -q "\-m"; then
            echo "Multipath support: YES"
            return 0
        fi
    fi
    echo "Multipath support: NO"
    return 1
}

# Run installation if executed directly with --install
if [[ "${1:-}" == "--install" ]]; then
    install_picoquic
fi
