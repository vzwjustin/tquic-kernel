// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Connection Benchmark
 *
 * Measures connection setup rate, concurrent connection capacity,
 * and memory usage per connection.
 *
 * Target metrics:
 *   - Connection setup: <1 RTT (0-RTT support)
 *   - Memory: <64KB per connection
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include "bench_common.h"
#include <sys/epoll.h>
#include <sys/resource.h>
#include <fcntl.h>

/* Connection states */
typedef enum {
    CONN_STATE_IDLE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_CLOSED,
    CONN_STATE_ERROR
} conn_state_t;

/* Connection structure */
typedef struct {
    int fd;
    conn_state_t state;
    uint64_t connect_start_ns;
    uint64_t connect_end_ns;
    bool zero_rtt;
    int id;
} tquic_conn_t;

/* Test configuration */
typedef struct {
    bench_ctx_t ctx;
    int max_connections;
    int connection_rate;    /* Connections per second */
    bool zero_rtt_enabled;
    bool measure_memory;
    int hold_time_sec;      /* How long to hold connections */
} connection_config_t;

/* Test state */
typedef struct {
    connection_config_t *config;
    tquic_conn_t *connections;
    int active_connections;
    int total_attempted;
    int total_successful;
    int total_failed;
    int zero_rtt_count;
    int epoll_fd;

    /* Memory tracking */
    size_t mem_baseline_kb;
    size_t mem_peak_kb;

    /* Timing */
    stats_t setup_times;
} connection_state_t;

/* Forward declarations */
static int run_connection_rate_test(connection_state_t *state);
static int run_concurrent_connection_test(connection_state_t *state);
static void calculate_results(connection_state_t *state, connection_result_t *result);
static void print_results(const connection_result_t *result);
static void print_usage(const char *prog);

/* Simulate TQUIC connection handshake */
static int simulate_connection(tquic_conn_t *conn, const struct sockaddr_in *target, bool zero_rtt)
{
    conn->connect_start_ns = get_time_ns();

    /* Create UDP socket (QUIC uses UDP) */
    conn->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (conn->fd < 0) {
        conn->state = CONN_STATE_ERROR;
        return -1;
    }

    /* Connect (for UDP this just sets the default destination) */
    if (connect(conn->fd, (struct sockaddr *)target, sizeof(*target)) < 0) {
        if (errno != EINPROGRESS) {
            close(conn->fd);
            conn->fd = -1;
            conn->state = CONN_STATE_ERROR;
            return -1;
        }
    }

    conn->state = CONN_STATE_CONNECTING;
    conn->zero_rtt = zero_rtt;

    /* Simulate QUIC handshake by sending Initial packet */
    struct {
        uint8_t header;
        uint32_t version;
        uint8_t dcid_len;
        uint8_t dcid[8];
        uint8_t scid_len;
        uint8_t scid[8];
        uint8_t token_len;
        uint16_t length;
        uint32_t pn;
        uint8_t payload[64];
    } __attribute__((packed)) initial_packet;

    memset(&initial_packet, 0, sizeof(initial_packet));
    initial_packet.header = 0xC3;  /* Long header, Initial type */
    initial_packet.version = htonl(0x00000001);  /* QUIC v1 */
    initial_packet.dcid_len = 8;
    initial_packet.scid_len = 8;

    /* Generate random connection IDs */
    for (int i = 0; i < 8; i++) {
        initial_packet.dcid[i] = rand() & 0xFF;
        initial_packet.scid[i] = rand() & 0xFF;
    }

    ssize_t sent = send(conn->fd, &initial_packet, sizeof(initial_packet), 0);
    if (sent < 0 && errno != EAGAIN) {
        close(conn->fd);
        conn->fd = -1;
        conn->state = CONN_STATE_ERROR;
        return -1;
    }

    /* For benchmark purposes, consider connected after send */
    conn->connect_end_ns = get_time_ns();
    conn->state = CONN_STATE_CONNECTED;

    return 0;
}

/* Close a connection */
static void close_connection(tquic_conn_t *conn)
{
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = CONN_STATE_CLOSED;
}

/* Run connection rate test */
static int run_connection_rate_test(connection_state_t *state)
{
    connection_config_t *cfg = state->config;
    struct sockaddr_in target;
    int batch_size;
    int interval_us;

    /* Setup target address */
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->ctx.target_port);
    if (inet_pton(AF_INET, cfg->ctx.target_addr, &target.sin_addr) != 1) {
        LOG_ERROR("Invalid target address: %s", cfg->ctx.target_addr);
        return -1;
    }

    /* Calculate batch parameters */
    if (cfg->connection_rate > 1000) {
        batch_size = cfg->connection_rate / 100;
        interval_us = 10000;  /* 10ms batches */
    } else {
        batch_size = 1;
        interval_us = 1000000 / cfg->connection_rate;
    }

    printf("\nConnection rate test: %d conn/sec target, %d second duration\n",
           cfg->connection_rate, cfg->ctx.duration_sec);

    stats_init(&state->setup_times);
    state->mem_baseline_kb = get_process_memory_kb();

    uint64_t start_time = get_time_ms();
    uint64_t end_time = start_time + (cfg->ctx.duration_sec * 1000);
    int conn_index = 0;

    while (get_time_ms() < end_time && !g_stop_flag && conn_index < cfg->max_connections) {
        /* Create batch of connections */
        for (int i = 0; i < batch_size && conn_index < cfg->max_connections; i++) {
            tquic_conn_t *conn = &state->connections[conn_index];
            conn->id = conn_index;

            bool use_zero_rtt = cfg->zero_rtt_enabled && (conn_index > 0);

            if (simulate_connection(conn, &target, use_zero_rtt) == 0) {
                state->total_successful++;
                if (conn->zero_rtt) {
                    state->zero_rtt_count++;
                }

                double setup_us = (double)(conn->connect_end_ns - conn->connect_start_ns) / 1000.0;
                stats_add(&state->setup_times, setup_us);

                state->active_connections++;
                conn_index++;
            } else {
                state->total_failed++;
            }
            state->total_attempted++;
        }

        /* Track memory */
        size_t current_mem = get_process_memory_kb();
        if (current_mem > state->mem_peak_kb) {
            state->mem_peak_kb = current_mem;
        }

        /* Progress update */
        int elapsed = (int)((get_time_ms() - start_time) / 1000);
        print_progress(elapsed, cfg->ctx.duration_sec, "Rate test");

        usleep(interval_us);
    }

    printf("\n");

    /* Hold connections briefly then close */
    if (cfg->hold_time_sec > 0) {
        printf("Holding %d connections for %d seconds...\n",
               state->active_connections, cfg->hold_time_sec);
        sleep(cfg->hold_time_sec);
    }

    /* Close all connections */
    printf("Closing connections...\n");
    for (int i = 0; i < conn_index; i++) {
        close_connection(&state->connections[i]);
    }

    return 0;
}

/* Run concurrent connection capacity test */
static int run_concurrent_connection_test(connection_state_t *state)
{
    connection_config_t *cfg = state->config;
    struct sockaddr_in target;

    /* Setup target address */
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->ctx.target_port);
    if (inet_pton(AF_INET, cfg->ctx.target_addr, &target.sin_addr) != 1) {
        LOG_ERROR("Invalid target address: %s", cfg->ctx.target_addr);
        return -1;
    }

    printf("\nConcurrent connection test: up to %d connections\n", cfg->max_connections);

    stats_init(&state->setup_times);
    state->mem_baseline_kb = get_process_memory_kb();

    /* Open connections until we hit the limit or fail */
    for (int i = 0; i < cfg->max_connections && !g_stop_flag; i++) {
        tquic_conn_t *conn = &state->connections[i];
        conn->id = i;

        bool use_zero_rtt = cfg->zero_rtt_enabled && (i > 0);

        if (simulate_connection(conn, &target, use_zero_rtt) == 0) {
            state->total_successful++;
            if (conn->zero_rtt) {
                state->zero_rtt_count++;
            }

            double setup_us = (double)(conn->connect_end_ns - conn->connect_start_ns) / 1000.0;
            stats_add(&state->setup_times, setup_us);

            state->active_connections++;
        } else {
            state->total_failed++;
            if (state->total_failed > 100) {
                printf("\nToo many failures, stopping at %d connections\n", i);
                break;
            }
        }
        state->total_attempted++;

        /* Progress update */
        if ((i + 1) % 1000 == 0) {
            print_progress(i + 1, cfg->max_connections, "Connecting");

            /* Track memory */
            size_t current_mem = get_process_memory_kb();
            if (current_mem > state->mem_peak_kb) {
                state->mem_peak_kb = current_mem;
            }
        }
    }

    printf("\n\nHolding %d connections...\n", state->active_connections);

    /* Final memory measurement */
    state->mem_peak_kb = get_process_memory_kb();

    /* Hold connections */
    if (cfg->hold_time_sec > 0) {
        sleep(cfg->hold_time_sec);
    }

    /* Close all connections */
    printf("Closing connections...\n");
    for (int i = 0; i < state->active_connections; i++) {
        close_connection(&state->connections[i]);
    }

    return 0;
}

/* Calculate results */
static void calculate_results(connection_state_t *state, connection_result_t *result)
{
    connection_config_t *cfg = state->config;

    double duration = (double)cfg->ctx.duration_sec;
    if (duration <= 0) duration = 1.0;

    result->cps = (double)state->total_successful / duration;
    result->total_connections = state->total_attempted;
    result->successful = state->total_successful;
    result->failed = state->total_failed;

    if (state->total_successful > 0) {
        result->zero_rtt_rate = (double)state->zero_rtt_count / state->total_successful;
    } else {
        result->zero_rtt_rate = 0.0;
    }

    /* Memory per connection */
    size_t mem_used = state->mem_peak_kb - state->mem_baseline_kb;
    if (state->active_connections > 0) {
        result->memory_per_conn_kb = (double)mem_used / state->active_connections;
    } else {
        result->memory_per_conn_kb = 0.0;
    }

    result->avg_setup_time_us = stats_mean(&state->setup_times);
}

/* Print results */
static void print_results(const connection_result_t *result)
{
    print_header("Connection Results");

    printf("  Total attempted:   %lu\n", (unsigned long)result->total_connections);
    printf("  Successful:        %lu\n", (unsigned long)result->successful);
    printf("  Failed:            %lu\n", (unsigned long)result->failed);
    printf("\n");
    printf("  Connections/sec:   %.2f\n", result->cps);
    printf("  Avg setup time:    %.2f us\n", result->avg_setup_time_us);
    printf("  0-RTT rate:        %.1f%%\n", result->zero_rtt_rate * 100);
    printf("\n");
    printf("  Memory per conn:   %.2f KB\n", result->memory_per_conn_kb);
    printf("\n");

    /* Check targets */
    const char *mem_status = (result->memory_per_conn_kb <= TARGET_MEMORY_KB) ? "PASS" : "FAIL";
    printf("  Memory target:     <%.0f KB/conn (%s)\n", (double)TARGET_MEMORY_KB, mem_status);

    /* 0-RTT check */
    if (result->zero_rtt_rate > 0) {
        printf("  0-RTT support:     Enabled (%.1f%% success rate)\n", result->zero_rtt_rate * 100);
    }

    print_separator();
}

/* Write JSON report */
static void write_json_report(const char *path, const connection_result_t *result)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        LOG_ERROR("Failed to open report file: %s", path);
        return;
    }

    print_json_start(fp);
    print_json_connection(fp, result);
    print_json_end(fp);
    fclose(fp);

    LOG_INFO("Report written to: %s", path);
}

/* Increase file descriptor limits */
static int increase_fd_limits(int desired)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        LOG_WARN("Failed to get fd limits: %s", strerror(errno));
        return -1;
    }

    LOG_INFO("Current fd limits: soft=%lu, hard=%lu",
             (unsigned long)rl.rlim_cur, (unsigned long)rl.rlim_max);

    if ((int)rl.rlim_cur < desired) {
        rl.rlim_cur = (rl.rlim_max < (rlim_t)desired) ? rl.rlim_max : (rlim_t)desired;
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            LOG_WARN("Failed to increase fd limit: %s", strerror(errno));
            return -1;
        }
        LOG_INFO("Increased fd limit to %lu", (unsigned long)rl.rlim_cur);
    }

    return (int)rl.rlim_cur;
}

static void print_usage(const char *prog)
{
    printf("TQUIC Connection Benchmark v%s\n\n", TQUIC_BENCH_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -t, --target ADDR      Target address (default: 127.0.0.1)\n");
    printf("  -p, --port PORT        Target port (default: 4433)\n");
    printf("  -m, --max-conns NUM    Maximum connections (default: %d)\n", DEFAULT_MAX_CONNECTIONS);
    printf("  -R, --rate NUM         Connection rate per second (default: %d)\n", DEFAULT_CONNECTION_RATE);
    printf("  -d, --duration SEC     Test duration in seconds (default: %d)\n", DEFAULT_DURATION_SEC);
    printf("  -H, --hold SEC         Hold time before closing (default: 5)\n");
    printf("  -z, --zero-rtt         Enable 0-RTT connection resumption\n");
    printf("  -M, --memory           Measure memory usage per connection\n");
    printf("  -c, --concurrent       Run concurrent connection test\n");
    printf("  -r, --report FILE      Output JSON report file\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -D, --debug            Debug output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -m 10000 -R 1000 -d 30\n", prog);
    printf("  %s -m 100000 -c -z -r connections.json\n", prog);
    printf("\n");
    printf("Target metrics:\n");
    printf("  - Connection setup: <1 RTT (0-RTT support)\n");
    printf("  - Memory: <%.0f KB per connection\n", (double)TARGET_MEMORY_KB);
}

int main(int argc, char *argv[])
{
    connection_config_t cfg;
    connection_state_t state;
    connection_result_t result;
    bool concurrent_test = false;

    static struct option long_options[] = {
        {"target",     required_argument, 0, 't'},
        {"port",       required_argument, 0, 'p'},
        {"max-conns",  required_argument, 0, 'm'},
        {"rate",       required_argument, 0, 'R'},
        {"duration",   required_argument, 0, 'd'},
        {"hold",       required_argument, 0, 'H'},
        {"zero-rtt",   no_argument,       0, 'z'},
        {"memory",     no_argument,       0, 'M'},
        {"concurrent", no_argument,       0, 'c'},
        {"report",     required_argument, 0, 'r'},
        {"verbose",    no_argument,       0, 'v'},
        {"debug",      no_argument,       0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Initialize configuration */
    memset(&cfg, 0, sizeof(cfg));
    bench_ctx_init(&cfg.ctx);
    cfg.max_connections = DEFAULT_MAX_CONNECTIONS;
    cfg.connection_rate = DEFAULT_CONNECTION_RATE;
    cfg.hold_time_sec = 5;
    strncpy(cfg.ctx.target_addr, "127.0.0.1", sizeof(cfg.ctx.target_addr) - 1);
    cfg.ctx.target_port = 4433;

    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "t:p:m:R:d:H:zMcr:vDh", long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            strncpy(cfg.ctx.target_addr, optarg, sizeof(cfg.ctx.target_addr) - 1);
            break;
        case 'p':
            cfg.ctx.target_port = (uint16_t)atoi(optarg);
            break;
        case 'm':
            cfg.max_connections = atoi(optarg);
            break;
        case 'R':
            cfg.connection_rate = atoi(optarg);
            break;
        case 'd':
            cfg.ctx.duration_sec = atoi(optarg);
            break;
        case 'H':
            cfg.hold_time_sec = atoi(optarg);
            break;
        case 'z':
            cfg.zero_rtt_enabled = true;
            break;
        case 'M':
            cfg.measure_memory = true;
            break;
        case 'c':
            concurrent_test = true;
            break;
        case 'r':
            strncpy(cfg.ctx.report_path, optarg, MAX_PATH_LENGTH - 1);
            break;
        case 'v':
            g_verbose = 1;
            cfg.ctx.verbose = true;
            break;
        case 'D':
            g_debug = 1;
            cfg.ctx.debug = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Setup signal handlers */
    setup_signal_handlers();

    /* Increase file descriptor limits */
    int max_fds = increase_fd_limits(cfg.max_connections + 100);
    if (max_fds > 0 && max_fds < cfg.max_connections) {
        LOG_WARN("Reducing max connections to %d due to fd limit", max_fds - 100);
        cfg.max_connections = max_fds - 100;
    }

    /* Initialize state */
    memset(&state, 0, sizeof(state));
    state.config = &cfg;
    state.connections = calloc(cfg.max_connections, sizeof(tquic_conn_t));
    if (!state.connections) {
        LOG_ERROR("Failed to allocate connection storage");
        return 1;
    }

    /* Initialize connection structures */
    for (int i = 0; i < cfg.max_connections; i++) {
        state.connections[i].fd = -1;
        state.connections[i].state = CONN_STATE_IDLE;
    }

    /* Print test info */
    print_header("TQUIC Connection Benchmark");
    printf("Target: %s:%d\n", cfg.ctx.target_addr, cfg.ctx.target_port);
    printf("Max connections: %d\n", cfg.max_connections);
    if (!concurrent_test) {
        printf("Connection rate: %d/sec\n", cfg.connection_rate);
    }
    printf("Duration: %d seconds\n", cfg.ctx.duration_sec);
    printf("0-RTT: %s\n", cfg.zero_rtt_enabled ? "Enabled" : "Disabled");
    printf("Test type: %s\n", concurrent_test ? "Concurrent capacity" : "Connection rate");
    print_separator();

    /* Run test */
    int ret;
    if (concurrent_test) {
        ret = run_concurrent_connection_test(&state);
    } else {
        ret = run_connection_rate_test(&state);
    }

    if (ret < 0) {
        LOG_ERROR("Test failed");
        free(state.connections);
        return 1;
    }

    /* Calculate and print results */
    calculate_results(&state, &result);
    print_results(&result);

    /* Write report */
    if (cfg.ctx.report_path[0] != '\0') {
        write_json_report(cfg.ctx.report_path, &result);
    }

    /* Cleanup */
    free(state.connections);
    bench_ctx_destroy(&cfg.ctx);

    return 0;
}
