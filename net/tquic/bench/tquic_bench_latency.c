// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Latency Benchmark
 *
 * Measures RTT, jitter, and latency percentiles for TQUIC connections.
 *
 * Target metrics:
 *   - p99 < 2x p50 (low jitter)
 *   - Minimal kernel overhead
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include "bench_common.h"
#include <math.h>

/* Latency sample storage */
#define MAX_SAMPLES 1000000

/* Test configuration */
typedef struct {
    bench_ctx_t ctx;
    int num_samples;
    int interval_us;
    bool histogram_output;
    bool raw_output;
    int payload_size;
} latency_config_t;

/* Latency sample */
typedef struct {
    uint64_t send_time_ns;
    uint64_t recv_time_ns;
    uint64_t rtt_ns;
    int sequence;
} latency_sample_t;

/* Test state */
typedef struct {
    latency_config_t *config;
    latency_sample_t *samples;
    int sample_count;
    int socket_fd;
    struct sockaddr_in target_addr;
} latency_state_t;

/* Forward declarations */
static int run_latency_test(latency_state_t *state);
static void calculate_results(latency_state_t *state, latency_result_t *result);
static void print_results(const latency_result_t *result, bool histogram);
static int compare_doubles(const void *a, const void *b);
static void print_usage(const char *prog);

/* Create UDP ping socket */
static int create_ping_socket(latency_state_t *state, const char *target, uint16_t port)
{
    state->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->socket_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(state->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Enable timestamping */
    int opt = 1;
    setsockopt(state->socket_fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt));

    /* Setup target address */
    memset(&state->target_addr, 0, sizeof(state->target_addr));
    state->target_addr.sin_family = AF_INET;
    state->target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, target, &state->target_addr.sin_addr) != 1) {
        LOG_ERROR("Invalid target address: %s", target);
        close(state->socket_fd);
        return -1;
    }

    return 0;
}

/* Send a timestamped ping packet */
static int send_ping(latency_state_t *state, int sequence, uint64_t *send_time)
{
    struct {
        uint32_t magic;
        uint32_t sequence;
        uint64_t timestamp;
        char padding[64];  /* Minimal payload */
    } __attribute__((packed)) ping_packet;

    ping_packet.magic = 0x54515043;  /* "TQPC" */
    ping_packet.sequence = htonl(sequence);
    *send_time = get_time_ns();
    ping_packet.timestamp = *send_time;

    ssize_t sent = sendto(state->socket_fd, &ping_packet,
                          sizeof(ping_packet), 0,
                          (struct sockaddr *)&state->target_addr,
                          sizeof(state->target_addr));

    if (sent != sizeof(ping_packet)) {
        return -1;
    }

    return 0;
}

/* Receive ping response */
static int recv_pong(latency_state_t *state, int expected_seq, uint64_t *recv_time)
{
    struct {
        uint32_t magic;
        uint32_t sequence;
        uint64_t timestamp;
        char padding[64];
    } __attribute__((packed)) pong_packet;

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t received = recvfrom(state->socket_fd, &pong_packet,
                                 sizeof(pong_packet), 0,
                                 (struct sockaddr *)&from_addr, &from_len);

    *recv_time = get_time_ns();

    if (received < 0) {
        return -1;  /* Timeout or error */
    }

    if (received < (ssize_t)sizeof(pong_packet) ||
        pong_packet.magic != 0x54515043 ||
        (int)ntohl(pong_packet.sequence) != expected_seq) {
        return -2;  /* Invalid response */
    }

    return 0;
}

/* Run the latency test */
static int run_latency_test(latency_state_t *state)
{
    latency_config_t *cfg = state->config;
    int timeout_count = 0;
    int error_count = 0;

    printf("\nCollecting %d latency samples...\n", cfg->num_samples);

    for (int i = 0; i < cfg->num_samples && !g_stop_flag; i++) {
        latency_sample_t *sample = &state->samples[state->sample_count];
        sample->sequence = i;

        /* Send ping */
        if (send_ping(state, i, &sample->send_time_ns) < 0) {
            error_count++;
            LOG_DEBUG("Send error at sample %d", i);
            continue;
        }

        /* Receive pong */
        int ret = recv_pong(state, i, &sample->recv_time_ns);
        if (ret < 0) {
            if (ret == -1) {
                timeout_count++;
                LOG_DEBUG("Timeout at sample %d", i);
            } else {
                error_count++;
                LOG_DEBUG("Invalid response at sample %d", i);
            }
            continue;
        }

        /* Calculate RTT */
        sample->rtt_ns = sample->recv_time_ns - sample->send_time_ns;
        state->sample_count++;

        /* Progress update */
        if ((i + 1) % 1000 == 0 || i == cfg->num_samples - 1) {
            print_progress(i + 1, cfg->num_samples, "Sampling");
        }

        /* Inter-sample delay */
        if (cfg->interval_us > 0) {
            usleep(cfg->interval_us);
        }
    }

    printf("\nCollected %d samples (%d timeouts, %d errors)\n",
           state->sample_count, timeout_count, error_count);

    return state->sample_count > 0 ? 0 : -1;
}

/* Compare function for qsort */
static int compare_doubles(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/* Calculate latency statistics */
static void calculate_results(latency_state_t *state, latency_result_t *result)
{
    if (state->sample_count == 0) {
        memset(result, 0, sizeof(*result));
        return;
    }

    /* Convert RTTs to microseconds and store in array for percentiles */
    double *rtt_us = malloc(state->sample_count * sizeof(double));
    if (!rtt_us) {
        LOG_ERROR("Failed to allocate RTT array");
        return;
    }

    stats_t stats;
    stats_init(&stats);

    for (int i = 0; i < state->sample_count; i++) {
        double rtt = (double)state->samples[i].rtt_ns / 1000.0;  /* ns to us */
        rtt_us[i] = rtt;
        stats_add(&stats, rtt);
    }

    /* Sort for percentile calculation */
    qsort(rtt_us, state->sample_count, sizeof(double), compare_doubles);

    /* Basic statistics */
    result->rtt_avg = stats_mean(&stats);
    result->rtt_min = stats_min(&stats);
    result->rtt_max = stats_max(&stats);
    result->jitter = stats_stddev(&stats);
    result->samples = state->sample_count;

    /* Percentiles */
    result->p50 = rtt_us[(int)(state->sample_count * 0.50)];
    result->p95 = rtt_us[(int)(state->sample_count * 0.95)];
    result->p99 = rtt_us[(int)(state->sample_count * 0.99)];
    result->p999 = rtt_us[(int)(state->sample_count * 0.999)];

    /* Build histogram */
    histogram_init(&result->histogram, 0, result->rtt_max * 1.1, 100);
    for (int i = 0; i < state->sample_count; i++) {
        histogram_add(&result->histogram, rtt_us[i]);
    }

    free(rtt_us);
}

/* Print results */
static void print_results(const latency_result_t *result, bool histogram)
{
    print_header("Latency Results");

    printf("  Samples:     %lu\n", (unsigned long)result->samples);
    printf("\n");
    printf("  RTT Average: %.2f us\n", result->rtt_avg);
    printf("  RTT Min:     %.2f us\n", result->rtt_min);
    printf("  RTT Max:     %.2f us\n", result->rtt_max);
    printf("  Jitter:      %.2f us (std dev)\n", result->jitter);
    printf("\n");
    printf("  Percentiles:\n");
    printf("    p50:       %.2f us\n", result->p50);
    printf("    p95:       %.2f us\n", result->p95);
    printf("    p99:       %.2f us\n", result->p99);
    printf("    p99.9:     %.2f us\n", result->p999);
    printf("\n");

    /* Jitter check */
    if (result->p50 > 0) {
        double p99_ratio = result->p99 / result->p50;
        const char *status = (p99_ratio < 2.0) ? "PASS" : "FAIL";
        printf("  p99/p50 ratio: %.2fx (%s, target: <2x)\n", p99_ratio, status);
    }

    print_separator();

    /* Optional histogram */
    if (histogram) {
        printf("\n");
        histogram_print(&result->histogram, stdout);
    }
}

/* Write JSON report */
static void write_json_report(const char *path, const latency_result_t *result)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        LOG_ERROR("Failed to open report file: %s", path);
        return;
    }

    print_json_start(fp);
    print_json_latency(fp, result);
    print_json_end(fp);
    fclose(fp);

    LOG_INFO("Report written to: %s", path);
}

/* Write raw samples to file */
static void write_raw_samples(const char *path, latency_state_t *state)
{
    char raw_path[MAX_PATH_LENGTH];
    snprintf(raw_path, sizeof(raw_path), "%s.raw.csv", path);

    FILE *fp = fopen(raw_path, "w");
    if (!fp) {
        LOG_ERROR("Failed to open raw file: %s", raw_path);
        return;
    }

    fprintf(fp, "sequence,send_time_ns,recv_time_ns,rtt_us\n");
    for (int i = 0; i < state->sample_count; i++) {
        latency_sample_t *s = &state->samples[i];
        fprintf(fp, "%d,%lu,%lu,%.3f\n",
                s->sequence,
                (unsigned long)s->send_time_ns,
                (unsigned long)s->recv_time_ns,
                (double)s->rtt_ns / 1000.0);
    }

    fclose(fp);
    LOG_INFO("Raw samples written to: %s", raw_path);
}

static void print_usage(const char *prog)
{
    printf("TQUIC Latency Benchmark v%s\n\n", TQUIC_BENCH_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -t, --target ADDR      Target address (default: 127.0.0.1)\n");
    printf("  -p, --port PORT        Target port (default: 4433)\n");
    printf("  -n, --samples NUM      Number of samples (default: %d)\n", DEFAULT_SAMPLES);
    printf("  -i, --interval US      Inter-sample interval in microseconds (default: 1000)\n");
    printf("  -s, --size BYTES       Payload size (default: 64)\n");
    printf("  -H, --histogram        Print histogram output\n");
    printf("  -R, --raw              Write raw samples to file\n");
    printf("  -r, --report FILE      Output JSON report file\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -D, --debug            Debug output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -t 192.168.1.1 -n 10000\n", prog);
    printf("  %s -n 100000 -i 100 -H -r latency.json\n", prog);
    printf("\n");
    printf("Note: This benchmark requires a TQUIC echo server or UDP echo service\n");
    printf("at the target address.\n");
}

int main(int argc, char *argv[])
{
    latency_config_t cfg;
    latency_state_t state;
    latency_result_t result;

    static struct option long_options[] = {
        {"target",    required_argument, 0, 't'},
        {"port",      required_argument, 0, 'p'},
        {"samples",   required_argument, 0, 'n'},
        {"interval",  required_argument, 0, 'i'},
        {"size",      required_argument, 0, 's'},
        {"histogram", no_argument,       0, 'H'},
        {"raw",       no_argument,       0, 'R'},
        {"report",    required_argument, 0, 'r'},
        {"verbose",   no_argument,       0, 'v'},
        {"debug",     no_argument,       0, 'D'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Initialize configuration */
    memset(&cfg, 0, sizeof(cfg));
    bench_ctx_init(&cfg.ctx);
    cfg.num_samples = DEFAULT_SAMPLES;
    cfg.interval_us = 1000;  /* 1ms default */
    cfg.payload_size = 64;
    strncpy(cfg.ctx.target_addr, "127.0.0.1", sizeof(cfg.ctx.target_addr) - 1);
    cfg.ctx.target_port = 4433;

    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "t:p:n:i:s:HRr:vDh", long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            strncpy(cfg.ctx.target_addr, optarg, sizeof(cfg.ctx.target_addr) - 1);
            break;
        case 'p':
            cfg.ctx.target_port = (uint16_t)atoi(optarg);
            break;
        case 'n':
            cfg.num_samples = atoi(optarg);
            break;
        case 'i':
            cfg.interval_us = atoi(optarg);
            break;
        case 's':
            cfg.payload_size = atoi(optarg);
            break;
        case 'H':
            cfg.histogram_output = true;
            break;
        case 'R':
            cfg.raw_output = true;
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

    /* Validate configuration */
    if (cfg.num_samples < 1 || cfg.num_samples > MAX_SAMPLES) {
        LOG_ERROR("Invalid sample count: %d (must be 1-%d)", cfg.num_samples, MAX_SAMPLES);
        return 1;
    }

    /* Setup signal handlers */
    setup_signal_handlers();

    /* Initialize state */
    memset(&state, 0, sizeof(state));
    state.config = &cfg;
    state.samples = calloc(cfg.num_samples, sizeof(latency_sample_t));
    if (!state.samples) {
        LOG_ERROR("Failed to allocate sample storage");
        return 1;
    }

    /* Print test info */
    print_header("TQUIC Latency Benchmark");
    printf("Target: %s:%d\n", cfg.ctx.target_addr, cfg.ctx.target_port);
    printf("Samples: %d\n", cfg.num_samples);
    printf("Interval: %d us\n", cfg.interval_us);
    printf("Payload: %d bytes\n", cfg.payload_size);
    print_separator();

    /* Create socket */
    if (create_ping_socket(&state, cfg.ctx.target_addr, cfg.ctx.target_port) < 0) {
        free(state.samples);
        return 1;
    }

    /* Run test */
    if (run_latency_test(&state) < 0) {
        LOG_ERROR("Latency test failed - no samples collected");
        close(state.socket_fd);
        free(state.samples);
        return 1;
    }

    /* Calculate and print results */
    calculate_results(&state, &result);
    print_results(&result, cfg.histogram_output);

    /* Write reports */
    if (cfg.ctx.report_path[0] != '\0') {
        write_json_report(cfg.ctx.report_path, &result);
        if (cfg.raw_output) {
            write_raw_samples(cfg.ctx.report_path, &state);
        }
    }

    /* Cleanup */
    close(state.socket_fd);
    free(state.samples);
    bench_ctx_destroy(&cfg.ctx);

    return 0;
}
