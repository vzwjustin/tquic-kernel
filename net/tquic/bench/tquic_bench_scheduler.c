// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Scheduler Benchmark
 *
 * Compares different multipath scheduling algorithms,
 * measures scheduling overhead, and analyzes path utilization.
 *
 * Algorithms tested:
 *   - MinRTT: Send on path with minimum RTT
 *   - Round-Robin: Distribute evenly across paths
 *   - Weighted: Distribute based on path capacity
 *   - Redundant: Send on all paths (for reliability)
 *   - BLEST: Blocking Estimation based scheduler
 *   - ECF: Earliest Completion First
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include "bench_common.h"
#include <math.h>

/* Maximum paths for scheduling tests */
#define MAX_PATHS 8

/* Simulated path characteristics */
typedef struct {
    char interface[IFNAMSIZ];
    double bandwidth_gbps;
    double rtt_ms;
    double loss_rate;
    double jitter_ms;
    int weight;

    /* Runtime statistics */
    uint64_t bytes_sent;
    uint64_t packets_sent;
    int socket_fd;
} path_info_t;

/* Test configuration */
typedef struct {
    bench_ctx_t ctx;
    sched_algorithm_t algorithms[SCHED_ALG_MAX];
    int num_algorithms;
    path_info_t paths[MAX_PATHS];
    int num_paths;
    int test_duration_sec;
    int packet_size;
    bool measure_overhead;
} scheduler_config_t;

/* Scheduling decision tracking */
typedef struct {
    uint64_t decisions;
    uint64_t total_time_ns;
    double min_time_ns;
    double max_time_ns;
} sched_overhead_t;

/* Test state */
typedef struct {
    scheduler_config_t *config;
    scheduler_result_t *results;
    int result_count;
    sched_overhead_t overhead;

    /* Current algorithm being tested */
    sched_algorithm_t current_algorithm;

    /* Traffic generation */
    volatile bool running;
    pthread_t traffic_threads[MAX_PATHS];
    uint64_t total_bytes;
    uint64_t total_packets;
} scheduler_state_t;

/* Forward declarations */
static int run_scheduler_test(scheduler_state_t *state, sched_algorithm_t alg, scheduler_result_t *result);
static int select_path_minrtt(scheduler_state_t *state);
static int select_path_roundrobin(scheduler_state_t *state, int *last_path);
static int select_path_weighted(scheduler_state_t *state);
static int select_path_redundant(scheduler_state_t *state, int *paths, int *count);
static int select_path_blest(scheduler_state_t *state);
static int select_path_ecf(scheduler_state_t *state, int packet_size);
static double calculate_fairness_index(scheduler_state_t *state);
static void print_results(scheduler_result_t *results, int count);
static void print_usage(const char *prog);

/* MinRTT scheduler: select path with minimum RTT */
static int select_path_minrtt(scheduler_state_t *state)
{
    scheduler_config_t *cfg = state->config;
    int best_path = 0;
    double min_rtt = cfg->paths[0].rtt_ms;

    for (int i = 1; i < cfg->num_paths; i++) {
        if (cfg->paths[i].rtt_ms < min_rtt) {
            min_rtt = cfg->paths[i].rtt_ms;
            best_path = i;
        }
    }

    return best_path;
}

/* Round-robin scheduler */
static int select_path_roundrobin(scheduler_state_t *state, int *last_path)
{
    *last_path = (*last_path + 1) % state->config->num_paths;
    return *last_path;
}

/* Weighted scheduler based on path capacity */
static int select_path_weighted(scheduler_state_t *state)
{
    scheduler_config_t *cfg = state->config;

    /* Calculate total weight */
    int total_weight = 0;
    for (int i = 0; i < cfg->num_paths; i++) {
        total_weight += cfg->paths[i].weight;
    }

    if (total_weight == 0) return 0;

    /* Random selection based on weight */
    int r = rand() % total_weight;
    int cumulative = 0;

    for (int i = 0; i < cfg->num_paths; i++) {
        cumulative += cfg->paths[i].weight;
        if (r < cumulative) {
            return i;
        }
    }

    return 0;
}

/* Redundant scheduler: returns all paths */
static int select_path_redundant(scheduler_state_t *state, int *paths, int *count)
{
    *count = state->config->num_paths;
    for (int i = 0; i < *count; i++) {
        paths[i] = i;
    }
    return 0;
}

/* BLEST scheduler: Blocking Estimation based */
static int select_path_blest(scheduler_state_t *state)
{
    scheduler_config_t *cfg = state->config;

    /* BLEST considers:
     * - RTT of each path
     * - Available bandwidth
     * - Estimation of blocking at receiver due to reordering
     */

    int best_path = 0;
    double best_score = -1;

    for (int i = 0; i < cfg->num_paths; i++) {
        /* Simple BLEST scoring:
         * Score = bandwidth / (RTT * (1 + queuing_estimate))
         * Higher is better
         */
        double rtt = cfg->paths[i].rtt_ms;
        double bw = cfg->paths[i].bandwidth_gbps;

        /* Estimate queuing based on bytes already sent on this path */
        double queue_factor = 1.0 + (double)cfg->paths[i].bytes_sent / (1024 * 1024);

        double score = bw / (rtt * queue_factor);

        if (score > best_score) {
            best_score = score;
            best_path = i;
        }
    }

    return best_path;
}

/* ECF scheduler: Earliest Completion First */
static int select_path_ecf(scheduler_state_t *state, int packet_size)
{
    scheduler_config_t *cfg = state->config;

    /* ECF selects path that will deliver packet earliest
     * Completion time = current_time + RTT + (packet_size / bandwidth)
     */

    int best_path = 0;
    double best_completion = INFINITY;

    for (int i = 0; i < cfg->num_paths; i++) {
        double rtt = cfg->paths[i].rtt_ms;
        double bw_bps = cfg->paths[i].bandwidth_gbps * 1e9;  /* Convert to bps */
        double transmission_time_ms = (packet_size * 8.0 / bw_bps) * 1000.0;
        double completion_time = rtt + transmission_time_ms;

        if (completion_time < best_completion) {
            best_completion = completion_time;
            best_path = i;
        }
    }

    return best_path;
}

/* Traffic generation per path */
static void *path_traffic_generator(void *arg)
{
    path_info_t *path = (path_info_t *)arg;
    char buffer[9000];  /* Max jumbo frame */
    memset(buffer, 0xAB, sizeof(buffer));

    while (path->socket_fd >= 0) {
        ssize_t sent = send(path->socket_fd, buffer, 1500, MSG_DONTWAIT);
        if (sent > 0) {
            path->bytes_sent += sent;
            path->packets_sent++;
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        usleep(10);  /* Pace traffic */
    }

    return NULL;
}

/* Create path sockets */
static int create_path_sockets(scheduler_state_t *state)
{
    scheduler_config_t *cfg = state->config;
    struct sockaddr_in target;

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->ctx.target_port);
    if (inet_pton(AF_INET, cfg->ctx.target_addr, &target.sin_addr) != 1) {
        return -1;
    }

    for (int i = 0; i < cfg->num_paths; i++) {
        cfg->paths[i].socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (cfg->paths[i].socket_fd < 0) {
            LOG_ERROR("Failed to create socket for path %d", i);
            return -1;
        }

        /* Bind to specific interface if specified */
        if (cfg->paths[i].interface[0] != '\0') {
            if (setsockopt(cfg->paths[i].socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                           cfg->paths[i].interface, strlen(cfg->paths[i].interface)) < 0) {
                LOG_DEBUG("Failed to bind to interface %s", cfg->paths[i].interface);
            }
        }

        if (connect(cfg->paths[i].socket_fd, (struct sockaddr *)&target, sizeof(target)) < 0) {
            LOG_ERROR("Failed to connect path %d socket", i);
            return -1;
        }
    }

    return 0;
}

/* Close path sockets */
static void close_path_sockets(scheduler_state_t *state)
{
    for (int i = 0; i < state->config->num_paths; i++) {
        if (state->config->paths[i].socket_fd >= 0) {
            close(state->config->paths[i].socket_fd);
            state->config->paths[i].socket_fd = -1;
        }
    }
}

/* Run scheduler test for a specific algorithm */
static int run_scheduler_test(scheduler_state_t *state, sched_algorithm_t alg,
                               scheduler_result_t *result)
{
    scheduler_config_t *cfg = state->config;
    char buffer[9000];
    int pkt_size = cfg->packet_size;

    memset(buffer, 0xAB, sizeof(buffer));
    memset(result, 0, sizeof(*result));
    result->algorithm = alg;

    /* Reset path statistics */
    for (int i = 0; i < cfg->num_paths; i++) {
        cfg->paths[i].bytes_sent = 0;
        cfg->paths[i].packets_sent = 0;
    }

    /* Reset overhead tracking */
    state->overhead.decisions = 0;
    state->overhead.total_time_ns = 0;
    state->overhead.min_time_ns = INFINITY;
    state->overhead.max_time_ns = 0;

    state->current_algorithm = alg;
    state->running = true;
    state->total_bytes = 0;
    state->total_packets = 0;

    LOG_INFO("Testing %s scheduler for %d seconds...",
             sched_alg_name(alg), cfg->test_duration_sec);

    int rr_last_path = -1;  /* For round-robin */
    int redundant_paths[MAX_PATHS];
    int redundant_count;

    uint64_t start_time = get_time_ns();
    uint64_t end_time = start_time + (uint64_t)cfg->test_duration_sec * 1000000000ULL;

    while (get_time_ns() < end_time && !g_stop_flag) {
        /* Measure scheduling decision time */
        uint64_t sched_start = 0;
        if (cfg->measure_overhead) {
            sched_start = get_time_ns();
        }

        /* Select path(s) based on algorithm */
        int selected_paths[MAX_PATHS];
        int num_selected = 1;

        switch (alg) {
        case SCHED_ALG_MINRTT:
            selected_paths[0] = select_path_minrtt(state);
            break;
        case SCHED_ALG_ROUNDROBIN:
            selected_paths[0] = select_path_roundrobin(state, &rr_last_path);
            break;
        case SCHED_ALG_WEIGHTED:
            selected_paths[0] = select_path_weighted(state);
            break;
        case SCHED_ALG_REDUNDANT:
            select_path_redundant(state, redundant_paths, &redundant_count);
            memcpy(selected_paths, redundant_paths, redundant_count * sizeof(int));
            num_selected = redundant_count;
            break;
        case SCHED_ALG_BLEST:
            selected_paths[0] = select_path_blest(state);
            break;
        case SCHED_ALG_ECF:
            selected_paths[0] = select_path_ecf(state, pkt_size);
            break;
        default:
            selected_paths[0] = 0;
        }

        /* Record scheduling overhead */
        if (cfg->measure_overhead) {
            uint64_t sched_time = get_time_ns() - sched_start;
            state->overhead.decisions++;
            state->overhead.total_time_ns += sched_time;
            if (sched_time < state->overhead.min_time_ns)
                state->overhead.min_time_ns = sched_time;
            if (sched_time > state->overhead.max_time_ns)
                state->overhead.max_time_ns = sched_time;
        }

        /* Send on selected path(s) */
        for (int i = 0; i < num_selected; i++) {
            int path_idx = selected_paths[i];
            path_info_t *path = &cfg->paths[path_idx];

            ssize_t sent = send(path->socket_fd, buffer, pkt_size, MSG_DONTWAIT);
            if (sent > 0) {
                path->bytes_sent += sent;
                path->packets_sent++;
                state->total_bytes += sent;
                state->total_packets++;
            }
        }

        /* Minimal pacing */
        usleep(1);
    }

    state->running = false;

    /* Calculate results */
    double duration = (double)cfg->test_duration_sec;
    result->throughput_gbps = bytes_to_gbps(state->total_bytes, duration);

    /* Path utilization */
    for (int i = 0; i < cfg->num_paths; i++) {
        result->path_utilization[i] =
            (double)cfg->paths[i].bytes_sent / state->total_bytes;
    }

    /* Scheduling overhead */
    if (state->overhead.decisions > 0) {
        result->scheduling_overhead_us =
            (double)state->overhead.total_time_ns / state->overhead.decisions / 1000.0;
    }

    /* Fairness index (Jain's index) */
    result->fairness_index = calculate_fairness_index(state);

    LOG_INFO("  Throughput: %.3f Gbps, Overhead: %.3f us, Fairness: %.4f",
             result->throughput_gbps, result->scheduling_overhead_us, result->fairness_index);

    return 0;
}

/* Calculate Jain's fairness index */
static double calculate_fairness_index(scheduler_state_t *state)
{
    scheduler_config_t *cfg = state->config;

    if (cfg->num_paths < 2) return 1.0;

    double sum = 0;
    double sum_sq = 0;

    for (int i = 0; i < cfg->num_paths; i++) {
        double util = (double)cfg->paths[i].bytes_sent;
        sum += util;
        sum_sq += util * util;
    }

    if (sum_sq == 0) return 1.0;

    return (sum * sum) / (cfg->num_paths * sum_sq);
}

/* Print results comparison */
static void print_results(scheduler_result_t *results, int count)
{
    print_header("Scheduler Comparison Results");

    printf("  %-12s %12s %12s %12s\n",
           "Algorithm", "Throughput", "Overhead", "Fairness");
    printf("  %-12s %12s %12s %12s\n",
           "-----------", "----------", "--------", "--------");

    double best_throughput = 0;
    const char *best_alg = NULL;

    for (int i = 0; i < count; i++) {
        scheduler_result_t *r = &results[i];
        printf("  %-12s %10.3f Gbps %9.3f us %12.4f\n",
               sched_alg_name(r->algorithm),
               r->throughput_gbps,
               r->scheduling_overhead_us,
               r->fairness_index);

        if (r->throughput_gbps > best_throughput) {
            best_throughput = r->throughput_gbps;
            best_alg = sched_alg_name(r->algorithm);
        }
    }

    print_separator();

    if (best_alg) {
        printf("\nBest performing scheduler: %s (%.3f Gbps)\n", best_alg, best_throughput);
    }

    /* Path utilization breakdown for each algorithm */
    printf("\nPath Utilization by Algorithm:\n");
    printf("  %-12s", "Algorithm");
    for (int p = 0; p < results[0].fairness_index > 0 ? MAX_INTERFACES : 2; p++) {
        printf(" %8s", "Path ");
    }
    printf("\n");

    for (int i = 0; i < count; i++) {
        printf("  %-12s", sched_alg_name(results[i].algorithm));
        for (int p = 0; p < MAX_INTERFACES && results[i].path_utilization[p] > 0.001; p++) {
            printf(" %7.1f%%", results[i].path_utilization[p] * 100);
        }
        printf("\n");
    }
}

/* Write JSON report */
static void write_json_report(const char *path, scheduler_result_t *results, int count)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        LOG_ERROR("Failed to open report file: %s", path);
        return;
    }

    print_json_start(fp);
    fprintf(fp, "  \"scheduler_results\": [\n");

    for (int i = 0; i < count; i++) {
        print_json_scheduler(fp, &results[i], i == count - 1);
    }

    fprintf(fp, "  ]\n");
    print_json_end(fp);
    fclose(fp);

    LOG_INFO("Report written to: %s", path);
}

/* Parse algorithm list */
static int parse_algorithms(const char *str, sched_algorithm_t *algs, int max)
{
    int count = 0;
    char *copy = strdup(str);
    if (!copy) return -1;

    char *token = strtok(copy, ",");
    while (token && count < max) {
        algs[count] = sched_alg_from_name(token);
        count++;
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

static void print_usage(const char *prog)
{
    printf("TQUIC Scheduler Benchmark v%s\n\n", TQUIC_BENCH_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -a, --algorithms LIST  Comma-separated scheduler algorithms\n");
    printf("                         (minrtt,roundrobin,weighted,redundant,blest,ecf)\n");
    printf("  -i, --interfaces LIST  Comma-separated network interfaces\n");
    printf("  -t, --target ADDR      Target address (default: 127.0.0.1)\n");
    printf("  -p, --port PORT        Target port (default: 4433)\n");
    printf("  -d, --duration SEC     Test duration per algorithm (default: 30)\n");
    printf("  -s, --size BYTES       Packet size (default: 1500)\n");
    printf("  -O, --overhead         Measure scheduling overhead\n");
    printf("  -r, --report FILE      Output JSON report file\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -D, --debug            Debug output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Algorithms:\n");
    printf("  minrtt      - Select path with minimum RTT\n");
    printf("  roundrobin  - Distribute evenly across paths\n");
    printf("  weighted    - Distribute based on path capacity\n");
    printf("  redundant   - Send on all paths\n");
    printf("  blest       - Blocking Estimation based scheduler\n");
    printf("  ecf         - Earliest Completion First\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -a minrtt,roundrobin,weighted -i eth0,eth1 -d 30\n", prog);
    printf("  %s -a blest,ecf -i eth0,eth1,wlan0 -O -r scheduler.json\n", prog);
}

int main(int argc, char *argv[])
{
    scheduler_config_t cfg;
    scheduler_state_t state;

    static struct option long_options[] = {
        {"algorithms", required_argument, 0, 'a'},
        {"interfaces", required_argument, 0, 'i'},
        {"target",     required_argument, 0, 't'},
        {"port",       required_argument, 0, 'p'},
        {"duration",   required_argument, 0, 'd'},
        {"size",       required_argument, 0, 's'},
        {"overhead",   no_argument,       0, 'O'},
        {"report",     required_argument, 0, 'r'},
        {"verbose",    no_argument,       0, 'v'},
        {"debug",      no_argument,       0, 'D'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Initialize configuration */
    memset(&cfg, 0, sizeof(cfg));
    bench_ctx_init(&cfg.ctx);
    cfg.test_duration_sec = 30;
    cfg.packet_size = 1500;
    strncpy(cfg.ctx.target_addr, "127.0.0.1", sizeof(cfg.ctx.target_addr) - 1);
    cfg.ctx.target_port = 4433;

    /* Default algorithms */
    cfg.algorithms[0] = SCHED_ALG_MINRTT;
    cfg.algorithms[1] = SCHED_ALG_ROUNDROBIN;
    cfg.algorithms[2] = SCHED_ALG_WEIGHTED;
    cfg.num_algorithms = 3;

    /* Default paths (simulated) */
    cfg.num_paths = 2;
    for (int i = 0; i < cfg.num_paths; i++) {
        cfg.paths[i].bandwidth_gbps = 10.0;
        cfg.paths[i].rtt_ms = 10.0 + i * 5.0;
        cfg.paths[i].weight = 10 - i;
        cfg.paths[i].socket_fd = -1;
    }

    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "a:i:t:p:d:s:Or:vDh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'a':
            cfg.num_algorithms = parse_algorithms(optarg, cfg.algorithms, SCHED_ALG_MAX);
            break;
        case 'i':
            cfg.num_paths = parse_interfaces(optarg, cfg.ctx.interfaces, MAX_INTERFACES);
            for (int i = 0; i < cfg.num_paths; i++) {
                strncpy(cfg.paths[i].interface, cfg.ctx.interfaces[i], IFNAMSIZ - 1);
                cfg.paths[i].bandwidth_gbps = 10.0;
                cfg.paths[i].rtt_ms = 10.0 + i * 5.0;
                cfg.paths[i].weight = 10 - i;
                cfg.paths[i].socket_fd = -1;
            }
            break;
        case 't':
            strncpy(cfg.ctx.target_addr, optarg, sizeof(cfg.ctx.target_addr) - 1);
            break;
        case 'p':
            cfg.ctx.target_port = (uint16_t)atoi(optarg);
            break;
        case 'd':
            cfg.test_duration_sec = atoi(optarg);
            break;
        case 's':
            cfg.packet_size = atoi(optarg);
            break;
        case 'O':
            cfg.measure_overhead = true;
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

    /* Validate */
    if (cfg.num_algorithms < 1) {
        LOG_ERROR("No algorithms specified");
        return 1;
    }
    if (cfg.num_paths < 1) {
        LOG_ERROR("No paths/interfaces specified");
        return 1;
    }

    /* Setup signal handlers */
    setup_signal_handlers();

    /* Initialize state */
    memset(&state, 0, sizeof(state));
    state.config = &cfg;
    state.results = calloc(cfg.num_algorithms, sizeof(scheduler_result_t));
    if (!state.results) {
        LOG_ERROR("Failed to allocate results storage");
        return 1;
    }

    /* Print test info */
    print_header("TQUIC Scheduler Benchmark");
    printf("Target: %s:%d\n", cfg.ctx.target_addr, cfg.ctx.target_port);
    printf("Paths: %d\n", cfg.num_paths);
    for (int i = 0; i < cfg.num_paths; i++) {
        printf("  Path %d: %s (BW: %.1f Gbps, RTT: %.1f ms, Weight: %d)\n",
               i, cfg.paths[i].interface[0] ? cfg.paths[i].interface : "default",
               cfg.paths[i].bandwidth_gbps, cfg.paths[i].rtt_ms, cfg.paths[i].weight);
    }
    printf("Algorithms: ");
    for (int i = 0; i < cfg.num_algorithms; i++) {
        printf("%s%s", sched_alg_name(cfg.algorithms[i]),
               i < cfg.num_algorithms - 1 ? ", " : "\n");
    }
    printf("Duration per algorithm: %d seconds\n", cfg.test_duration_sec);
    printf("Packet size: %d bytes\n", cfg.packet_size);
    printf("Overhead measurement: %s\n", cfg.measure_overhead ? "Enabled" : "Disabled");
    print_separator();

    /* Create path sockets */
    if (create_path_sockets(&state) < 0) {
        free(state.results);
        return 1;
    }

    /* Run tests for each algorithm */
    for (int i = 0; i < cfg.num_algorithms && !g_stop_flag; i++) {
        printf("\n=== Testing %s ===\n", sched_alg_name(cfg.algorithms[i]));

        if (run_scheduler_test(&state, cfg.algorithms[i], &state.results[i]) == 0) {
            state.result_count++;
        }

        /* Brief pause between algorithms */
        if (i < cfg.num_algorithms - 1) {
            sleep(2);
        }
    }

    /* Close sockets */
    close_path_sockets(&state);

    /* Print results */
    if (state.result_count > 0) {
        printf("\n");
        print_results(state.results, state.result_count);

        /* Write report */
        if (cfg.ctx.report_path[0] != '\0') {
            write_json_report(cfg.ctx.report_path, state.results, state.result_count);
        }
    }

    /* Cleanup */
    free(state.results);
    bench_ctx_destroy(&cfg.ctx);

    return 0;
}
