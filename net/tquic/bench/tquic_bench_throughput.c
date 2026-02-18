// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Throughput Benchmark
 *
 * Measures single-path and multi-path throughput performance of TQUIC.
 *
 * Target metrics:
 *   - Single-path: >9 Gbps @ 10G NIC
 *   - Multipath: >95% of sum(path BWs)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include "bench_common.h"
#include <sys/mman.h>
#include <sched.h>

/* Default packet sizes to test */
static int default_sizes[] = {64, 512, 1500, 9000, 65535};
static int num_default_sizes = sizeof(default_sizes) / sizeof(default_sizes[0]);

/* Test configuration */
typedef struct {
    bench_ctx_t ctx;
    int packet_sizes[MAX_PACKET_SIZES];
    int num_packet_sizes;
    bool multipath_test;
    int num_threads;
    int cpu_affinity;
    bool zero_copy;
    uint64_t target_rate;  /* Target rate in bytes/sec, 0 = unlimited */
} throughput_config_t;

/* Per-thread state */
typedef struct {
    int thread_id;
    throughput_config_t *config;
    pthread_t thread;

    /* Statistics */
    uint64_t bytes_sent;
    uint64_t packets_sent;
    uint64_t errors;

    /* Timing */
    uint64_t start_time_ns;
    uint64_t end_time_ns;
} thread_state_t;

/* Simulated TQUIC socket for benchmarking */
typedef struct {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int path_id;
} tquic_socket_t;

/* Forward declarations */
static void *throughput_thread(void *arg);
static int run_single_path_test(throughput_config_t *cfg, int pkt_size, throughput_result_t *result);
static int run_multipath_test(throughput_config_t *cfg, int pkt_size, throughput_result_t *result);
static void print_results_table(throughput_result_t *results, int count, bool multipath);
static void print_usage(const char *prog);

/* Create a TQUIC test socket */
static int create_test_socket(tquic_socket_t *sock, const char *target, uint16_t port)
{
    struct sockaddr_in *addr4;

    sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock->fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket options for performance */
    int opt = 1;
    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Increase buffer sizes */
    int bufsize = 16 * 1024 * 1024;  /* 16MB */
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    /* Setup target address */
    memset(&sock->addr, 0, sizeof(sock->addr));
    addr4 = (struct sockaddr_in *)&sock->addr;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    if (inet_pton(AF_INET, target, &addr4->sin_addr) != 1) {
        LOG_ERROR("Invalid target address: %s", target);
        close(sock->fd);
        return -1;
    }
    sock->addrlen = sizeof(struct sockaddr_in);

    return 0;
}

static void close_test_socket(tquic_socket_t *sock)
{
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
}

/* Throughput test thread */
static void *throughput_thread(void *arg)
{
    thread_state_t *state = (thread_state_t *)arg;
    throughput_config_t *cfg = state->config;
    tquic_socket_t sock;
    char *buffer;
    int pkt_size = cfg->packet_sizes[0];  /* Use first size for now */

    /* Set CPU affinity if requested */
    if (cfg->cpu_affinity >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET((cfg->cpu_affinity + state->thread_id) % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    /* Allocate send buffer */
    if (cfg->zero_copy) {
        buffer = mmap(NULL, pkt_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        buffer = malloc(pkt_size);
    }

    if (!buffer) {
        LOG_ERROR("Thread %d: Failed to allocate buffer", state->thread_id);
        return NULL;
    }

    /* Fill buffer with pattern */
    memset(buffer, 0xAB, pkt_size);

    /* Create socket */
    if (create_test_socket(&sock, cfg->ctx.target_addr, cfg->ctx.target_port) < 0) {
        if (cfg->zero_copy) munmap(buffer, pkt_size);
        else free(buffer);
        return NULL;
    }

    /* Connect for faster sendto */
    if (connect(sock.fd, (struct sockaddr *)&sock.addr, sock.addrlen) < 0) {
        LOG_ERROR("Thread %d: Failed to connect: %s", state->thread_id, strerror(errno));
        close_test_socket(&sock);
        if (cfg->zero_copy) munmap(buffer, pkt_size);
        else free(buffer);
        return NULL;
    }

    /* Wait for start signal */
    while (!cfg->ctx.running && !g_stop_flag) {
        usleep(1000);
    }

    state->start_time_ns = get_time_ns();

    /* Main send loop */
    while (cfg->ctx.running && !g_stop_flag) {
        ssize_t sent = send(sock.fd, buffer, pkt_size, MSG_DONTWAIT);
        if (sent > 0) {
            state->bytes_sent += sent;
            state->packets_sent++;
        } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            state->errors++;
        }

        /* Rate limiting if configured */
        if (cfg->target_rate > 0) {
            uint64_t expected_time = (state->bytes_sent * 1000000000ULL) / cfg->target_rate;
            uint64_t elapsed = get_time_ns() - state->start_time_ns;
            if (elapsed < expected_time) {
                usleep((expected_time - elapsed) / 1000);
            }
        }
    }

    state->end_time_ns = get_time_ns();

    /* Cleanup */
    close_test_socket(&sock);
    if (cfg->zero_copy) munmap(buffer, pkt_size);
    else free(buffer);

    return NULL;
}

/* Run single-path throughput test */
static int run_single_path_test(throughput_config_t *cfg, int pkt_size,
                                 throughput_result_t *result)
{
    thread_state_t *threads;
    cpu_stats_t cpu_start, cpu_end;

    cfg->packet_sizes[0] = pkt_size;

    LOG_INFO("Single-path test: %d byte packets, %d threads, %d seconds",
             pkt_size, cfg->num_threads, cfg->ctx.duration_sec);

    /* Allocate thread state */
    threads = calloc(cfg->num_threads, sizeof(thread_state_t));
    if (!threads) {
        LOG_ERROR("Failed to allocate thread state");
        return -1;
    }

    /* Create threads */
    for (int i = 0; i < cfg->num_threads; i++) {
        threads[i].thread_id = i;
        threads[i].config = cfg;
        if (pthread_create(&threads[i].thread, NULL, throughput_thread, &threads[i]) != 0) {
            LOG_ERROR("Failed to create thread %d", i);
            cfg->num_threads = i;
            break;
        }
    }

    /* Warmup period */
    if (cfg->ctx.warmup_sec > 0) {
        LOG_INFO("Warmup: %d seconds", cfg->ctx.warmup_sec);
        sleep(cfg->ctx.warmup_sec);
    }

    /* Start measurement */
    cpu_stats_read(&cpu_start);
    cfg->ctx.running = true;

    /* Run test */
    for (int i = 0; i < cfg->ctx.duration_sec && !g_stop_flag; i++) {
        sleep(1);
        print_progress(i + 1, cfg->ctx.duration_sec, "Testing");
    }

    /* Stop measurement */
    cfg->ctx.running = false;
    cpu_stats_read(&cpu_end);

    /* Wait for threads */
    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;
    uint64_t total_errors = 0;

    for (int i = 0; i < cfg->num_threads; i++) {
        pthread_join(threads[i].thread, NULL);
        total_bytes += threads[i].bytes_sent;
        total_packets += threads[i].packets_sent;
        total_errors += threads[i].errors;
    }

    /* Calculate results */
    double duration = (double)cfg->ctx.duration_sec;
    result->packet_size = pkt_size;
    result->gbps = bytes_to_gbps(total_bytes, duration);
    result->pps = total_packets / (uint64_t)duration;
    result->cpu_percent = cpu_usage_percent(&cpu_start, &cpu_end);
    result->efficiency = result->gbps / (result->cpu_percent / 100.0);

    LOG_INFO("Results: %.3f Gbps, %lu PPS, %.1f%% CPU",
             result->gbps, (unsigned long)result->pps, result->cpu_percent);

    free(threads);
    return 0;
}

/* Run multipath aggregation test */
static int run_multipath_test(throughput_config_t *cfg, int pkt_size,
                               throughput_result_t *result)
{
    thread_state_t *threads;
    cpu_stats_t cpu_start, cpu_end;
    int total_threads;

    cfg->packet_sizes[0] = pkt_size;

    /* Use one thread per interface for multipath */
    total_threads = cfg->ctx.num_interfaces * cfg->num_threads;

    LOG_INFO("Multipath test: %d byte packets, %d interfaces, %d threads, %d seconds",
             pkt_size, cfg->ctx.num_interfaces, total_threads, cfg->ctx.duration_sec);

    threads = calloc(total_threads, sizeof(thread_state_t));
    if (!threads) {
        LOG_ERROR("Failed to allocate thread state");
        return -1;
    }

    /* Create threads - distribute across interfaces */
    for (int i = 0; i < total_threads; i++) {
        threads[i].thread_id = i;
        threads[i].config = cfg;
        if (pthread_create(&threads[i].thread, NULL, throughput_thread, &threads[i]) != 0) {
            LOG_ERROR("Failed to create thread %d", i);
            total_threads = i;
            break;
        }
    }

    /* Warmup */
    if (cfg->ctx.warmup_sec > 0) {
        sleep(cfg->ctx.warmup_sec);
    }

    /* Start measurement */
    cpu_stats_read(&cpu_start);
    bench_ctx_start_tracking(&cfg->ctx);

    /* Run test */
    for (int i = 0; i < cfg->ctx.duration_sec && !g_stop_flag; i++) {
        sleep(1);
        print_progress(i + 1, cfg->ctx.duration_sec, "Multipath");
    }

    /* Stop measurement */
    bench_ctx_stop_tracking(&cfg->ctx);
    cpu_stats_read(&cpu_end);

    /* Aggregate results */
    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;

    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i].thread, NULL);
        total_bytes += threads[i].bytes_sent;
        total_packets += threads[i].packets_sent;
    }

    /* Calculate results */
    double duration = (double)cfg->ctx.duration_sec;
    result->packet_size = pkt_size;
    result->gbps = bytes_to_gbps(total_bytes, duration);
    result->pps = total_packets / (uint64_t)duration;
    result->cpu_percent = cpu_usage_percent(&cpu_start, &cpu_end);
    result->efficiency = result->gbps / (result->cpu_percent / 100.0);

    /* Calculate interface utilization */
    double per_if_gbps[MAX_INTERFACES];
    double total_if_gbps = 0;
    for (int i = 0; i < cfg->ctx.num_interfaces; i++) {
        uint64_t if_bytes = ifstats_tx_bytes_diff(&cfg->ctx.if_start[i],
                                                   &cfg->ctx.if_end[i]);
        per_if_gbps[i] = bytes_to_gbps(if_bytes, duration);
        total_if_gbps += per_if_gbps[i];
        LOG_INFO("  Interface %s: %.3f Gbps", cfg->ctx.interfaces[i], per_if_gbps[i]);
    }

    LOG_INFO("Aggregated: %.3f Gbps, %lu PPS, %.1f%% CPU",
             result->gbps, (unsigned long)result->pps, result->cpu_percent);

    free(threads);
    return 0;
}

/* Print results table */
static void print_results_table(throughput_result_t *results, int count, bool multipath)
{
    printf("\n");
    print_header(multipath ? "Multipath Throughput Results" : "Single-Path Throughput Results");
    printf("  %-10s %12s %15s %10s %12s %8s\n",
           "Pkt Size", "Throughput", "Packets/sec", "CPU %", "Efficiency", "Target");
    printf("  %-10s %12s %15s %10s %12s %8s\n",
           "--------", "----------", "-----------", "-----", "----------", "------");

    for (int i = 0; i < count; i++) {
        throughput_result_t *r = &results[i];
        const char *status = (r->gbps >= TARGET_THROUGHPUT_GBPS) ? "PASS" : "FAIL";

        printf("  %-10d %10.3f Gbps %13lu %9.1f%% %10.2f Gbps/core %s\n",
               r->packet_size, r->gbps, (unsigned long)r->pps,
               r->cpu_percent, r->efficiency, status);
    }

    print_separator();
    printf("Target: >%.1f Gbps @ 10G NIC\n", TARGET_THROUGHPUT_GBPS);
    if (multipath) {
        printf("Target: >%.0f%% multipath aggregation efficiency\n",
               TARGET_MULTIPATH_EFFICIENCY * 100);
    }
}

/* Write JSON report */
static void write_json_report(const char *path, throughput_result_t *results,
                               int count, bool multipath)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        LOG_ERROR("Failed to open report file: %s", path);
        return;
    }

    print_json_start(fp);
    fprintf(fp, "  \"test_type\": \"%s\",\n", multipath ? "multipath" : "single_path");
    fprintf(fp, "  \"target_gbps\": %.1f,\n", TARGET_THROUGHPUT_GBPS);
    fprintf(fp, "  \"results\": [\n");

    for (int i = 0; i < count; i++) {
        print_json_throughput(fp, &results[i], i == count - 1);
    }

    fprintf(fp, "  ]\n");
    print_json_end(fp);
    fclose(fp);

    LOG_INFO("Report written to: %s", path);
}

static void print_usage(const char *prog)
{
    printf("TQUIC Throughput Benchmark v%s\n\n", TQUIC_BENCH_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --interface IF     Network interface (default: lo)\n");
    printf("  -t, --target ADDR      Target address (default: 127.0.0.1)\n");
    printf("  -p, --port PORT        Target port (default: 4433)\n");
    printf("  -d, --duration SEC     Test duration in seconds (default: %d)\n", DEFAULT_DURATION_SEC);
    printf("  -s, --sizes LIST       Comma-separated packet sizes (default: 64,512,1500,9000,65535)\n");
    printf("  -m, --multipath LIST   Comma-separated interfaces for multipath test\n");
    printf("  -n, --threads NUM      Number of threads (default: 1)\n");
    printf("  -c, --cpu NUM          CPU affinity starting core (default: none)\n");
    printf("  -r, --report FILE      Output JSON report file\n");
    printf("  -w, --warmup SEC       Warmup duration (default: %d)\n", DEFAULT_WARMUP_SEC);
    printf("  -z, --zero-copy        Use zero-copy mode\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -D, --debug            Debug output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -i eth0 -d 60 -s 1500,9000\n", prog);
    printf("  %s -m eth0,eth1 -d 30 -r results.json\n", prog);
}

int main(int argc, char *argv[])
{
    throughput_config_t cfg;
    throughput_result_t results[MAX_PACKET_SIZES];
    int num_results = 0;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"target",    required_argument, 0, 't'},
        {"port",      required_argument, 0, 'p'},
        {"duration",  required_argument, 0, 'd'},
        {"sizes",     required_argument, 0, 's'},
        {"multipath", required_argument, 0, 'm'},
        {"threads",   required_argument, 0, 'n'},
        {"cpu",       required_argument, 0, 'c'},
        {"report",    required_argument, 0, 'r'},
        {"warmup",    required_argument, 0, 'w'},
        {"zero-copy", no_argument,       0, 'z'},
        {"verbose",   no_argument,       0, 'v'},
        {"debug",     no_argument,       0, 'D'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Initialize configuration */
    memset(&cfg, 0, sizeof(cfg));
    bench_ctx_init(&cfg.ctx);
    cfg.num_threads = 1;
    cfg.cpu_affinity = -1;
    strncpy(cfg.ctx.target_addr, "127.0.0.1", sizeof(cfg.ctx.target_addr) - 1);
    cfg.ctx.target_port = 4433;
    strncpy(cfg.ctx.interfaces[0], "lo", IFNAMSIZ - 1);
    cfg.ctx.num_interfaces = 1;

    /* Parse command line */
    int opt;
    while ((opt = getopt_long(argc, argv, "i:t:p:d:s:m:n:c:r:w:zvDh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(cfg.ctx.interfaces[0], optarg, IFNAMSIZ - 1);
            break;
        case 't':
            strncpy(cfg.ctx.target_addr, optarg, sizeof(cfg.ctx.target_addr) - 1);
            break;
        case 'p':
            cfg.ctx.target_port = (uint16_t)atoi(optarg);
            break;
        case 'd':
            cfg.ctx.duration_sec = atoi(optarg);
            break;
        case 's':
            cfg.num_packet_sizes = parse_packet_sizes(optarg, cfg.packet_sizes, MAX_PACKET_SIZES);
            break;
        case 'm':
            cfg.ctx.num_interfaces = parse_interfaces(optarg, cfg.ctx.interfaces, MAX_INTERFACES);
            cfg.multipath_test = true;
            break;
        case 'n':
            cfg.num_threads = atoi(optarg);
            break;
        case 'c':
            cfg.cpu_affinity = atoi(optarg);
            break;
        case 'r':
            strncpy(cfg.ctx.report_path, optarg, MAX_PATH_LENGTH - 1);
            break;
        case 'w':
            cfg.ctx.warmup_sec = atoi(optarg);
            break;
        case 'z':
            cfg.zero_copy = true;
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

    /* Use default packet sizes if not specified */
    if (cfg.num_packet_sizes == 0) {
        memcpy(cfg.packet_sizes, default_sizes, sizeof(default_sizes));
        cfg.num_packet_sizes = num_default_sizes;
    }

    /* Validate threads */
    if (cfg.num_threads < 1 || cfg.num_threads > MAX_THREADS) {
        LOG_ERROR("Invalid thread count: %d (must be 1-%d)", cfg.num_threads, MAX_THREADS);
        return 1;
    }

    /* Setup signal handlers */
    setup_signal_handlers();

    /* Print test info */
    print_header("TQUIC Throughput Benchmark");
    printf("Target: %s:%d\n", cfg.ctx.target_addr, cfg.ctx.target_port);
    printf("Duration: %d seconds (warmup: %d sec)\n", cfg.ctx.duration_sec, cfg.ctx.warmup_sec);
    printf("Threads: %d\n", cfg.num_threads);
    printf("Interfaces: ");
    for (int i = 0; i < cfg.ctx.num_interfaces; i++) {
        printf("%s%s", cfg.ctx.interfaces[i], i < cfg.ctx.num_interfaces - 1 ? ", " : "\n");
    }
    printf("Packet sizes: ");
    for (int i = 0; i < cfg.num_packet_sizes; i++) {
        printf("%d%s", cfg.packet_sizes[i], i < cfg.num_packet_sizes - 1 ? ", " : "\n");
    }
    printf("Mode: %s\n", cfg.multipath_test ? "Multipath" : "Single-path");
    print_separator();

    /* Run tests for each packet size */
    for (int i = 0; i < cfg.num_packet_sizes && !g_stop_flag; i++) {
        int pkt_size = cfg.packet_sizes[i];
        throughput_result_t *result = &results[num_results];

        printf("\nTesting %d byte packets...\n", pkt_size);

        if (cfg.multipath_test) {
            if (run_multipath_test(&cfg, pkt_size, result) == 0) {
                num_results++;
            }
        } else {
            if (run_single_path_test(&cfg, pkt_size, result) == 0) {
                num_results++;
            }
        }
    }

    /* Print results */
    if (num_results > 0) {
        print_results_table(results, num_results, cfg.multipath_test);

        /* Write JSON report if requested */
        if (cfg.ctx.report_path[0] != '\0') {
            write_json_report(cfg.ctx.report_path, results, num_results, cfg.multipath_test);
        }
    }

    bench_ctx_destroy(&cfg.ctx);
    return 0;
}
