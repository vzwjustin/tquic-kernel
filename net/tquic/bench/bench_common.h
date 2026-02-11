/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Benchmark Common Utilities
 *
 * Shared definitions and utilities for TQUIC benchmark tools.
 *
 * Copyright (c) 2024-2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_BENCH_COMMON_H
#define _TQUIC_BENCH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>

/* Version */
#define TQUIC_BENCH_VERSION "1.0.0"

/* Target metrics from audit */
#define TARGET_THROUGHPUT_GBPS      9.0     /* >9 Gbps @ 10G NIC */
#define TARGET_MULTIPATH_EFFICIENCY 0.95    /* >95% of sum(BW) */
#define TARGET_FAILOVER_MS          100     /* <100ms failover */
#define TARGET_MEMORY_KB            64      /* <64KB per connection */
#define TARGET_CONNECTION_RTT       1       /* <1 RTT (0-RTT support) */

/* Benchmark defaults */
#define DEFAULT_DURATION_SEC        60
#define DEFAULT_WARMUP_SEC          5
#define DEFAULT_COOLDOWN_SEC        2
#define DEFAULT_SAMPLES             10000
#define DEFAULT_MAX_CONNECTIONS     100000
#define DEFAULT_CONNECTION_RATE     10000

/* Packet sizes for throughput tests */
#define PKTSIZE_MIN                 64
#define PKTSIZE_SMALL               512
#define PKTSIZE_MTU                 1500
#define PKTSIZE_JUMBO               9000
#define PKTSIZE_MAX                 65535

/* Maximum values */
#define MAX_INTERFACES              8
#define MAX_PACKET_SIZES            16
#define MAX_PATH_LENGTH             256
#define MAX_THREADS                 64
#define MAX_HISTOGRAM_BUCKETS       1000

/* Scheduling algorithms */
typedef enum {
    SCHED_ALG_MINRTT = 0,
    SCHED_ALG_ROUNDROBIN,
    SCHED_ALG_WEIGHTED,
    SCHED_ALG_REDUNDANT,
    SCHED_ALG_BLEST,
    SCHED_ALG_ECF,
    SCHED_ALG_MAX
} sched_algorithm_t;

/* Statistics structure */
typedef struct {
    uint64_t count;
    double sum;
    double sum_sq;
    double min;
    double max;
} stats_t;

/* Histogram for latency distribution */
typedef struct {
    uint64_t buckets[MAX_HISTOGRAM_BUCKETS];
    int num_buckets;
    double bucket_size;
    double min_value;
    double max_value;
} histogram_t;

/* CPU usage tracking */
typedef struct {
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
} cpu_stats_t;

/* Network interface statistics */
typedef struct {
    char name[IFNAMSIZ];
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
} ifstats_t;

/* Throughput result */
typedef struct {
    int packet_size;
    double gbps;
    uint64_t pps;
    double cpu_percent;
    double efficiency;  /* Gbps per CPU core */
} throughput_result_t;

/* Latency result */
typedef struct {
    double rtt_avg;
    double rtt_min;
    double rtt_max;
    double jitter;
    double p50;
    double p95;
    double p99;
    double p999;
    uint64_t samples;
    histogram_t histogram;
} latency_result_t;

/* Connection result */
typedef struct {
    double cps;                 /* Connections per second */
    uint64_t total_connections;
    uint64_t successful;
    uint64_t failed;
    double zero_rtt_rate;
    double memory_per_conn_kb;
    double avg_setup_time_us;
} connection_result_t;

/* Failover result */
typedef struct {
    double failover_time_ms;
    uint64_t packets_lost;
    double recovery_time_ms;
    double bandwidth_during_failover;
    int iterations;
} failover_result_t;

/* Scheduler result */
typedef struct {
    sched_algorithm_t algorithm;
    double throughput_gbps;
    double path_utilization[MAX_INTERFACES];
    double scheduling_overhead_us;
    double fairness_index;
} scheduler_result_t;

/* Benchmark context */
typedef struct {
    /* Configuration */
    char interfaces[MAX_INTERFACES][IFNAMSIZ];
    int num_interfaces;
    int duration_sec;
    int warmup_sec;
    int cooldown_sec;
    char target_addr[INET6_ADDRSTRLEN];
    uint16_t target_port;
    char report_path[MAX_PATH_LENGTH];
    bool verbose;
    bool debug;
    bool json_output;

    /* State */
    volatile bool running;
    pthread_mutex_t lock;

    /* CPU tracking */
    cpu_stats_t cpu_start;
    cpu_stats_t cpu_end;

    /* Interface tracking */
    ifstats_t if_start[MAX_INTERFACES];
    ifstats_t if_end[MAX_INTERFACES];
} bench_ctx_t;

/* Time utilities */
static inline uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t get_time_us(void)
{
    return get_time_ns() / 1000;
}

static inline uint64_t get_time_ms(void)
{
    return get_time_ns() / 1000000;
}

static inline void sleep_ms(int ms)
{
    usleep(ms * 1000);
}

static inline void sleep_us(int us)
{
    usleep(us);
}

/* Statistics functions */
void stats_init(stats_t *s);
void stats_add(stats_t *s, double value);
double stats_mean(const stats_t *s);
double stats_stddev(const stats_t *s);
double stats_min(const stats_t *s);
double stats_max(const stats_t *s);

/* Histogram functions */
void histogram_init(histogram_t *h, double min_val, double max_val, int buckets);
void histogram_add(histogram_t *h, double value);
double histogram_percentile(const histogram_t *h, double pct);
void histogram_print(const histogram_t *h, FILE *fp);

/* CPU utilization */
int cpu_stats_read(cpu_stats_t *stats);
double cpu_usage_percent(const cpu_stats_t *start, const cpu_stats_t *end);

/* Network interface stats */
int ifstats_read(const char *ifname, ifstats_t *stats);
uint64_t ifstats_rx_bytes_diff(const ifstats_t *start, const ifstats_t *end);
uint64_t ifstats_tx_bytes_diff(const ifstats_t *start, const ifstats_t *end);

/* Benchmark context */
void bench_ctx_init(bench_ctx_t *ctx);
void bench_ctx_destroy(bench_ctx_t *ctx);
void bench_ctx_start_tracking(bench_ctx_t *ctx);
void bench_ctx_stop_tracking(bench_ctx_t *ctx);

/* Output functions */
void print_json_start(FILE *fp);
void print_json_end(FILE *fp);
void print_json_throughput(FILE *fp, const throughput_result_t *r, bool last);
void print_json_latency(FILE *fp, const latency_result_t *r);
void print_json_connection(FILE *fp, const connection_result_t *r);
void print_json_failover(FILE *fp, const failover_result_t *r);
void print_json_scheduler(FILE *fp, const scheduler_result_t *r, bool last);

/* Logging */
extern int g_verbose;
extern int g_debug;

#define LOG_INFO(fmt, ...) \
    do { if (g_verbose) fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__); } while(0)

#define LOG_DEBUG(fmt, ...) \
    do { if (g_debug) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)

/* Signal handling */
extern volatile sig_atomic_t g_stop_flag;
void setup_signal_handlers(void);

/* Utility functions */
const char *sched_alg_name(sched_algorithm_t alg);
sched_algorithm_t sched_alg_from_name(const char *name);
int parse_interfaces(const char *str, char interfaces[][IFNAMSIZ], int max);
int parse_packet_sizes(const char *str, int *sizes, int max);
void print_progress(int current, int total, const char *label);
void print_separator(void);
void print_header(const char *title);
double bytes_to_gbps(uint64_t bytes, double seconds);
uint64_t gbps_to_bytes(double gbps, double seconds);

/* Memory tracking */
size_t get_process_memory_kb(void);
size_t get_tquic_module_memory_kb(void);

/* Validation */
bool check_tquic_module_loaded(void);
bool check_interface_exists(const char *ifname);
bool check_root_privileges(void);

#endif /* _TQUIC_BENCH_COMMON_H */
