// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Benchmark Common Utilities
 *
 * Implementation of shared utilities for TQUIC benchmark tools.
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include "bench_common.h"
#include <math.h>
#include <ctype.h>

/* Global variables */
int g_verbose = 0;
int g_debug = 0;
volatile sig_atomic_t g_stop_flag = 0;

/* Signal handler */
static void signal_handler(int sig)
{
    (void)sig;
    g_stop_flag = 1;
}

void setup_signal_handlers(void)
{
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* Statistics functions */
void stats_init(stats_t *s)
{
    memset(s, 0, sizeof(*s));
    s->min = INFINITY;
    s->max = -INFINITY;
}

void stats_add(stats_t *s, double value)
{
    s->count++;
    s->sum += value;
    s->sum_sq += value * value;
    if (value < s->min) s->min = value;
    if (value > s->max) s->max = value;
}

double stats_mean(const stats_t *s)
{
    if (s->count == 0) return 0.0;
    return s->sum / s->count;
}

double stats_stddev(const stats_t *s)
{
    if (s->count < 2) return 0.0;
    double mean = stats_mean(s);
    double variance = (s->sum_sq - s->count * mean * mean) / (s->count - 1);
    return sqrt(fmax(0.0, variance));
}

double stats_min(const stats_t *s)
{
    return (s->count > 0) ? s->min : 0.0;
}

double stats_max(const stats_t *s)
{
    return (s->count > 0) ? s->max : 0.0;
}

/* Histogram functions */
void histogram_init(histogram_t *h, double min_val, double max_val, int buckets)
{
    memset(h, 0, sizeof(*h));
    h->min_value = min_val;
    h->max_value = max_val;
    h->num_buckets = (buckets > MAX_HISTOGRAM_BUCKETS) ? MAX_HISTOGRAM_BUCKETS : buckets;
    h->bucket_size = (max_val - min_val) / h->num_buckets;
}

void histogram_add(histogram_t *h, double value)
{
    if (value < h->min_value) value = h->min_value;
    if (value > h->max_value) value = h->max_value;

    int bucket = (int)((value - h->min_value) / h->bucket_size);
    if (bucket >= h->num_buckets) bucket = h->num_buckets - 1;
    if (bucket < 0) bucket = 0;

    h->buckets[bucket]++;
}

double histogram_percentile(const histogram_t *h, double pct)
{
    uint64_t total = 0;
    for (int i = 0; i < h->num_buckets; i++) {
        total += h->buckets[i];
    }

    if (total == 0) return 0.0;

    uint64_t target = (uint64_t)(total * pct / 100.0);
    uint64_t count = 0;

    for (int i = 0; i < h->num_buckets; i++) {
        count += h->buckets[i];
        if (count >= target) {
            return h->min_value + (i + 0.5) * h->bucket_size;
        }
    }

    return h->max_value;
}

void histogram_print(const histogram_t *h, FILE *fp)
{
    uint64_t max_count = 0;
    for (int i = 0; i < h->num_buckets; i++) {
        if (h->buckets[i] > max_count) max_count = h->buckets[i];
    }

    if (max_count == 0) {
        fprintf(fp, "Histogram: (empty)\n");
        return;
    }

    fprintf(fp, "Histogram:\n");
    for (int i = 0; i < h->num_buckets; i++) {
        if (h->buckets[i] == 0) continue;

        double range_start = h->min_value + i * h->bucket_size;
        double range_end = range_start + h->bucket_size;
        int bar_width = (int)(50.0 * h->buckets[i] / max_count);

        fprintf(fp, "  %8.2f - %8.2f: ", range_start, range_end);
        for (int j = 0; j < bar_width; j++) fprintf(fp, "#");
        fprintf(fp, " (%lu)\n", (unsigned long)h->buckets[i]);
    }
}

/* CPU utilization */
int cpu_stats_read(cpu_stats_t *stats)
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return -1;

    char line[256];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Parse: cpu user nice system idle iowait irq softirq */
    if (sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu",
               &stats->user, &stats->nice, &stats->system, &stats->idle,
               &stats->iowait, &stats->irq, &stats->softirq) != 7) {
        return -1;
    }

    return 0;
}

double cpu_usage_percent(const cpu_stats_t *start, const cpu_stats_t *end)
{
    uint64_t start_total = start->user + start->nice + start->system +
                           start->idle + start->iowait + start->irq + start->softirq;
    uint64_t end_total = end->user + end->nice + end->system +
                         end->idle + end->iowait + end->irq + end->softirq;

    uint64_t start_idle = start->idle + start->iowait;
    uint64_t end_idle = end->idle + end->iowait;

    uint64_t total_diff = end_total - start_total;
    uint64_t idle_diff = end_idle - start_idle;

    if (total_diff == 0) return 0.0;

    return 100.0 * (1.0 - (double)idle_diff / total_diff);
}

/* Network interface stats */
int ifstats_read(const char *ifname, ifstats_t *stats)
{
    char path[256];
    FILE *fp;

    strncpy(stats->name, ifname, IFNAMSIZ - 1);
    stats->name[IFNAMSIZ - 1] = '\0';

    /* Read RX bytes */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", ifname);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lu", &stats->rx_bytes) != 1) { fclose(fp); return -1; }
    fclose(fp);

    /* Read RX packets */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", ifname);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lu", &stats->rx_packets) != 1) { fclose(fp); return -1; }
    fclose(fp);

    /* Read TX bytes */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lu", &stats->tx_bytes) != 1) { fclose(fp); return -1; }
    fclose(fp);

    /* Read TX packets */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", ifname);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lu", &stats->tx_packets) != 1) { fclose(fp); return -1; }
    fclose(fp);

    /* Read errors */
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_errors", ifname);
    fp = fopen(path, "r");
    if (fp) {
        if (fscanf(fp, "%lu", &stats->rx_errors) != 1) stats->rx_errors = 0;
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_errors", ifname);
    fp = fopen(path, "r");
    if (fp) {
        if (fscanf(fp, "%lu", &stats->tx_errors) != 1) stats->tx_errors = 0;
        fclose(fp);
    }

    return 0;
}

uint64_t ifstats_rx_bytes_diff(const ifstats_t *start, const ifstats_t *end)
{
    return end->rx_bytes - start->rx_bytes;
}

uint64_t ifstats_tx_bytes_diff(const ifstats_t *start, const ifstats_t *end)
{
    return end->tx_bytes - start->tx_bytes;
}

/* Benchmark context */
void bench_ctx_init(bench_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->duration_sec = DEFAULT_DURATION_SEC;
    ctx->warmup_sec = DEFAULT_WARMUP_SEC;
    ctx->cooldown_sec = DEFAULT_COOLDOWN_SEC;
    ctx->target_port = 443;
    ctx->running = false;
    pthread_mutex_init(&ctx->lock, NULL);
}

void bench_ctx_destroy(bench_ctx_t *ctx)
{
    pthread_mutex_destroy(&ctx->lock);
}

void bench_ctx_start_tracking(bench_ctx_t *ctx)
{
    cpu_stats_read(&ctx->cpu_start);
    for (int i = 0; i < ctx->num_interfaces; i++) {
        ifstats_read(ctx->interfaces[i], &ctx->if_start[i]);
    }
    ctx->running = true;
}

void bench_ctx_stop_tracking(bench_ctx_t *ctx)
{
    ctx->running = false;
    cpu_stats_read(&ctx->cpu_end);
    for (int i = 0; i < ctx->num_interfaces; i++) {
        ifstats_read(ctx->interfaces[i], &ctx->if_end[i]);
    }
}

/* JSON output functions */
void print_json_start(FILE *fp)
{
    fprintf(fp, "{\n");
    fprintf(fp, "  \"benchmark\": \"tquic\",\n");
    fprintf(fp, "  \"version\": \"%s\",\n", TQUIC_BENCH_VERSION);

    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    fprintf(fp, "  \"timestamp\": \"%s\",\n", timebuf);
}

void print_json_end(FILE *fp)
{
    fprintf(fp, "}\n");
}

void print_json_throughput(FILE *fp, const throughput_result_t *r, bool last)
{
    fprintf(fp, "    {\n");
    fprintf(fp, "      \"packet_size\": %d,\n", r->packet_size);
    fprintf(fp, "      \"gbps\": %.3f,\n", r->gbps);
    fprintf(fp, "      \"pps\": %lu,\n", (unsigned long)r->pps);
    fprintf(fp, "      \"cpu_percent\": %.2f,\n", r->cpu_percent);
    fprintf(fp, "      \"efficiency\": %.3f\n", r->efficiency);
    fprintf(fp, "    }%s\n", last ? "" : ",");
}

void print_json_latency(FILE *fp, const latency_result_t *r)
{
    fprintf(fp, "  \"latency\": {\n");
    fprintf(fp, "    \"rtt_avg_us\": %.2f,\n", r->rtt_avg);
    fprintf(fp, "    \"rtt_min_us\": %.2f,\n", r->rtt_min);
    fprintf(fp, "    \"rtt_max_us\": %.2f,\n", r->rtt_max);
    fprintf(fp, "    \"jitter_us\": %.2f,\n", r->jitter);
    fprintf(fp, "    \"p50_us\": %.2f,\n", r->p50);
    fprintf(fp, "    \"p95_us\": %.2f,\n", r->p95);
    fprintf(fp, "    \"p99_us\": %.2f,\n", r->p99);
    fprintf(fp, "    \"p999_us\": %.2f,\n", r->p999);
    fprintf(fp, "    \"samples\": %lu\n", (unsigned long)r->samples);
    fprintf(fp, "  }\n");
}

void print_json_connection(FILE *fp, const connection_result_t *r)
{
    fprintf(fp, "  \"connections\": {\n");
    fprintf(fp, "    \"cps\": %.2f,\n", r->cps);
    fprintf(fp, "    \"total\": %lu,\n", (unsigned long)r->total_connections);
    fprintf(fp, "    \"successful\": %lu,\n", (unsigned long)r->successful);
    fprintf(fp, "    \"failed\": %lu,\n", (unsigned long)r->failed);
    fprintf(fp, "    \"zero_rtt_rate\": %.4f,\n", r->zero_rtt_rate);
    fprintf(fp, "    \"memory_per_conn_kb\": %.2f,\n", r->memory_per_conn_kb);
    fprintf(fp, "    \"avg_setup_time_us\": %.2f\n", r->avg_setup_time_us);
    fprintf(fp, "  }\n");
}

void print_json_failover(FILE *fp, const failover_result_t *r)
{
    fprintf(fp, "  \"failover\": {\n");
    fprintf(fp, "    \"failover_time_ms\": %.2f,\n", r->failover_time_ms);
    fprintf(fp, "    \"packets_lost\": %lu,\n", (unsigned long)r->packets_lost);
    fprintf(fp, "    \"recovery_time_ms\": %.2f,\n", r->recovery_time_ms);
    fprintf(fp, "    \"bandwidth_during_failover\": %.3f,\n", r->bandwidth_during_failover);
    fprintf(fp, "    \"iterations\": %d\n", r->iterations);
    fprintf(fp, "  }\n");
}

void print_json_scheduler(FILE *fp, const scheduler_result_t *r, bool last)
{
    fprintf(fp, "    {\n");
    fprintf(fp, "      \"algorithm\": \"%s\",\n", sched_alg_name(r->algorithm));
    fprintf(fp, "      \"throughput_gbps\": %.3f,\n", r->throughput_gbps);
    fprintf(fp, "      \"scheduling_overhead_us\": %.3f,\n", r->scheduling_overhead_us);
    fprintf(fp, "      \"fairness_index\": %.4f\n", r->fairness_index);
    fprintf(fp, "    }%s\n", last ? "" : ",");
}

/* Scheduler algorithm names */
static const char *sched_alg_names[] = {
    [SCHED_ALG_MINRTT]      = "minrtt",
    [SCHED_ALG_ROUNDROBIN]  = "roundrobin",
    [SCHED_ALG_WEIGHTED]    = "weighted",
    [SCHED_ALG_REDUNDANT]   = "redundant",
    [SCHED_ALG_BLEST]       = "blest",
    [SCHED_ALG_ECF]         = "ecf",
};

const char *sched_alg_name(sched_algorithm_t alg)
{
    if (alg >= SCHED_ALG_MAX) return "unknown";
    return sched_alg_names[alg];
}

sched_algorithm_t sched_alg_from_name(const char *name)
{
    for (int i = 0; i < SCHED_ALG_MAX; i++) {
        if (strcasecmp(name, sched_alg_names[i]) == 0) {
            return (sched_algorithm_t)i;
        }
    }
    return SCHED_ALG_MINRTT; /* default */
}

/* Utility functions */
int parse_interfaces(const char *str, char interfaces[][IFNAMSIZ], int max)
{
    int count = 0;
    char *copy = strdup(str);
    if (!copy) return -1;

    char *token = strtok(copy, ",");
    while (token && count < max) {
        while (isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';

        strncpy(interfaces[count], token, IFNAMSIZ - 1);
        interfaces[count][IFNAMSIZ - 1] = '\0';
        count++;
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

int parse_packet_sizes(const char *str, int *sizes, int max)
{
    int count = 0;
    char *copy = strdup(str);
    if (!copy) return -1;

    char *token = strtok(copy, ",");
    while (token && count < max) {
        sizes[count++] = atoi(token);
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

void print_progress(int current, int total, const char *label)
{
    int percent = (current * 100) / total;
    int bar_width = 40;
    int filled = (current * bar_width) / total;

    fprintf(stderr, "\r%s [", label);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) fprintf(stderr, "=");
        else if (i == filled) fprintf(stderr, ">");
        else fprintf(stderr, " ");
    }
    fprintf(stderr, "] %3d%%", percent);
    fflush(stderr);

    if (current == total) fprintf(stderr, "\n");
}

void print_separator(void)
{
    printf("================================================================\n");
}

void print_header(const char *title)
{
    print_separator();
    printf(" %s\n", title);
    print_separator();
}

double bytes_to_gbps(uint64_t bytes, double seconds)
{
    if (seconds <= 0) return 0.0;
    return (bytes * 8.0) / (seconds * 1000000000.0);
}

uint64_t gbps_to_bytes(double gbps, double seconds)
{
    return (uint64_t)(gbps * seconds * 1000000000.0 / 8.0);
}

/* Memory tracking */
size_t get_process_memory_kb(void)
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;

    size_t mem_kb = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%zu", &mem_kb);
            break;
        }
    }
    fclose(fp);
    return mem_kb;
}

size_t get_tquic_module_memory_kb(void)
{
    /* Read from /sys/module/tquic/... or estimate from /proc/slabinfo */
    FILE *fp = fopen("/proc/slabinfo", "r");
    if (!fp) return 0;

    size_t total_kb = 0;
    char line[512];

    /* Skip header lines */
    if (fgets(line, sizeof(line), fp) == NULL) { fclose(fp); return 0; }
    if (fgets(line, sizeof(line), fp) == NULL) { fclose(fp); return 0; }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "tquic") != NULL) {
            /* Format: name <active_objs> <num_objs> <objsize> ... */
            char name[64];
            unsigned long active_objs, num_objs, objsize;
            if (sscanf(line, "%63s %lu %lu %lu", name, &active_objs, &num_objs, &objsize) >= 4) {
                total_kb += (active_objs * objsize) / 1024;
            }
        }
    }
    fclose(fp);
    return total_kb;
}

/* Validation */
bool check_tquic_module_loaded(void)
{
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) return false;

    bool found = false;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "tquic ", 6) == 0) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

bool check_interface_exists(const char *ifname)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
    return access(path, F_OK) == 0;
}

bool check_root_privileges(void)
{
    return geteuid() == 0;
}
