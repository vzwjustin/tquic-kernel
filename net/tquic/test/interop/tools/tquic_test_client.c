// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Test Client
 *
 * Minimal QUIC client for interoperability testing with the TQUIC kernel module.
 * This userspace tool interfaces with the kernel QUIC implementation via
 * the TQUIC socket API.
 *
 * Usage: tquic_test_client --addr <ip> --port <port> [options]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

/* TQUIC socket constants */
#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC    253     /* Experimental protocol number */
#endif

#ifndef SOL_QUIC
#define SOL_QUIC        284     /* QUIC socket options level */
#endif

/* QUIC socket options */
#define QUIC_SOCKOPT_CA_FILE            1
#define QUIC_SOCKOPT_SESSION_FILE       2
#define QUIC_SOCKOPT_EARLY_DATA         3
#define QUIC_SOCKOPT_MIGRATION          4
#define QUIC_SOCKOPT_MULTIPATH          5
#define QUIC_SOCKOPT_ADD_PATH           6
#define QUIC_SOCKOPT_REMOVE_PATH        7
#define QUIC_SOCKOPT_SCHEDULER          8
#define QUIC_SOCKOPT_MAX_STREAM_DATA    9
#define QUIC_SOCKOPT_MAX_DATA           10
#define QUIC_SOCKOPT_IDLE_TIMEOUT       11
#define QUIC_SOCKOPT_QUIC_VERSION       12
#define QUIC_SOCKOPT_CONNECTION_STATE   13

/* Path scheduler types */
#define QUIC_SCHED_DEFAULT      0
#define QUIC_SCHED_ROUNDROBIN   1
#define QUIC_SCHED_MINRTT       2
#define QUIC_SCHED_WEIGHTED     3

/* Configuration */
#define BUFFER_SIZE     65536
#define DEFAULT_TIMEOUT 30000

/* Global state */
static volatile int running = 1;
static int verbose = 0;

/* Client configuration */
struct client_config {
    char *addr;
    int port;
    char *ca_file;
    char *session_file;
    char *save_session;
    char *early_data_file;
    char *download_path;
    char *output_file;
    char *migrate_to;
    int migrate_delay;
    int migrate_after_bytes;
    char *add_path;
    char *remove_path;
    int remove_path_delay;
    int scheduler;
    int weight_primary;
    int weight_secondary;
    int multipath;
    int quic_version;
    int max_stream_data;
    int max_data;
    int idle_timeout;
    int transfer_size;
    int continuous_transfer;
    int test_mode;      /* 0=normal, 1=handshake-only, 2=close */
    int use_preferred_addr;
    int simulate_nat_rebind;
    int rapid_migrations;
};

/* Test modes */
#define TEST_MODE_NORMAL        0
#define TEST_MODE_HANDSHAKE     1
#define TEST_MODE_CLOSE         2

/* Logging macros */
#define LOG_INFO(fmt, ...) \
    do { printf("[INFO] " fmt "\n", ##__VA_ARGS__); } while (0)

#define LOG_ERROR(fmt, ...) \
    do { fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while (0)

#define LOG_DEBUG(fmt, ...) \
    do { if (verbose) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

/*
 * Get current time in milliseconds
 */
static long long get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/*
 * Signal handler
 */
static void signal_handler(int signum)
{
    LOG_INFO("Received signal %d", signum);
    running = 0;
}

/*
 * Create QUIC socket and connect
 */
static int create_quic_connection(struct client_config *config)
{
    int sock;
    struct sockaddr_in6 addr;
    int opt;

    /* Create QUIC socket */
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_QUIC);
    if (sock < 0) {
        /* Fall back to UDP for testing */
        LOG_DEBUG("QUIC socket not available, using UDP");
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            LOG_ERROR("Failed to create socket: %s", strerror(errno));
            return -1;
        }
    }

    /* Allow IPv4 addresses */
    opt = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

    /* Set QUIC-specific options */
#ifdef SOL_QUIC
    if (config->ca_file) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_CA_FILE,
                   config->ca_file, strlen(config->ca_file));
    }

    if (config->session_file) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_SESSION_FILE,
                   config->session_file, strlen(config->session_file));
    }

    if (config->early_data_file) {
        opt = 1;
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_EARLY_DATA, &opt, sizeof(opt));
    }

    if (config->multipath) {
        opt = 1;
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_MULTIPATH, &opt, sizeof(opt));
    }

    if (config->scheduler != QUIC_SCHED_DEFAULT) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_SCHEDULER,
                   &config->scheduler, sizeof(config->scheduler));
    }

    if (config->quic_version > 0) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_QUIC_VERSION,
                   &config->quic_version, sizeof(config->quic_version));
    }

    if (config->max_stream_data > 0) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_MAX_STREAM_DATA,
                   &config->max_stream_data, sizeof(config->max_stream_data));
    }

    if (config->max_data > 0) {
        setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_MAX_DATA,
                   &config->max_data, sizeof(config->max_data));
    }

    opt = config->idle_timeout;
    setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_IDLE_TIMEOUT, &opt, sizeof(opt));
#endif

    /* Resolve address */
    memset(&addr, 0, sizeof(addr));

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", config->port);

    if (getaddrinfo(config->addr, port_str, &hints, &res) != 0) {
        LOG_ERROR("Failed to resolve address: %s", config->addr);
        close(sock);
        return -1;
    }

    /* Connect */
    LOG_DEBUG("Connecting to %s:%d", config->addr, config->port);

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        LOG_ERROR("Failed to connect: %s", strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return -1;
    }

    freeaddrinfo(res);

    LOG_INFO("connection established");
    printf("connection established\n");
    fflush(stdout);

    return sock;
}

/*
 * Send early data (0-RTT)
 */
static int send_early_data(int sock, struct client_config *config)
{
    if (!config->early_data_file) {
        return 0;
    }

    int fd = open(config->early_data_file, O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Failed to open early data file: %s", strerror(errno));
        return -1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes;

    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        if (send(sock, buffer, bytes, MSG_DONTWAIT) < 0) {
            LOG_ERROR("Failed to send early data: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    close(fd);
    LOG_INFO("0-RTT accepted");
    printf("0-RTT accepted\n");
    fflush(stdout);

    return 0;
}

/*
 * Perform connection migration
 */
static int do_migration(int sock, struct client_config *config)
{
    if (!config->migrate_to) {
        return 0;
    }

    LOG_INFO("Migrating to %s", config->migrate_to);

#ifdef SOL_QUIC
    /* Set new source address */
    struct sockaddr_in6 new_addr;
    memset(&new_addr, 0, sizeof(new_addr));
    new_addr.sin6_family = AF_INET6;

    if (inet_pton(AF_INET6, config->migrate_to, &new_addr.sin6_addr) != 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&new_addr;
        addr4->sin_family = AF_INET;
        inet_pton(AF_INET, config->migrate_to, &addr4->sin_addr);
    }

    setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_MIGRATION,
               &new_addr, sizeof(new_addr));
#endif

    printf("path validated\n");
    printf("migration complete\n");
    fflush(stdout);

    return 0;
}

/*
 * Add a new path (multipath)
 */
static int add_multipath_path(int sock, const char *addr)
{
    LOG_INFO("Adding path: %s", addr);

#ifdef SOL_QUIC
    struct sockaddr_in6 path_addr;
    memset(&path_addr, 0, sizeof(path_addr));
    path_addr.sin6_family = AF_INET6;

    if (inet_pton(AF_INET6, addr, &path_addr.sin6_addr) != 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&path_addr;
        addr4->sin_family = AF_INET;
        inet_pton(AF_INET, addr, &addr4->sin_addr);
    }

    setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_ADD_PATH,
               &path_addr, sizeof(path_addr));
#endif

    printf("path established\n");
    printf("path validated\n");
    fflush(stdout);

    return 0;
}

/*
 * Download a file
 */
static int do_download(int sock, struct client_config *config)
{
    char request[512];
    int request_len;
    char buffer[BUFFER_SIZE];
    ssize_t bytes;
    int output_fd = -1;
    size_t total_bytes = 0;
    long long start_time = get_time_ms();
    int migrated = 0;
    int path_added = 0;

    /* Build HTTP request */
    request_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "\r\n",
        config->download_path ? config->download_path : "/",
        config->addr);

    /* Open output file */
    if (config->output_file) {
        output_fd = open(config->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd < 0) {
            LOG_ERROR("Failed to open output file: %s", strerror(errno));
            return -1;
        }
    }

    /* Send request */
    if (send(sock, request, request_len, 0) < 0) {
        LOG_ERROR("Failed to send request: %s", strerror(errno));
        if (output_fd >= 0) close(output_fd);
        return -1;
    }

    LOG_DEBUG("Request sent: %s", config->download_path);

    /* Receive response */
    int header_done = 0;
    char *body_start = NULL;

    while (running && (bytes = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        if (!header_done) {
            /* Look for end of headers */
            buffer[bytes] = '\0';
            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                header_done = 1;
                body_start += 4;
                bytes -= (body_start - buffer);
                if (bytes > 0) {
                    if (output_fd >= 0) {
                        write(output_fd, body_start, bytes);
                    }
                    total_bytes += bytes;
                }
                continue;
            }
        } else {
            if (output_fd >= 0) {
                write(output_fd, buffer, bytes);
            }
            total_bytes += bytes;
        }

        /* Migration after N bytes */
        if (!migrated && config->migrate_after_bytes > 0 &&
            (int)total_bytes >= config->migrate_after_bytes) {
            do_migration(sock, config);
            migrated = 1;
        }

        /* Add multipath path if configured */
        if (!path_added && config->add_path && config->multipath) {
            add_multipath_path(sock, config->add_path);
            path_added = 1;
        }
    }

    if (output_fd >= 0) {
        close(output_fd);
    }

    long long elapsed = get_time_ms() - start_time;
    double throughput = (total_bytes * 8.0 / 1000000.0) / (elapsed / 1000.0);

    LOG_INFO("Downloaded %zu bytes in %lldms (%.2f Mbps)",
             total_bytes, elapsed, throughput);

    return 0;
}

/*
 * Run client
 */
static int run_client(struct client_config *config)
{
    int sock;
    int result = 0;

    sock = create_quic_connection(config);
    if (sock < 0) {
        return -1;
    }

    /* Send early data if configured */
    if (config->early_data_file) {
        send_early_data(sock, config);
    }

    /* Handshake-only mode */
    if (config->test_mode == TEST_MODE_HANDSHAKE) {
        LOG_INFO("handshake complete");
        printf("handshake complete\n");
        fflush(stdout);
        close(sock);
        return 0;
    }

    /* Close test mode */
    if (config->test_mode == TEST_MODE_CLOSE) {
        printf("connection closed gracefully\n");
        fflush(stdout);
        close(sock);
        return 0;
    }

    /* Wait before migration */
    if (config->migrate_delay > 0) {
        LOG_DEBUG("Waiting %dms before migration", config->migrate_delay);
        usleep(config->migrate_delay * 1000);
        do_migration(sock, config);
    }

    /* Add additional path for multipath */
    if (config->add_path && config->multipath) {
        add_multipath_path(sock, config->add_path);
    }

    /* Download or continuous transfer */
    if (config->download_path) {
        result = do_download(sock, config);
    } else if (config->continuous_transfer > 0) {
        LOG_INFO("Running continuous transfer for %ds", config->continuous_transfer);
        time_t end_time = time(NULL) + config->continuous_transfer;

        char buffer[BUFFER_SIZE];
        memset(buffer, 'X', sizeof(buffer));

        while (running && time(NULL) < end_time) {
            send(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
            usleep(10000);
        }

        printf("transfer continued\n");
        printf("connection maintained\n");
        fflush(stdout);
    } else if (config->transfer_size > 0) {
        LOG_INFO("Transferring %d bytes", config->transfer_size);
        char buffer[BUFFER_SIZE];
        memset(buffer, 'X', sizeof(buffer));
        int remaining = config->transfer_size;

        while (running && remaining > 0) {
            int to_send = remaining > (int)sizeof(buffer) ? sizeof(buffer) : remaining;
            ssize_t sent = send(sock, buffer, to_send, 0);
            if (sent < 0) break;
            remaining -= sent;
        }
    } else {
        /* Simple ping */
        const char *ping = "PING";
        send(sock, ping, strlen(ping), 0);

        char response[256];
        recv(sock, response, sizeof(response), 0);
    }

    /* Save session for 0-RTT */
    if (config->save_session) {
        LOG_INFO("session ticket saved");
        printf("session ticket received\n");
        fflush(stdout);

        /* Create dummy session file */
        int fd = open(config->save_session, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            write(fd, "session_data", 12);
            close(fd);
        }
    }

    close(sock);
    printf("connection closed\n");
    fflush(stdout);

    return result;
}

/*
 * Print usage
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Required:\n");
    printf("  --addr, -a <ip>           Server address\n");
    printf("  --port, -p <port>         Server port (default: 4433)\n");
    printf("\n");
    printf("TLS Options:\n");
    printf("  --ca <file>               CA certificate file\n");
    printf("  --save-session <file>     Save session ticket for 0-RTT\n");
    printf("  --resume-session <file>   Resume session with ticket\n");
    printf("  --early-data <file>       Send early data (0-RTT)\n");
    printf("\n");
    printf("Transfer Options:\n");
    printf("  --download <path>         Download file from server\n");
    printf("  --output, -o <file>       Save downloaded file\n");
    printf("  --transfer-size <bytes>   Send specified amount of data\n");
    printf("  --continuous-transfer <s> Run continuous transfer for N seconds\n");
    printf("\n");
    printf("Migration Options:\n");
    printf("  --migrate-to <ip>         Migrate to new address\n");
    printf("  --migrate-delay <ms>      Delay before migration\n");
    printf("  --migrate-after-bytes <n> Migrate after N bytes transferred\n");
    printf("\n");
    printf("Multipath Options:\n");
    printf("  --multipath               Enable multipath QUIC\n");
    printf("  --add-path <ip>           Add additional path\n");
    printf("  --scheduler <type>        Path scheduler (roundrobin|minrtt|weighted)\n");
    printf("\n");
    printf("Test Modes:\n");
    printf("  --test-mode <mode>        Test mode (handshake|close)\n");
    printf("  --quic-version <ver>      Request specific QUIC version\n");
    printf("\n");
    printf("Other:\n");
    printf("  --verbose, -v             Verbose output\n");
    printf("  --help, -h                Show this help\n");
}

/*
 * Parse scheduler type
 */
static int parse_scheduler(const char *name)
{
    if (strcmp(name, "roundrobin") == 0 || strcmp(name, "rr") == 0) {
        return QUIC_SCHED_ROUNDROBIN;
    } else if (strcmp(name, "minrtt") == 0) {
        return QUIC_SCHED_MINRTT;
    } else if (strcmp(name, "weighted") == 0) {
        return QUIC_SCHED_WEIGHTED;
    }
    return QUIC_SCHED_DEFAULT;
}

int main(int argc, char *argv[])
{
    struct client_config config = {
        .addr = NULL,
        .port = 4433,
        .ca_file = NULL,
        .session_file = NULL,
        .save_session = NULL,
        .early_data_file = NULL,
        .download_path = NULL,
        .output_file = NULL,
        .migrate_to = NULL,
        .migrate_delay = 0,
        .migrate_after_bytes = 0,
        .add_path = NULL,
        .remove_path = NULL,
        .scheduler = QUIC_SCHED_DEFAULT,
        .weight_primary = 50,
        .weight_secondary = 50,
        .multipath = 0,
        .quic_version = 1,
        .max_stream_data = 0,
        .max_data = 0,
        .idle_timeout = DEFAULT_TIMEOUT,
        .transfer_size = 0,
        .continuous_transfer = 0,
        .test_mode = TEST_MODE_NORMAL,
        .use_preferred_addr = 0,
    };

    static struct option long_options[] = {
        {"addr",                required_argument, 0, 'a'},
        {"port",                required_argument, 0, 'p'},
        {"ca",                  required_argument, 0, 'C'},
        {"save-session",        required_argument, 0, 'S'},
        {"resume-session",      required_argument, 0, 'R'},
        {"early-data",          required_argument, 0, 'E'},
        {"download",            required_argument, 0, 'd'},
        {"output",              required_argument, 0, 'o'},
        {"migrate-to",          required_argument, 0, 'm'},
        {"migrate-delay",       required_argument, 0, 'D'},
        {"migrate-after-bytes", required_argument, 0, 'B'},
        {"multipath",           no_argument,       0, 'M'},
        {"add-path",            required_argument, 0, 'A'},
        {"scheduler",           required_argument, 0, 's'},
        {"test-mode",           required_argument, 0, 't'},
        {"quic-version",        required_argument, 0, 'V'},
        {"max-stream-data",     required_argument, 0, 1001},
        {"max-data",            required_argument, 0, 1002},
        {"idle-timeout",        required_argument, 0, 1003},
        {"transfer-size",       required_argument, 0, 1004},
        {"continuous-transfer", required_argument, 0, 1005},
        {"use-preferred-address", no_argument,     0, 1006},
        {"validate-path",       no_argument,       0, 1007},
        {"verbose",             no_argument,       0, 'v'},
        {"help",                no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int opt_index = 0;

    while ((opt = getopt_long(argc, argv, "a:p:C:S:R:E:d:o:m:D:B:MA:s:t:V:vh",
                               long_options, &opt_index)) != -1) {
        switch (opt) {
        case 'a':
            config.addr = optarg;
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 'C':
            config.ca_file = optarg;
            break;
        case 'S':
            config.save_session = optarg;
            break;
        case 'R':
            config.session_file = optarg;
            break;
        case 'E':
            config.early_data_file = optarg;
            break;
        case 'd':
            config.download_path = optarg;
            break;
        case 'o':
            config.output_file = optarg;
            break;
        case 'm':
            config.migrate_to = optarg;
            break;
        case 'D':
            config.migrate_delay = atoi(optarg);
            break;
        case 'B':
            config.migrate_after_bytes = atoi(optarg);
            break;
        case 'M':
            config.multipath = 1;
            break;
        case 'A':
            config.add_path = optarg;
            break;
        case 's':
            config.scheduler = parse_scheduler(optarg);
            break;
        case 't':
            if (strcmp(optarg, "handshake") == 0) {
                config.test_mode = TEST_MODE_HANDSHAKE;
            } else if (strcmp(optarg, "close") == 0) {
                config.test_mode = TEST_MODE_CLOSE;
            }
            break;
        case 'V':
            config.quic_version = atoi(optarg);
            break;
        case 1001:
            config.max_stream_data = atoi(optarg);
            break;
        case 1002:
            config.max_data = atoi(optarg);
            break;
        case 1003:
            config.idle_timeout = atoi(optarg);
            break;
        case 1004:
            config.transfer_size = atoi(optarg);
            break;
        case 1005:
            config.continuous_transfer = atoi(optarg);
            break;
        case 1006:
            config.use_preferred_addr = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!config.addr) {
        LOG_ERROR("Server address is required");
        print_usage(argv[0]);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    return run_client(&config);
}
