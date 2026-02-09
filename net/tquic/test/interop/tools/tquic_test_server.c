// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Test Server
 *
 * Minimal QUIC server for interoperability testing with the TQUIC kernel module.
 * This userspace tool interfaces with the kernel QUIC implementation via
 * the TQUIC socket API.
 *
 * Usage: tquic_test_server --addr <ip> --port <port> --cert <cert> --key <key>
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
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

/* TQUIC socket constants - must match include/uapi/linux/tquic.h */
#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC    253     /* IPPROTO_TQUIC in kernel */
#endif

#ifndef SOL_TQUIC
#define SOL_TQUIC       288     /* TQUIC socket options level */
#endif
#define SOL_QUIC        SOL_TQUIC

/* TQUIC socket options (from include/uapi/linux/tquic.h) */
#define TQUIC_IDLE_TIMEOUT       11  /* Idle timeout in ms */
#define TQUIC_MAX_STREAMS_BIDI   14  /* Max bidirectional streams */
#define TQUIC_MIGRATION          17  /* Enable connection migration */
#define TQUIC_MULTIPATH          18  /* Enable multipath */
#define TQUIC_CERT_VERIFY_MODE   30  /* Certificate verification mode */
#define TQUIC_ALLOW_SELF_SIGNED  32  /* Allow self-signed certs */

#define TQUIC_VERIFY_NONE        0
#define TQUIC_VERIFY_OPTIONAL    1
#define TQUIC_VERIFY_REQUIRED    2

/* Legacy aliases */
#define QUIC_SOCKOPT_CERT_FILE          1
#define QUIC_SOCKOPT_KEY_FILE           2
#define QUIC_SOCKOPT_ALPN               3
#define QUIC_SOCKOPT_SESSION_TICKET     4
#define QUIC_SOCKOPT_EARLY_DATA         5
#define QUIC_SOCKOPT_MIGRATION          TQUIC_MIGRATION
#define QUIC_SOCKOPT_MULTIPATH          TQUIC_MULTIPATH
#define QUIC_SOCKOPT_MAX_STREAMS        TQUIC_MAX_STREAMS_BIDI
#define QUIC_SOCKOPT_IDLE_TIMEOUT       TQUIC_IDLE_TIMEOUT
#define QUIC_SOCKOPT_CONNECTION_ID      10

/* Configuration */
#define MAX_CONNECTIONS     1024
#define BUFFER_SIZE         65536
#define MAX_EVENTS          64
#define DEFAULT_IDLE_TIMEOUT 30000

/* Global state */
static volatile int running = 1;
static int verbose = 0;

/* Connection state */
struct quic_connection {
    int fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    int active;
    time_t last_activity;
    char connection_id[20];
    int connection_id_len;
};

/* Server configuration */
struct server_config {
    char *addr;
    int port;
    char *cert_file;
    char *key_file;
    char *serve_dir;
    int enable_0rtt;
    int enable_migration;
    int enable_multipath;
    int max_streams;
    int idle_timeout;
};

/* Logging macros */
#define LOG_INFO(fmt, ...) \
    do { printf("[INFO] " fmt "\n", ##__VA_ARGS__); } while (0)

#define LOG_ERROR(fmt, ...) \
    do { fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while (0)

#define LOG_DEBUG(fmt, ...) \
    do { if (verbose) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

/*
 * Signal handler for graceful shutdown
 */
static void signal_handler(int signum)
{
    LOG_INFO("Received signal %d, shutting down...", signum);
    running = 0;
}

/*
 * Create and configure QUIC listener socket
 */
static int create_quic_socket(struct server_config *config)
{
    int sock;
    struct sockaddr_in6 addr;
    int opt = 1;

    /* Create QUIC socket */
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_QUIC);
    if (sock < 0) {
        /* Fall back to UDP socket for testing without kernel module */
        LOG_DEBUG("QUIC socket not available, falling back to UDP");
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            LOG_ERROR("Failed to create socket: %s", strerror(errno));
            return -1;
        }
    }

    /* Set socket options */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Enable IPv4-mapped addresses */
    opt = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

    /* Set TQUIC-specific options */
    /* For testing: disable certificate verification */
    opt = TQUIC_VERIFY_NONE;
    setsockopt(sock, SOL_TQUIC, TQUIC_CERT_VERIFY_MODE, &opt, sizeof(opt));

    opt = 1;
    setsockopt(sock, SOL_TQUIC, TQUIC_ALLOW_SELF_SIGNED, &opt, sizeof(opt));

    if (config->enable_migration) {
        opt = 1;
        setsockopt(sock, SOL_TQUIC, TQUIC_MIGRATION, &opt, sizeof(opt));
    }

    if (config->enable_multipath) {
        opt = 1;
        setsockopt(sock, SOL_TQUIC, TQUIC_MULTIPATH, &opt, sizeof(opt));
    }

    opt = config->idle_timeout;
    setsockopt(sock, SOL_TQUIC, TQUIC_IDLE_TIMEOUT, &opt, sizeof(opt));

    /* Bind to address */
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(config->port);

    if (config->addr && strcmp(config->addr, "::") != 0) {
        if (inet_pton(AF_INET6, config->addr, &addr.sin6_addr) != 1) {
            /* Try IPv4 */
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(config->port);
            if (inet_pton(AF_INET, config->addr, &addr4->sin_addr) != 1) {
                LOG_ERROR("Invalid address: %s", config->addr);
                close(sock);
                return -1;
            }
        }
    } else {
        addr.sin6_addr = in6addr_any;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Listen for connections */
    if (listen(sock, SOMAXCONN) < 0) {
        /* UDP sockets don't need listen, ignore error */
        LOG_DEBUG("listen() not applicable for this socket type");
    }

    LOG_INFO("Server listening on %s:%d", config->addr ? config->addr : "::", config->port);

    return sock;
}

/*
 * Handle incoming connection
 */
static int handle_connection(int client_fd, struct server_config *config)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes;

    LOG_INFO("New connection on fd %d", client_fd);
    printf("connection established\n");
    fflush(stdout);

    /* Set non-blocking */
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    while (running) {
        bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes > 0) {
            buffer[bytes] = '\0';
            LOG_DEBUG("Received %zd bytes: %s", bytes, buffer);

            /* Simple HTTP/0.9 style response */
            if (strncmp(buffer, "GET ", 4) == 0) {
                char *path = buffer + 4;
                char *end = strchr(path, ' ');
                if (end) *end = '\0';
                end = strchr(path, '\r');
                if (end) *end = '\0';
                end = strchr(path, '\n');
                if (end) *end = '\0';

                LOG_INFO("GET request for: %s", path);

                /* Serve file if serve_dir is set */
                if (config->serve_dir) {
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "%s%s",
                             config->serve_dir, path);

                    int file_fd = open(filepath, O_RDONLY);
                    if (file_fd >= 0) {
                        struct stat st;
                        fstat(file_fd, &st);

                        char header[256];
                        int header_len = snprintf(header, sizeof(header),
                            "HTTP/1.0 200 OK\r\n"
                            "Content-Length: %ld\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "\r\n", (long)st.st_size);

                        send(client_fd, header, header_len, 0);

                        while ((bytes = read(file_fd, buffer, sizeof(buffer))) > 0) {
                            send(client_fd, buffer, bytes, 0);
                        }
                        close(file_fd);
                    } else {
                        const char *not_found =
                            "HTTP/1.0 404 Not Found\r\n"
                            "Content-Length: 9\r\n"
                            "\r\n"
                            "Not Found";
                        send(client_fd, not_found, strlen(not_found), 0);
                    }
                } else {
                    /* Default response */
                    const char *response =
                        "HTTP/1.0 200 OK\r\n"
                        "Content-Length: 13\r\n"
                        "Content-Type: text/plain\r\n"
                        "\r\n"
                        "Hello, QUIC!\n";
                    send(client_fd, response, strlen(response), 0);
                }

                break;  /* Close after response */
            }
        } else if (bytes == 0) {
            LOG_INFO("Connection closed by peer");
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("recv error: %s", strerror(errno));
            break;
        }

        usleep(10000);  /* 10ms */
    }

    printf("connection closed\n");
    fflush(stdout);

    close(client_fd);
    return 0;
}

/*
 * Main server loop
 */
static int run_server(struct server_config *config)
{
    int listen_fd;
    int epoll_fd;
    struct epoll_event ev, events[MAX_EVENTS];

    listen_fd = create_quic_socket(config);
    if (listen_fd < 0) {
        return -1;
    }

    /* Create epoll instance */
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        LOG_ERROR("Failed to create epoll: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        LOG_ERROR("Failed to add listen socket to epoll: %s", strerror(errno));
        close(epoll_fd);
        close(listen_fd);
        return -1;
    }

    LOG_INFO("Server started, waiting for connections...");

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("epoll_wait error: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_fd) {
                /* New connection */
                struct sockaddr_storage peer_addr;
                socklen_t peer_len = sizeof(peer_addr);

                int client_fd = accept(listen_fd,
                                       (struct sockaddr *)&peer_addr,
                                       &peer_len);

                if (client_fd >= 0) {
                    /* Handle in same thread for simplicity */
                    handle_connection(client_fd, config);
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("accept error: %s", strerror(errno));
                }
            }
        }
    }

    close(epoll_fd);
    close(listen_fd);

    LOG_INFO("Server stopped");
    return 0;
}

/*
 * Print usage
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --addr, -a <ip>         Listen address (default: ::)\n");
    printf("  --port, -p <port>       Listen port (default: 4433)\n");
    printf("  --cert, -c <file>       TLS certificate file\n");
    printf("  --key, -k <file>        TLS private key file\n");
    printf("  --serve-dir, -d <dir>   Directory to serve files from\n");
    printf("  --enable-0rtt           Enable 0-RTT early data\n");
    printf("  --enable-migration      Enable connection migration\n");
    printf("  --enable-multipath      Enable multipath QUIC\n");
    printf("  --idle-timeout <ms>     Idle timeout in milliseconds\n");
    printf("  --verbose, -v           Enable verbose output\n");
    printf("  --help, -h              Show this help\n");
}

int main(int argc, char *argv[])
{
    struct server_config config = {
        .addr = NULL,
        .port = 4433,
        .cert_file = NULL,
        .key_file = NULL,
        .serve_dir = NULL,
        .enable_0rtt = 0,
        .enable_migration = 1,
        .enable_multipath = 0,
        .max_streams = 100,
        .idle_timeout = DEFAULT_IDLE_TIMEOUT,
    };

    static struct option long_options[] = {
        {"addr",             required_argument, 0, 'a'},
        {"port",             required_argument, 0, 'p'},
        {"cert",             required_argument, 0, 'c'},
        {"key",              required_argument, 0, 'k'},
        {"serve-dir",        required_argument, 0, 'd'},
        {"enable-0rtt",      no_argument,       0, 'e'},
        {"enable-migration", no_argument,       0, 'm'},
        {"enable-multipath", no_argument,       0, 'M'},
        {"idle-timeout",     required_argument, 0, 't'},
        {"verbose",          no_argument,       0, 'v'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int opt_index = 0;

    while ((opt = getopt_long(argc, argv, "a:p:c:k:d:emMt:vh",
                               long_options, &opt_index)) != -1) {
        switch (opt) {
        case 'a':
            config.addr = optarg;
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 'c':
            config.cert_file = optarg;
            break;
        case 'k':
            config.key_file = optarg;
            break;
        case 'd':
            config.serve_dir = optarg;
            break;
        case 'e':
            config.enable_0rtt = 1;
            break;
        case 'm':
            config.enable_migration = 1;
            break;
        case 'M':
            config.enable_multipath = 1;
            break;
        case 't':
            config.idle_timeout = atoi(optarg);
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

    /* Validate required options */
    if (!config.cert_file || !config.key_file) {
        LOG_ERROR("Certificate and key files are required");
        print_usage(argv[0]);
        return 1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    return run_server(&config);
}
