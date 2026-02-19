// SPDX-License-Identifier: GPL-2.0-only
/*
 * ip-tquic - iproute2-compatible command for TQUIC multipath management
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Usage:
 *   ip tquic show
 *   ip tquic path show [conn_id <id>]
 *   ip tquic path add conn_id <id> ifindex <n> local <addr> remote <addr>
 *   ip tquic path del path_id <n>
 *   ip tquic scheduler get [conn_id <id>]
 *   ip tquic scheduler set <name> [conn_id <id>]
 *   ip tquic bonding show
 *   ip tquic monitor
 *
 * Communicates with the TQUIC kernel module via generic netlink.
 * Install as /usr/lib/iproute2/ip-tquic for 'ip tquic' integration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>

/* =========================================================================
 * TQUIC genetlink constants (must match net/tquic/tquic_netlink.c)
 * ========================================================================= */

#define TQUIC_GENL_NAME		"tquic"
#define TQUIC_GENL_VERSION	1

/* Commands */
enum {
	TQUIC_NL_CMD_UNSPEC,
	TQUIC_NL_CMD_PATH_ADD,
	TQUIC_NL_CMD_PATH_REMOVE,
	TQUIC_NL_CMD_PATH_SET,
	TQUIC_NL_CMD_PATH_GET,
	TQUIC_NL_CMD_PATH_LIST,
	TQUIC_NL_CMD_SCHED_SET,
	TQUIC_NL_CMD_SCHED_GET,
	TQUIC_NL_CMD_STATS_GET,
	TQUIC_NL_CMD_CONN_GET,
	__TQUIC_NL_CMD_MAX,
};

/* Attributes */
enum {
	TQUIC_NL_ATTR_UNSPEC,
	TQUIC_NL_ATTR_PATH_ID,
	TQUIC_NL_ATTR_PATH_LOCAL_ADDR,
	TQUIC_NL_ATTR_PATH_REMOTE_ADDR,
	TQUIC_NL_ATTR_PATH_IFINDEX,
	TQUIC_NL_ATTR_PATH_STATE,
	TQUIC_NL_ATTR_PATH_RTT,
	TQUIC_NL_ATTR_PATH_BANDWIDTH,
	TQUIC_NL_ATTR_PATH_LOSS_RATE,
	TQUIC_NL_ATTR_PATH_WEIGHT,
	TQUIC_NL_ATTR_PATH_PRIORITY,
	TQUIC_NL_ATTR_PATH_FLAGS,
	TQUIC_NL_ATTR_SCHED_NAME,
	TQUIC_NL_ATTR_CONN_ID,
	TQUIC_NL_ATTR_PATH_LIST,
	TQUIC_NL_ATTR_PATH_ENTRY,
	TQUIC_NL_ATTR_STATS,
	TQUIC_NL_ATTR_LOCAL_ADDR4,
	TQUIC_NL_ATTR_LOCAL_ADDR6,
	TQUIC_NL_ATTR_REMOTE_ADDR4,
	TQUIC_NL_ATTR_REMOTE_ADDR6,
	TQUIC_NL_ATTR_LOCAL_PORT,
	TQUIC_NL_ATTR_REMOTE_PORT,
	TQUIC_NL_ATTR_FAMILY,
	TQUIC_NL_ATTR_STATS_TX_PACKETS,
	TQUIC_NL_ATTR_STATS_RX_PACKETS,
	TQUIC_NL_ATTR_STATS_TX_BYTES,
	TQUIC_NL_ATTR_STATS_RX_BYTES,
	TQUIC_NL_ATTR_STATS_RETRANS,
	TQUIC_NL_ATTR_STATS_SPURIOUS,
	TQUIC_NL_ATTR_STATS_CWND,
	TQUIC_NL_ATTR_STATS_SRTT,
	TQUIC_NL_ATTR_STATS_RTTVAR,
	TQUIC_NL_ATTR_EVENT_TYPE,
	TQUIC_NL_ATTR_EVENT_REASON,
	TQUIC_NL_ATTR_OLD_PATH_ID,
	TQUIC_NL_ATTR_NEW_PATH_ID,
	TQUIC_NL_ATTR_PAD,
	__TQUIC_NL_ATTR_MAX,
};
#define TQUIC_NL_ATTR_MAX (__TQUIC_NL_ATTR_MAX - 1)

/* Path states */
enum {
	TQUIC_NL_PATH_STATE_UNKNOWN = 0,
	TQUIC_NL_PATH_STATE_VALIDATING,
	TQUIC_NL_PATH_STATE_VALIDATED,
	TQUIC_NL_PATH_STATE_ACTIVE,
	TQUIC_NL_PATH_STATE_STANDBY,
	TQUIC_NL_PATH_STATE_DEGRADED,
	TQUIC_NL_PATH_STATE_FAILED,
};

/* Path flags */
#define TQUIC_NL_PATH_FLAG_BACKUP	(1 << 0)
#define TQUIC_NL_PATH_FLAG_SUBFLOW	(1 << 1)
#define TQUIC_NL_PATH_FLAG_USABLE	(1 << 2)
#define TQUIC_NL_PATH_FLAG_PREFERRED	(1 << 3)

/* Event types */
enum {
	TQUIC_EVENT_UNSPEC,
	TQUIC_EVENT_PATH_UP,
	TQUIC_EVENT_PATH_DOWN,
	TQUIC_EVENT_PATH_CHANGE,
	TQUIC_EVENT_MIGRATION,
};

/* =========================================================================
 * Netlink socket helpers
 * ========================================================================= */

#define NL_BUF_SIZE	(16 * 1024)

struct nl_sock {
	int fd;
	__u32 seq;
	__u32 pid;
};

static int nl_open(struct nl_sock *nlsk)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };

	nlsk->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nlsk->fd < 0)
		return -errno;

	if (bind(nlsk->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(nlsk->fd);
		return -errno;
	}

	nlsk->seq = 1;
	nlsk->pid = getpid();
	return 0;
}

static void nl_close(struct nl_sock *nlsk)
{
	if (nlsk->fd >= 0)
		close(nlsk->fd);
}

static int nl_send(struct nl_sock *nlsk, void *buf, size_t len)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct iovec iov = { buf, len };
	struct msghdr msg = {
		.msg_name    = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov     = &iov,
		.msg_iovlen  = 1,
	};
	ssize_t ret;

	ret = sendmsg(nlsk->fd, &msg, 0);
	return ret < 0 ? -errno : 0;
}

static int nl_recv(struct nl_sock *nlsk, void *buf, size_t bufsize)
{
	ssize_t ret;

	ret = recv(nlsk->fd, buf, bufsize, 0);
	return ret < 0 ? -errno : (int)ret;
}

/* =========================================================================
 * Generic netlink family ID discovery
 * ========================================================================= */

static int genl_get_family_id(struct nl_sock *nlsk, const char *name)
{
	struct {
		struct nlmsghdr  nlh;
		struct genlmsghdr gnlh;
		char             data[256];
	} req = {};
	struct nlattr *na;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *attrs[CTRL_ATTR_MAX + 1];
	int ret, len;
	size_t name_len;

	name_len = strlen(name) + 1;

	/* Build CTRL_CMD_GETFAMILY request */
	req.nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type  = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq   = nlsk->seq++;
	req.nlh.nlmsg_pid   = nlsk->pid;
	req.gnlh.cmd        = CTRL_CMD_GETFAMILY;
	req.gnlh.version    = 1;

	/* Add CTRL_ATTR_FAMILY_NAME attribute */
	na = (struct nlattr *)((char *)&req + NLMSG_LENGTH(GENL_HDRLEN));
	na->nla_type = CTRL_ATTR_FAMILY_NAME;
	na->nla_len  = NLA_HDRSIZE + name_len;
	memcpy((char *)na + NLA_HDRSIZE, name, name_len);
	req.nlh.nlmsg_len += NLA_ALIGN(na->nla_len);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0)
		return ret;

	ret = nl_recv(nlsk, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	nlh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nlh, (unsigned int)ret) || nlh->nlmsg_type == NLMSG_ERROR)
		return -ENOENT;

	/* Parse response attributes */
	memset(attrs, 0, sizeof(attrs));
	len = ret - NLMSG_LENGTH(GENL_HDRLEN);
	na = (struct nlattr *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN);

	while (NLA_OK(na, len)) {
		if (na->nla_type <= CTRL_ATTR_MAX)
			attrs[na->nla_type] = na;
		na = NLA_NEXT(na, len);
	}

	if (!attrs[CTRL_ATTR_FAMILY_ID])
		return -ENOENT;

	return *(unsigned short *)((char *)attrs[CTRL_ATTR_FAMILY_ID] +
				   NLA_HDRSIZE);
}

/* =========================================================================
 * Request builder helpers
 * ========================================================================= */

struct nl_req {
	struct nlmsghdr  nlh;
	struct genlmsghdr gnlh;
	char             data[2048];
};

static void nl_req_init(struct nl_req *req, int family_id, __u32 seq,
			__u32 pid, int cmd, int flags)
{
	memset(req, 0, sizeof(*req));
	req->nlh.nlmsg_type  = family_id;
	req->nlh.nlmsg_flags = NLM_F_REQUEST | flags;
	req->nlh.nlmsg_seq   = seq;
	req->nlh.nlmsg_pid   = pid;
	req->nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
	req->gnlh.cmd        = cmd;
	req->gnlh.version    = TQUIC_GENL_VERSION;
}

static struct nlattr *nl_req_tail(struct nl_req *req)
{
	return (struct nlattr *)((char *)req + req->nlh.nlmsg_len);
}

static void nl_req_put_u32(struct nl_req *req, int type, __u32 val)
{
	struct nlattr *na = nl_req_tail(req);

	na->nla_type = type;
	na->nla_len  = NLA_HDRSIZE + sizeof(__u32);
	*(__u32 *)((char *)na + NLA_HDRSIZE) = val;
	req->nlh.nlmsg_len += NLA_ALIGN(na->nla_len);
}

static void nl_req_put_u64(struct nl_req *req, int type, __u64 val)
{
	struct nlattr *na = nl_req_tail(req);

	na->nla_type = type;
	na->nla_len  = NLA_HDRSIZE + sizeof(__u64);
	memcpy((char *)na + NLA_HDRSIZE, &val, sizeof(__u64));
	req->nlh.nlmsg_len += NLA_ALIGN(na->nla_len);
}

static void nl_req_put_str(struct nl_req *req, int type, const char *str)
{
	struct nlattr *na = nl_req_tail(req);
	size_t len = strlen(str) + 1;

	na->nla_type = type;
	na->nla_len  = NLA_HDRSIZE + len;
	memcpy((char *)na + NLA_HDRSIZE, str, len);
	req->nlh.nlmsg_len += NLA_ALIGN(na->nla_len);
}

static void nl_req_put_in_addr(struct nl_req *req, int type,
			       const struct in_addr *addr)
{
	struct nlattr *na = nl_req_tail(req);

	na->nla_type = type;
	na->nla_len  = NLA_HDRSIZE + sizeof(*addr);
	memcpy((char *)na + NLA_HDRSIZE, addr, sizeof(*addr));
	req->nlh.nlmsg_len += NLA_ALIGN(na->nla_len);
}

static void nl_req_put_in6_addr(struct nl_req *req, int type,
				const struct in6_addr *addr)
{
	struct nlattr *na = nl_req_tail(req);

	na->nla_type = type;
	na->nla_len  = NLA_HDRSIZE + sizeof(*addr);
	memcpy((char *)na + NLA_HDRSIZE, addr, sizeof(*addr));
	req->nlh.nlmsg_len += NLA_ALIGN(na->nla_len);
}

/* Parse attributes from a netlink message into an array */
static void parse_attrs(struct nlattr **tb, int max, struct nlattr *na, int len)
{
	memset(tb, 0, (max + 1) * sizeof(*tb));
	while (NLA_OK(na, len)) {
		if (na->nla_type <= max)
			tb[na->nla_type] = na;
		na = NLA_NEXT(na, len);
	}
}

#define NLA_DATA(na)	((void *)((char *)(na) + NLA_HDRSIZE))

/* =========================================================================
 * Display helpers
 * ========================================================================= */

static const char *path_state_str(int state)
{
	switch (state) {
	case TQUIC_NL_PATH_STATE_VALIDATING:	return "validating";
	case TQUIC_NL_PATH_STATE_VALIDATED:	return "validated";
	case TQUIC_NL_PATH_STATE_ACTIVE:	return "active";
	case TQUIC_NL_PATH_STATE_STANDBY:	return "standby";
	case TQUIC_NL_PATH_STATE_DEGRADED:	return "degraded";
	case TQUIC_NL_PATH_STATE_FAILED:	return "failed";
	default:				return "unknown";
	}
}

static const char *event_type_str(int type)
{
	switch (type) {
	case TQUIC_EVENT_PATH_UP:	return "path-up";
	case TQUIC_EVENT_PATH_DOWN:	return "path-down";
	case TQUIC_EVENT_PATH_CHANGE:	return "path-change";
	case TQUIC_EVENT_MIGRATION:	return "migration";
	default:			return "unknown";
	}
}

static void print_addr4(const struct in_addr *addr, __be16 port)
{
	char buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, addr, buf, sizeof(buf));
	printf("%s:%u", buf, ntohs(port));
}

static void print_addr6(const struct in6_addr *addr, __be16 port)
{
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, buf, sizeof(buf));
	printf("[%s]:%u", buf, ntohs(port));
}

static void print_path_flags(unsigned int flags)
{
	if (flags & TQUIC_NL_PATH_FLAG_BACKUP)
		printf(" backup");
	if (flags & TQUIC_NL_PATH_FLAG_PREFERRED)
		printf(" preferred");
	if (flags & TQUIC_NL_PATH_FLAG_USABLE)
		printf(" usable");
	if (flags & TQUIC_NL_PATH_FLAG_SUBFLOW)
		printf(" subflow");
}

/* Print a single path from an attribute set */
static void print_path(struct nlattr **tb)
{
	char ifname[IF_NAMESIZE] = "?";
	int ifindex;

	if (tb[TQUIC_NL_ATTR_PATH_IFINDEX]) {
		ifindex = *(int *)NLA_DATA(tb[TQUIC_NL_ATTR_PATH_IFINDEX]);
		if_indextoname(ifindex, ifname);
	}

	printf("\tpath %u", tb[TQUIC_NL_ATTR_PATH_ID] ?
		*(unsigned int *)NLA_DATA(tb[TQUIC_NL_ATTR_PATH_ID]) : 0);

	printf(" state %s", path_state_str(tb[TQUIC_NL_ATTR_PATH_STATE] ?
		*(unsigned char *)NLA_DATA(tb[TQUIC_NL_ATTR_PATH_STATE]) : 0));

	printf(" dev %s", ifname);

	/* Local address */
	printf(" local ");
	if (tb[TQUIC_NL_ATTR_LOCAL_ADDR4] && tb[TQUIC_NL_ATTR_LOCAL_PORT]) {
		print_addr4(NLA_DATA(tb[TQUIC_NL_ATTR_LOCAL_ADDR4]),
			    *(__be16 *)NLA_DATA(tb[TQUIC_NL_ATTR_LOCAL_PORT]));
	} else if (tb[TQUIC_NL_ATTR_LOCAL_ADDR6] && tb[TQUIC_NL_ATTR_LOCAL_PORT]) {
		print_addr6(NLA_DATA(tb[TQUIC_NL_ATTR_LOCAL_ADDR6]),
			    *(__be16 *)NLA_DATA(tb[TQUIC_NL_ATTR_LOCAL_PORT]));
	} else {
		printf("?");
	}

	/* Remote address */
	printf(" remote ");
	if (tb[TQUIC_NL_ATTR_REMOTE_ADDR4] && tb[TQUIC_NL_ATTR_REMOTE_PORT]) {
		print_addr4(NLA_DATA(tb[TQUIC_NL_ATTR_REMOTE_ADDR4]),
			    *(__be16 *)NLA_DATA(tb[TQUIC_NL_ATTR_REMOTE_PORT]));
	} else if (tb[TQUIC_NL_ATTR_REMOTE_ADDR6] && tb[TQUIC_NL_ATTR_REMOTE_PORT]) {
		print_addr6(NLA_DATA(tb[TQUIC_NL_ATTR_REMOTE_ADDR6]),
			    *(__be16 *)NLA_DATA(tb[TQUIC_NL_ATTR_REMOTE_PORT]));
	} else {
		printf("?");
	}

	if (tb[TQUIC_NL_ATTR_PATH_RTT]) {
		unsigned int rtt = *(unsigned int *)NLA_DATA(tb[TQUIC_NL_ATTR_PATH_RTT]);

		printf(" rtt %u.%03ums", rtt / 1000, rtt % 1000);
	}

	if (tb[TQUIC_NL_ATTR_PATH_BANDWIDTH]) {
		unsigned long long bw;

		memcpy(&bw, NLA_DATA(tb[TQUIC_NL_ATTR_PATH_BANDWIDTH]),
		       sizeof(bw));
		if (bw >= 1000000000ULL)
			printf(" bw %.2fGbps", bw / 1e9);
		else if (bw >= 1000000ULL)
			printf(" bw %.2fMbps", bw / 1e6);
		else if (bw >= 1000ULL)
			printf(" bw %.2fKbps", bw / 1e3);
		else
			printf(" bw %llubps", bw);
	}

	if (tb[TQUIC_NL_ATTR_PATH_LOSS_RATE]) {
		unsigned int loss = *(unsigned int *)NLA_DATA(
				    tb[TQUIC_NL_ATTR_PATH_LOSS_RATE]);

		printf(" loss %u.%02u%%", loss / 100, loss % 100);
	}

	if (tb[TQUIC_NL_ATTR_PATH_WEIGHT]) {
		printf(" weight %u",
		       *(unsigned int *)NLA_DATA(tb[TQUIC_NL_ATTR_PATH_WEIGHT]));
	}

	if (tb[TQUIC_NL_ATTR_PATH_FLAGS]) {
		unsigned int flags = *(unsigned int *)NLA_DATA(
				     tb[TQUIC_NL_ATTR_PATH_FLAGS]);

		print_path_flags(flags);
	}

	printf("\n");
}

/* =========================================================================
 * Command implementations
 * ========================================================================= */

/* ip tquic show / ip tquic path show [conn_id <id>] */
static int cmd_path_show(struct nl_sock *nlsk, int family_id,
			 unsigned long long conn_id, int has_conn_id)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_PATH_LIST, NLM_F_DUMP);

	if (has_conn_id)
		nl_req_put_u64(&req, TQUIC_NL_ATTR_CONN_ID, conn_id);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	/* Receive and print multipart response */
	while (1) {
		ret = nl_recv(nlsk, buf, sizeof(buf));
		if (ret < 0) {
			fprintf(stderr, "recv error: %s\n", strerror(-ret));
			return ret;
		}

		nlh = (struct nlmsghdr *)buf;

		while (NLMSG_OK(nlh, (unsigned int)ret)) {
			struct nlattr *tb[TQUIC_NL_ATTR_MAX + 1];
			struct genlmsghdr *gnlh;
			int alen;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				fprintf(stderr, "kernel error: %s\n",
					strerror(-err->error));
				return err->error;
			}

			gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
			parse_attrs(tb, TQUIC_NL_ATTR_MAX,
				    (struct nlattr *)((char *)gnlh + GENL_HDRLEN),
				    alen);

			/* Print connection header if conn_id present */
			if (tb[TQUIC_NL_ATTR_CONN_ID]) {
				unsigned long long cid;

				memcpy(&cid,
				       NLA_DATA(tb[TQUIC_NL_ATTR_CONN_ID]),
				       sizeof(cid));
				printf("conn %llu\n", cid);
			}

			print_path(tb);
			nlh = NLMSG_NEXT(nlh, ret);
		}

		/* Not a multipart message */
		if (!(((struct nlmsghdr *)buf)->nlmsg_flags & NLM_F_MULTI))
			break;
	}

	return 0;
}

/* ip tquic path add conn_id <id> ifindex <n> local <addr>:<port>
 *                                           remote <addr>:<port> */
static int cmd_path_add(struct nl_sock *nlsk, int family_id,
			unsigned long long conn_id, int ifindex,
			const char *local_ip, unsigned short local_port,
			const char *remote_ip, unsigned short remote_port)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	struct in_addr addr4;
	struct in6_addr addr6;
	int ret;
	int is_v6_local  = strchr(local_ip, ':') != NULL;
	int is_v6_remote = strchr(remote_ip, ':') != NULL;
	__be16 lport = htons(local_port);
	__be16 rport = htons(remote_port);

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_PATH_ADD, 0);

	nl_req_put_u64(&req, TQUIC_NL_ATTR_CONN_ID, conn_id);
	nl_req_put_u32(&req, TQUIC_NL_ATTR_PATH_IFINDEX, (unsigned int)ifindex);

	if (is_v6_local) {
		if (inet_pton(AF_INET6, local_ip, &addr6) != 1) {
			fprintf(stderr, "invalid local address: %s\n", local_ip);
			return -EINVAL;
		}
		nl_req_put_in6_addr(&req, TQUIC_NL_ATTR_LOCAL_ADDR6, &addr6);
		nl_req_put_u32(&req, TQUIC_NL_ATTR_FAMILY, AF_INET6);
	} else {
		if (inet_pton(AF_INET, local_ip, &addr4) != 1) {
			fprintf(stderr, "invalid local address: %s\n", local_ip);
			return -EINVAL;
		}
		nl_req_put_in_addr(&req, TQUIC_NL_ATTR_LOCAL_ADDR4, &addr4);
		nl_req_put_u32(&req, TQUIC_NL_ATTR_FAMILY, AF_INET);
	}
	nl_req_put_u32(&req, TQUIC_NL_ATTR_LOCAL_PORT, ntohs(lport));

	if (is_v6_remote) {
		if (inet_pton(AF_INET6, remote_ip, &addr6) != 1) {
			fprintf(stderr, "invalid remote address: %s\n", remote_ip);
			return -EINVAL;
		}
		nl_req_put_in6_addr(&req, TQUIC_NL_ATTR_REMOTE_ADDR6, &addr6);
	} else {
		if (inet_pton(AF_INET, remote_ip, &addr4) != 1) {
			fprintf(stderr, "invalid remote address: %s\n", remote_ip);
			return -EINVAL;
		}
		nl_req_put_in_addr(&req, TQUIC_NL_ATTR_REMOTE_ADDR4, &addr4);
	}
	nl_req_put_u32(&req, TQUIC_NL_ATTR_REMOTE_PORT, ntohs(rport));

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	ret = nl_recv(nlsk, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "recv error: %s\n", strerror(-ret));
		return ret;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		if (err->error) {
			fprintf(stderr, "Failed to add path: %s\n",
				strerror(-err->error));
			return err->error;
		}
	}

	printf("Path added successfully\n");
	return 0;
}

/* ip tquic path del path_id <n> */
static int cmd_path_del(struct nl_sock *nlsk, int family_id,
			unsigned int path_id)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_PATH_REMOVE, 0);

	nl_req_put_u32(&req, TQUIC_NL_ATTR_PATH_ID, path_id);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	ret = nl_recv(nlsk, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "recv error: %s\n", strerror(-ret));
		return ret;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		if (err->error) {
			fprintf(stderr, "Failed to remove path: %s\n",
				strerror(-err->error));
			return err->error;
		}
	}

	printf("Path %u removed\n", path_id);
	return 0;
}

/* ip tquic scheduler get [conn_id <id>] */
static int cmd_sched_get(struct nl_sock *nlsk, int family_id,
			 unsigned long long conn_id, int has_conn_id)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *tb[TQUIC_NL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh;
	int ret, alen;

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_SCHED_GET, 0);

	if (has_conn_id)
		nl_req_put_u64(&req, TQUIC_NL_ATTR_CONN_ID, conn_id);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	ret = nl_recv(nlsk, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "recv error: %s\n", strerror(-ret));
		return ret;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		fprintf(stderr, "kernel error: %s\n", strerror(-err->error));
		return err->error;
	}

	gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	parse_attrs(tb, TQUIC_NL_ATTR_MAX,
		    (struct nlattr *)((char *)gnlh + GENL_HDRLEN), alen);

	if (!tb[TQUIC_NL_ATTR_SCHED_NAME]) {
		printf("scheduler: (unknown)\n");
		return 0;
	}

	printf("scheduler: %s\n", (char *)NLA_DATA(tb[TQUIC_NL_ATTR_SCHED_NAME]));
	return 0;
}

/* ip tquic scheduler set <name> [conn_id <id>] */
static int cmd_sched_set(struct nl_sock *nlsk, int family_id,
			 const char *name,
			 unsigned long long conn_id, int has_conn_id)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_SCHED_SET, 0);

	nl_req_put_str(&req, TQUIC_NL_ATTR_SCHED_NAME, name);

	if (has_conn_id)
		nl_req_put_u64(&req, TQUIC_NL_ATTR_CONN_ID, conn_id);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	ret = nl_recv(nlsk, buf, sizeof(buf));
	if (ret < 0) {
		fprintf(stderr, "recv error: %s\n", strerror(-ret));
		return ret;
	}

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		if (err->error) {
			fprintf(stderr, "Failed to set scheduler: %s\n",
				strerror(-err->error));
			return err->error;
		}
	}

	printf("Scheduler set to: %s\n", name);
	return 0;
}

/* ip tquic stats [conn_id <id>] */
static int cmd_stats(struct nl_sock *nlsk, int family_id,
		     unsigned long long conn_id, int has_conn_id)
{
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	int ret;

	nl_req_init(&req, family_id, nlsk->seq++, nlsk->pid,
		    TQUIC_NL_CMD_STATS_GET, NLM_F_DUMP);

	if (has_conn_id)
		nl_req_put_u64(&req, TQUIC_NL_ATTR_CONN_ID, conn_id);

	ret = nl_send(nlsk, &req, req.nlh.nlmsg_len);
	if (ret < 0) {
		fprintf(stderr, "send error: %s\n", strerror(-ret));
		return ret;
	}

	while (1) {
		ret = nl_recv(nlsk, buf, sizeof(buf));
		if (ret < 0) {
			fprintf(stderr, "recv error: %s\n", strerror(-ret));
			return ret;
		}

		nlh = (struct nlmsghdr *)buf;

		while (NLMSG_OK(nlh, (unsigned int)ret)) {
			struct nlattr *tb[TQUIC_NL_ATTR_MAX + 1];
			struct genlmsghdr *gnlh;
			int alen;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				fprintf(stderr, "kernel error: %s\n",
					strerror(-err->error));
				return err->error;
			}

			gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
			parse_attrs(tb, TQUIC_NL_ATTR_MAX,
				    (struct nlattr *)((char *)gnlh + GENL_HDRLEN),
				    alen);

			printf("path %u:", tb[TQUIC_NL_ATTR_PATH_ID] ?
				*(unsigned int *)NLA_DATA(
				tb[TQUIC_NL_ATTR_PATH_ID]) : 0);

			if (tb[TQUIC_NL_ATTR_STATS_TX_BYTES]) {
				unsigned long long v;

				memcpy(&v,
				       NLA_DATA(tb[TQUIC_NL_ATTR_STATS_TX_BYTES]),
				       sizeof(v));
				printf(" tx=%llu bytes", v);
			}
			if (tb[TQUIC_NL_ATTR_STATS_RX_BYTES]) {
				unsigned long long v;

				memcpy(&v,
				       NLA_DATA(tb[TQUIC_NL_ATTR_STATS_RX_BYTES]),
				       sizeof(v));
				printf(" rx=%llu bytes", v);
			}
			if (tb[TQUIC_NL_ATTR_STATS_TX_PACKETS]) {
				unsigned long long v;

				memcpy(&v,
				       NLA_DATA(tb[TQUIC_NL_ATTR_STATS_TX_PACKETS]),
				       sizeof(v));
				printf(" tx_pkts=%llu", v);
			}
			if (tb[TQUIC_NL_ATTR_STATS_RETRANS]) {
				unsigned long long v;

				memcpy(&v,
				       NLA_DATA(tb[TQUIC_NL_ATTR_STATS_RETRANS]),
				       sizeof(v));
				printf(" retrans=%llu", v);
			}
			if (tb[TQUIC_NL_ATTR_STATS_SRTT]) {
				unsigned int srtt = *(unsigned int *)NLA_DATA(
					tb[TQUIC_NL_ATTR_STATS_SRTT]);

				printf(" srtt=%uus", srtt);
			}
			if (tb[TQUIC_NL_ATTR_STATS_CWND]) {
				printf(" cwnd=%u",
				       *(unsigned int *)NLA_DATA(
				       tb[TQUIC_NL_ATTR_STATS_CWND]));
			}
			printf("\n");

			nlh = NLMSG_NEXT(nlh, ret);
		}

		if (!(((struct nlmsghdr *)buf)->nlmsg_flags & NLM_F_MULTI))
			break;
	}

	return 0;
}

/* ip tquic monitor - subscribe to TQUIC events */
static volatile int monitor_running = 1;

static void monitor_sig(int sig)
{
	(void)sig;
	monitor_running = 0;
}

static int cmd_monitor(struct nl_sock *nlsk, int family_id)
{
	/* Subscribe to events multicast group */
	struct nl_req req;
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	int grp_id = -1;
	int ret;

	/* Discover multicast group ID for "events" */
	{
		struct {
			struct nlmsghdr  nlh;
			struct genlmsghdr gnlh;
			char             data[64];
		} greq = {};
		struct nlattr *na;
		struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
		struct iovec iov;
		struct msghdr msg;

		greq.nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
		greq.nlh.nlmsg_type  = GENL_ID_CTRL;
		greq.nlh.nlmsg_flags = NLM_F_REQUEST;
		greq.nlh.nlmsg_seq   = nlsk->seq++;
		greq.nlh.nlmsg_pid   = nlsk->pid;
		greq.gnlh.cmd        = CTRL_CMD_GETFAMILY;
		greq.gnlh.version    = 1;

		na = (struct nlattr *)((char *)&greq + NLMSG_LENGTH(GENL_HDRLEN));
		na->nla_type = CTRL_ATTR_FAMILY_NAME;
		na->nla_len  = NLA_HDRSIZE + strlen(TQUIC_GENL_NAME) + 1;
		memcpy((char *)na + NLA_HDRSIZE, TQUIC_GENL_NAME,
		       strlen(TQUIC_GENL_NAME) + 1);
		greq.nlh.nlmsg_len += NLA_ALIGN(na->nla_len);

		iov.iov_base = &greq;
		iov.iov_len  = greq.nlh.nlmsg_len;
		msg.msg_name    = &sa;
		msg.msg_namelen = sizeof(sa);
		msg.msg_iov     = &iov;
		msg.msg_iovlen  = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags   = 0;

		sendmsg(nlsk->fd, &msg, 0);
		ret = nl_recv(nlsk, buf, sizeof(buf));
		if (ret > 0) {
			nlh = (struct nlmsghdr *)buf;
			if (NLMSG_OK(nlh, (unsigned int)ret) &&
			    nlh->nlmsg_type != NLMSG_ERROR) {
				int len = ret - NLMSG_LENGTH(GENL_HDRLEN);
				struct nlattr *attrs[CTRL_ATTR_MAX + 1];

				parse_attrs(attrs, CTRL_ATTR_MAX,
					    (struct nlattr *)((char *)NLMSG_DATA(nlh)
					    + GENL_HDRLEN), len);

				if (attrs[CTRL_ATTR_MCAST_GROUPS]) {
					struct nlattr *mcgrps =
						attrs[CTRL_ATTR_MCAST_GROUPS];
					struct nlattr *grp;
					int mlen = NLA_PAYLOAD(mcgrps);

					grp = (struct nlattr *)NLA_DATA(mcgrps);
					while (NLA_OK(grp, mlen)) {
						struct nlattr *ga[CTRL_ATTR_MCAST_GRP_MAX + 1];
						int glen = NLA_PAYLOAD(grp);

						parse_attrs(ga,
							    CTRL_ATTR_MCAST_GRP_MAX,
							    (struct nlattr *)NLA_DATA(grp),
							    glen);
						if (ga[CTRL_ATTR_MCAST_GRP_NAME] &&
						    strcmp(NLA_DATA(ga[CTRL_ATTR_MCAST_GRP_NAME]),
							   "events") == 0) {
							grp_id = *(int *)NLA_DATA(
								ga[CTRL_ATTR_MCAST_GRP_ID]);
						}
						grp = NLA_NEXT(grp, mlen);
					}
				}
			}
		}
	}

	if (grp_id < 0) {
		fprintf(stderr, "Failed to find TQUIC events multicast group\n");
		return -ENOENT;
	}

	/* Join the multicast group */
	if (setsockopt(nlsk->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &grp_id, sizeof(grp_id)) < 0) {
		perror("setsockopt NETLINK_ADD_MEMBERSHIP");
		return -errno;
	}

	signal(SIGINT, monitor_sig);
	signal(SIGTERM, monitor_sig);

	printf("Monitoring TQUIC events (press Ctrl+C to stop)...\n");

	while (monitor_running) {
		struct nlattr *tb[TQUIC_NL_ATTR_MAX + 1];
		struct genlmsghdr *gnlh;
		int alen;

		ret = nl_recv(nlsk, buf, sizeof(buf));
		if (ret < 0) {
			if (errno == EINTR)
				break;
			fprintf(stderr, "recv error: %s\n", strerror(-ret));
			break;
		}

		nlh = (struct nlmsghdr *)buf;
		if (!NLMSG_OK(nlh, (unsigned int)ret))
			continue;
		if (nlh->nlmsg_type == NLMSG_NOOP ||
		    nlh->nlmsg_type == NLMSG_DONE)
			continue;

		gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
		alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
		parse_attrs(tb, TQUIC_NL_ATTR_MAX,
			    (struct nlattr *)((char *)gnlh + GENL_HDRLEN), alen);

		/* Print timestamp */
		{
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			printf("[%ld.%06ld] ", ts.tv_sec, ts.tv_nsec / 1000);
		}

		if (tb[TQUIC_NL_ATTR_EVENT_TYPE]) {
			unsigned char etype = *(unsigned char *)NLA_DATA(
					      tb[TQUIC_NL_ATTR_EVENT_TYPE]);

			printf("%-12s", event_type_str(etype));
		} else {
			printf("event      ");
		}

		if (tb[TQUIC_NL_ATTR_CONN_ID]) {
			unsigned long long cid;

			memcpy(&cid, NLA_DATA(tb[TQUIC_NL_ATTR_CONN_ID]),
			       sizeof(cid));
			printf(" conn %llu", cid);
		}

		if (tb[TQUIC_NL_ATTR_PATH_ID]) {
			printf(" path %u", *(unsigned int *)NLA_DATA(
					   tb[TQUIC_NL_ATTR_PATH_ID]));
		}

		if (tb[TQUIC_NL_ATTR_PATH_STATE]) {
			printf(" state %s", path_state_str(
				*(unsigned char *)NLA_DATA(
				tb[TQUIC_NL_ATTR_PATH_STATE])));
		}

		printf("\n");
		fflush(stdout);
	}

	printf("\nDone.\n");
	return 0;
}

/* =========================================================================
 * Command-line parsing
 * ========================================================================= */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s COMMAND [OPTIONS]\n"
		"\n"
		"Commands:\n"
		"  show                      Show all TQUIC connections and paths\n"
		"  path show [conn_id <id>]  Show paths (optionally for a connection)\n"
		"  path add conn_id <id> ifindex <n>\n"
		"          local <addr>:<port> remote <addr>:<port>\n"
		"                            Add a path to a connection\n"
		"  path del path_id <n>      Remove a path\n"
		"  scheduler get [conn_id <id>]\n"
		"                            Get active scheduler\n"
		"  scheduler set <name> [conn_id <id>]\n"
		"                            Set scheduler (minrtt/aggregate/weighted/blest/ecf)\n"
		"  stats [conn_id <id>]      Show per-path statistics\n"
		"  monitor                   Subscribe to TQUIC path events\n"
		"\n",
		prog);
}

int main(int argc, char *argv[])
{
	struct nl_sock nlsk = { .fd = -1 };
	int family_id;
	int ret;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	ret = nl_open(&nlsk);
	if (ret < 0) {
		fprintf(stderr, "Failed to open netlink socket: %s\n",
			strerror(-ret));
		return 1;
	}

	family_id = genl_get_family_id(&nlsk, TQUIC_GENL_NAME);
	if (family_id < 0) {
		fprintf(stderr,
			"TQUIC kernel module not loaded or not accessible.\n"
			"Load the module: modprobe tquic\n");
		nl_close(&nlsk);
		return 1;
	}

	if (strcmp(argv[1], "show") == 0) {
		ret = cmd_path_show(&nlsk, family_id, 0, 0);

	} else if (strcmp(argv[1], "path") == 0) {
		if (argc < 3) {
			usage(argv[0]);
			ret = 1;
			goto out;
		}

		if (strcmp(argv[2], "show") == 0) {
			unsigned long long conn_id = 0;
			int has_conn_id = 0;

			if (argc >= 5 && strcmp(argv[3], "conn_id") == 0) {
				conn_id = strtoull(argv[4], NULL, 0);
				has_conn_id = 1;
			}
			ret = cmd_path_show(&nlsk, family_id, conn_id,
					    has_conn_id);

		} else if (strcmp(argv[2], "add") == 0) {
			/* path add conn_id <id> ifindex <n>
			 *            local <addr>:<port> remote <addr>:<port> */
			unsigned long long conn_id = 0;
			int ifindex = 0;
			const char *local_ip = NULL, *remote_ip = NULL;
			unsigned short local_port = 0, remote_port = 0;
			char local_buf[64], remote_buf[64];
			char *colon;
			int i;

			for (i = 3; i < argc - 1; i++) {
				if (strcmp(argv[i], "conn_id") == 0)
					conn_id = strtoull(argv[++i], NULL, 0);
				else if (strcmp(argv[i], "ifindex") == 0)
					ifindex = (int)strtol(argv[++i], NULL, 0);
				else if (strcmp(argv[i], "dev") == 0) {
					ifindex = if_nametoindex(argv[++i]);
					if (!ifindex) {
						fprintf(stderr,
							"Unknown interface: %s\n",
							argv[i]);
						ret = 1;
						goto out;
					}
				} else if (strcmp(argv[i], "local") == 0) {
					strncpy(local_buf, argv[++i],
						sizeof(local_buf) - 1);
					local_buf[sizeof(local_buf) - 1] = '\0';
					colon = strrchr(local_buf, ':');
					if (colon) {
						*colon = '\0';
						local_port = (unsigned short)
							strtoul(colon + 1,
								NULL, 10);
					}
					local_ip = local_buf;
				} else if (strcmp(argv[i], "remote") == 0) {
					strncpy(remote_buf, argv[++i],
						sizeof(remote_buf) - 1);
					remote_buf[sizeof(remote_buf) - 1] = '\0';
					colon = strrchr(remote_buf, ':');
					if (colon) {
						*colon = '\0';
						remote_port = (unsigned short)
							strtoul(colon + 1,
								NULL, 10);
					}
					remote_ip = remote_buf;
				}
			}

			if (!local_ip || !remote_ip || !ifindex) {
				fprintf(stderr,
					"path add requires: conn_id, ifindex (or dev), local, remote\n");
				ret = 1;
				goto out;
			}

			ret = cmd_path_add(&nlsk, family_id, conn_id, ifindex,
					   local_ip, local_port,
					   remote_ip, remote_port);

		} else if (strcmp(argv[2], "del") == 0) {
			unsigned int path_id = 0;
			int i;

			for (i = 3; i < argc - 1; i++) {
				if (strcmp(argv[i], "path_id") == 0)
					path_id = (unsigned int)strtoul(
						argv[++i], NULL, 0);
			}

			if (!path_id) {
				fprintf(stderr, "path del requires: path_id <n>\n");
				ret = 1;
				goto out;
			}

			ret = cmd_path_del(&nlsk, family_id, path_id);

		} else {
			fprintf(stderr, "Unknown path command: %s\n", argv[2]);
			usage(argv[0]);
			ret = 1;
		}

	} else if (strcmp(argv[1], "scheduler") == 0) {
		if (argc < 3) {
			usage(argv[0]);
			ret = 1;
			goto out;
		}

		if (strcmp(argv[2], "get") == 0) {
			unsigned long long conn_id = 0;
			int has_conn_id = 0;

			if (argc >= 5 && strcmp(argv[3], "conn_id") == 0) {
				conn_id = strtoull(argv[4], NULL, 0);
				has_conn_id = 1;
			}
			ret = cmd_sched_get(&nlsk, family_id, conn_id,
					    has_conn_id);

		} else if (strcmp(argv[2], "set") == 0) {
			unsigned long long conn_id = 0;
			int has_conn_id = 0;
			const char *name;

			if (argc < 4) {
				fprintf(stderr,
					"scheduler set requires: <name>\n");
				ret = 1;
				goto out;
			}

			name = argv[3];

			if (argc >= 6 && strcmp(argv[4], "conn_id") == 0) {
				conn_id = strtoull(argv[5], NULL, 0);
				has_conn_id = 1;
			}

			ret = cmd_sched_set(&nlsk, family_id, name, conn_id,
					    has_conn_id);

		} else {
			fprintf(stderr, "Unknown scheduler command: %s\n",
				argv[2]);
			usage(argv[0]);
			ret = 1;
		}

	} else if (strcmp(argv[1], "stats") == 0) {
		unsigned long long conn_id = 0;
		int has_conn_id = 0;

		if (argc >= 4 && strcmp(argv[2], "conn_id") == 0) {
			conn_id = strtoull(argv[3], NULL, 0);
			has_conn_id = 1;
		}
		ret = cmd_stats(&nlsk, family_id, conn_id, has_conn_id);

	} else if (strcmp(argv[1], "monitor") == 0) {
		ret = cmd_monitor(&nlsk, family_id);

	} else if (strcmp(argv[1], "help") == 0 ||
		   strcmp(argv[1], "--help") == 0 ||
		   strcmp(argv[1], "-h") == 0) {
		usage(argv[0]);
		ret = 0;

	} else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		usage(argv[0]);
		ret = 1;
	}

out:
	nl_close(&nlsk);
	return ret < 0 ? 1 : ret;
}
