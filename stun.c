#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "st.h"

union address_u {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
};
typedef union address_u address_t;

#define ADDRESS_PORT(addr) ((addr).sa.sa_family == AF_INET ? (addr).sa_in.sin_port : (addr).sa_in6.sin6_port)
#define ADDRESS_STRING(addr, buf, size) \
    ((addr).sa.sa_family == AF_INET ? \
        inet_ntop((addr).sa.sa_family, &(addr).sa_in.sin_addr, buf, size) : \
        inet_ntop((addr).sa.sa_family, &(addr).sa_in6.sin6_addr, buf, size))

/* addr_s is compact version of sockaddr_in[6] for sending over network */
struct addr_s {
    u_int16_t family;
    u_int16_t port;
    union {
        struct in_addr in4;
        struct in6_addr in6;
    } addr;
} __attribute__((__packed__));
typedef struct addr_s addr_t;

#define ADDR_STRING(a, buf, size) \
    ((a).family == AF_INET ? \
        inet_ntop((a).family, &(a).addr.in4, buf, size) : \
        inet_ntop((a).family, &(a).addr.in6, buf, size))

static void address_to_addr(address_t *a, addr_t *b) {
    if (a->sa.sa_family == AF_INET) {
        b->family = a->sa_in.sin_family;
        b->port = a->sa_in.sin_port;
        b->addr.in4 = a->sa_in.sin_addr;
    } else if (a->sa.sa_family == AF_INET6) {
        b->family = a->sa_in6.sin6_family;
        b->port = a->sa_in6.sin6_port;
        b->addr.in6 = a->sa_in6.sin6_addr;
    }
}

static void addr_to_address(addr_t *a, address_t *b) {
    memset(b, 0, sizeof(address_t));
    if (a->family == AF_INET) {
        b->sa_in.sin_family = a->family;
        b->sa_in.sin_port = a->port;
        b->sa_in.sin_addr = a->addr.in4;
    } else if (a->family == AF_INET6) {
        b->sa_in6.sin6_family = a->family;
        b->sa_in6.sin6_port = a->port;
        b->sa_in6.sin6_addr = a->addr.in6;
    }
}

struct packet_header_s {
    /* local addr */
    addr_t laddr;
    /* remote addr */
    addr_t raddr;
    /* packet size and data */
    u_int16_t size;
} __attribute__((__packed__));
#define PACKET_HEADER_SIZE sizeof(struct packet_header_s)

struct packet_s {
    struct packet_header_s hdr;
    char buf[4*1024];
} __attribute__((__packed__));

/* TODO: replace server_s */
struct state_s {
	GHashTable *connections;
	/* verbs read and write here refer to the actions taken on the tunnel socket */
	GAsyncQueue *read_queue;
	GAsyncQueue *write_queue;
	int read_fd; /* used to notify when tunnel has read */
	int write_fd; /* used to notify when tunnel needs write */
};
typedef struct state_s state_t;

static GHashTable *netmap;
static GHashTable *connections;
/* verbs read and write here refer to the actions taken on the tunnel socket */
static GAsyncQueue *read_packet_queue;
static GAsyncQueue *write_packet_queue;
static int tun_read_fd; /* used to notify when tunnel has read */
static int tun_write_fd; /* used to notify when tunnel needs write */

/* tunnel size */
static GHashTable *tun_connections;
static GAsyncQueue *out_read_packet_queue;
static GAsyncQueue *out_write_packet_queue;
static int out_read_fd; /* used to notify when out tunnel has read */
static int out_write_fd; /* used to notify when out tunnel needs write */

void queue_push_notify(int fd, GAsyncQueue *q, gpointer data) {
    g_async_queue_lock(q);
    int len = g_async_queue_length_unlocked(q);
    g_async_queue_push_unlocked(q, data);
    g_async_queue_unlock(q);
    if (len == 0) { write(fd, (void*)"\x01", 1); }
}

static void packet_free(gpointer data) {
    g_slice_free(struct packet_s, data);
}

static void *tunnel_handler(void *arg) {
    st_netfd_t client_nfd = (st_netfd_t)arg;

    struct pollfd pds[2];
    pds[0].fd = st_netfd_fileno(client_nfd);
    pds[0].events = POLLIN;
    pds[1].fd = out_write_fd;
    pds[1].events = POLLIN;

    for (;;) {
        pds[0].revents = 0;
        pds[1].revents = 0;
        if (st_poll(pds, 2, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            struct packet_s *p = g_slice_new(struct packet_s);
            ssize_t nr = st_read(client_nfd, p, PACKET_HEADER_SIZE, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            nr = st_read(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
            printf("read %zd out of %d\n", nr, p->hdr.size);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            queue_push_notify(out_write_fd, out_write_packet_queue, p);
        }

        if (pds[1].revents & POLLIN) {
            char tmp[1];
            read(out_write_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(out_read_packet_queue))) {
                printf("tunnel packet local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                ssize_t nw = st_write(client_nfd, p, PACKET_HEADER_SIZE+p->hdr.size, ST_UTIME_NO_TIMEOUT);
                g_slice_free(struct packet_s, p);
                if (nw <= 0) goto done;
            }
        }
    }
done:
    printf("exiting tunnel handler!!\n");
    st_netfd_close(client_nfd);
    return NULL;
}

static void *tunnel_out_read_sthread(void *arg) {
    addr_t *laddr = (addr_t *)arg;
    address_t remote_addr;
    socklen_t slen;
    int status;

    st_netfd_t client_nfd = g_hash_table_lookup(tun_connections, laddr);
    g_assert(client_nfd);

    slen = sizeof(remote_addr);
    status = getpeername(st_netfd_fileno(client_nfd), &remote_addr.sa, &slen);
    g_assert(status == 0);

    char addrbuf[INET6_ADDRSTRLEN];
    printf("new out tunnel remote peer: %s:%u\n",
        ADDRESS_STRING(remote_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(remote_addr)));

    for (;;) {
        struct packet_s *p = g_slice_new0(struct packet_s);
        ssize_t nr = st_read(client_nfd, p->buf, sizeof(p->buf), ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
        memcpy(&p->hdr.laddr, laddr, sizeof(addr_t));
        address_to_addr(&remote_addr, &p->hdr.raddr);
        p->hdr.size = nr;
        queue_push_notify(out_read_fd, out_read_packet_queue, p);
    }

    printf("closing out tunnel connection: %s:%u\n",
        ADDRESS_STRING(remote_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(remote_addr)));
    g_hash_table_remove(tun_connections, laddr);
    g_slice_free(addr_t, laddr);
    st_netfd_close(client_nfd);
    return NULL;
}

static void *tunnel_out_thread(void *arg) {
    st_init();

    struct pollfd pds[1];
    pds[0].fd = out_read_fd;
    pds[0].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        if (st_poll(pds, 1, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("out write queue notified\n");
            char tmp[1];
            read(out_read_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(out_write_packet_queue))) {
                printf("packet out write queue local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                st_netfd_t client_nfd = g_hash_table_lookup(tun_connections, &p->hdr.laddr);
                if (client_nfd) {
                    printf("found tunnel out client!\n");
                    ssize_t nw = st_write(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                    printf("%zd bytes written to client\n", nw);
                    if (nw <= 0) { printf("write failed\n"); }
                } else {
                    printf("tunnel out client not found\n");
                    address_t rmt_addr;
                    int sock;
                    st_netfd_t rmt_nfd;

                    addr_to_address(&p->hdr.raddr, &rmt_addr);

                    /* Connect to remote host */
                    if ((sock = socket(rmt_addr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
                        goto done;
                    }
                    if ((rmt_nfd = st_netfd_open_socket(sock)) == NULL) {
                        close(sock);
                        goto done;
                    }
                    if (st_connect(rmt_nfd, (struct sockaddr *)&rmt_addr,
                          sizeof(rmt_addr), ST_UTIME_NO_TIMEOUT) == 0) {
                        printf("connected to remote host!\n");
                        addr_t *laddr = g_slice_new0(addr_t);
                        memcpy(laddr, &p->hdr.laddr, sizeof(addr_t));
                        g_hash_table_insert(tun_connections, laddr, rmt_nfd);

                        ssize_t nw = st_write(rmt_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                        printf("%zd bytes written to tunnel out client\n", nw);
                        st_thread_t t = st_thread_create(tunnel_out_read_sthread, laddr, 0, 4*1024);
                        g_assert(t);
                    } else {
                        printf("connection to remote host failed. notify client through tunnel.\n");
                    }
                }
                g_slice_free(struct packet_s, p);
            }
        }
    }
done:
    printf("exiting tunnel out thread!!\n");
    st_thread_exit(NULL);
    g_warn_if_reached();
    return NULL;
}

static void *handle_connection(void *arg) {
    st_netfd_t client_nfd = (st_netfd_t)arg;
    address_t listening_addr;
    address_t local_addr;
    socklen_t slen;
    int status;
    gpointer hkey;
    addr_t laddr;

    slen = sizeof(listening_addr);
    status = getsockname(st_netfd_fileno(client_nfd), &listening_addr.sa, &slen);
    g_assert(status == 0);

    slen = sizeof(local_addr);
    status = getpeername(st_netfd_fileno(client_nfd), &local_addr.sa, &slen);
    g_assert(status == 0);

    hkey = (gpointer)ADDRESS_PORT(local_addr);
    g_hash_table_insert(connections, hkey, client_nfd);

    char addrbuf[INET6_ADDRSTRLEN];
    printf("new peer: %s:%u\n",
        ADDRESS_STRING(local_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(local_addr)));

    for (;;) {
        struct packet_s *p = g_slice_new0(struct packet_s);
        ssize_t nr = st_read(client_nfd, p->buf, sizeof(p->buf), ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
        address_to_addr(&local_addr, &p->hdr.laddr);
        address_to_addr(&listening_addr, &laddr);
        /* TODO: fill in remote address from mapping */
        addr_t *remote_addr = g_hash_table_lookup(netmap, &laddr);
        char addrbuf[INET6_ADDRSTRLEN];
        if (remote_addr) {
            printf("found remote: %s:%u\n",
                ADDR_STRING(*remote_addr, addrbuf, sizeof(addrbuf)),
                ntohs(remote_addr->port));
            memcpy(&p->hdr.raddr, remote_addr, sizeof(addr_t));
        } else {
            printf("no remote found\n");
        }
        p->hdr.size = nr;
        queue_push_notify(tun_write_fd, write_packet_queue, p);
    }
    printf("closing\n");
    gboolean removed = g_hash_table_remove(connections, hkey);
    g_assert(removed);
    st_netfd_close(client_nfd);
    return NULL;
}

static void *tunnel_thread(void *arg) {
    st_init();

    address_t rmt_addr;
    int sock;
    st_netfd_t rmt_nfd;

    memset(&rmt_addr, 0, sizeof(rmt_addr));
    rmt_addr.sa_in.sin_family = AF_INET;
    rmt_addr.sa_in.sin_port = htons(9001);
    inet_pton(AF_INET, "127.0.0.1", &rmt_addr.sa_in.sin_addr);

    /* Connect to remote host */
    if ((sock = socket(rmt_addr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
        goto done;
    }
    if ((rmt_nfd = st_netfd_open_socket(sock)) == NULL) {
        close(sock);
        goto done;
    }
    for (;;) {
        if (st_connect(rmt_nfd, (struct sockaddr *)&rmt_addr,
              sizeof(rmt_addr), ST_UTIME_NO_TIMEOUT) == 0) {
            break;
        }
        printf("sleeping before reconnecting tunnel\n");
        st_sleep(1);
    }
    printf("connected to tunnel!\n");

    struct pollfd pds[2];
    pds[0].fd = sock;
    pds[0].events = POLLIN;
    pds[1].fd = tun_read_fd;
    pds[1].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        pds[1].revents = 0;
        if (st_poll(pds, 2, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("data to be read from tunnel\n");
            struct packet_s *p = g_slice_new(struct packet_s);
            ssize_t nr = st_read(rmt_nfd, p, PACKET_HEADER_SIZE, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            nr = st_read(rmt_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
            printf("read %zd out of %d\n", nr, p->hdr.size);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            queue_push_notify(tun_read_fd, read_packet_queue, p);
        }

        if (pds[1].revents & POLLIN) {
            char tmp[1];
            read(tun_read_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(write_packet_queue))) {
                printf("packet local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                ssize_t nw = st_write(rmt_nfd, p, PACKET_HEADER_SIZE+p->hdr.size, ST_UTIME_NO_TIMEOUT);
                g_slice_free(struct packet_s, p);
                if (nw <= 0) goto done;
            }
        }
    }
done:
    printf("exiting tunnel thread!!\n");
    st_thread_exit(NULL);
    g_warn_if_reached();
    return NULL;
}

struct server_s {
    st_netfd_t nfd;
    u_int16_t port;
    void *(*start)(void *arg);
};

static void *accept_loop(void *arg) {
    struct server_s *s = (struct server_s *)arg;
    st_netfd_t client_nfd;
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    for (;;) {
        client_nfd = st_accept(s->nfd,
          (struct sockaddr *)&from, &fromlen, ST_UTIME_NO_TIMEOUT);
        printf("accepted\n");
        if (st_thread_create(s->start,
          (void *)client_nfd, 0, 1024 * 1024) == NULL)
        {
            fprintf(stderr, "st_thread_create error\n");
        }
    }
    free(s);
}

static st_thread_t listen_server(u_int16_t port, void *(*start)(void *arg)) {
    int sock;
    int n;
    struct sockaddr_in serv_addr;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
    }

    n = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0) {
        perror("setsockopt SO_REUSEADDR");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
    }

    if (listen(sock, 10) < 0) {
        perror("listen");
    }

    struct server_s *s = malloc(sizeof(struct server_s));
    s->nfd = st_netfd_open_socket(sock);
    s->port = port;
    s->start = start;
    return st_thread_create(accept_loop, (void *)s, 0, 4 * 1024);
}

static void *write_sthread(void *arg) {
    struct pollfd pds[1];
    pds[0].fd = tun_write_fd;
    pds[0].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        if (st_poll(pds, 1, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("read queue notified\n");
            char tmp[1];
            read(tun_write_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(read_packet_queue))) {
                printf("packet read queue local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                st_netfd_t client_nfd = g_hash_table_lookup(connections, (gpointer)p->hdr.laddr.port);
                if (client_nfd) {
                    printf("found client!\n");
                    ssize_t nw = st_write(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                    printf("%zd bytes written to client\n", nw);
                    if (nw <= 0) { printf("write failed\n"); }
                } else {
                    printf("client not found\n");
                }
                g_slice_free(struct packet_s, p);
            }
        }
    }
    return NULL;
}

static gboolean addr_match(gconstpointer a_, gconstpointer b_) {
    /* not strict equal, will match IN[6]ADDR_ANY with any addr */
    addr_t *a = (addr_t *)a_;
    addr_t *b = (addr_t *)b_;
    if ((a->family == a->family) && (a->port == a->port)) {
        if (a->family == AF_INET) {
            if (a->addr.in4.s_addr == b->addr.in4.s_addr) return TRUE;
            if (a->addr.in4.s_addr == INADDR_ANY) return TRUE;
            if (b->addr.in4.s_addr == INADDR_ANY) return TRUE;
        } else if (a->family == AF_INET6) {
            if (memcmp(&a->addr.in6, &b->addr.in6, sizeof(struct in6_addr)) == 0) return TRUE;
            if (memcmp(&a->addr.in6, &in6addr_any, sizeof(struct in6_addr)) == 0) return TRUE;
            if (memcmp(&b->addr.in6, &in6addr_any, sizeof(struct in6_addr)) == 0) return TRUE;
        }
    }
    return FALSE;
}

static int strtoaddr(const char *s, addr_t *a) {
	if (!s) return 0;
	int success = 0;

	gchar *port_str = strrchr(s, ':');
	if (!port_str) return 0;

	*port_str = 0;
	++port_str;
	a->port = htons((u_int16_t)strtol(port_str, NULL, 0));
	if (a->port == 0) goto done;
	if (inet_pton(AF_INET, s, &a->addr.in4) > 0) {
		a->family = AF_INET;
	} else if (inet_pton(AF_INET6, s, &a->addr.in6) > 0) {
		a->family = AF_INET6;
	} else {
		goto done;
	}

	success=1;
done:
	--port_str;
	*port_str = ':';
	return success;
}

static void parse_config(void) {
    GKeyFile *kf = g_key_file_new();

    if (!g_key_file_load_from_file(kf, "stun.conf", G_KEY_FILE_NONE, NULL)) {
        printf("no stun.conf found\n");
        goto free_key_file;
    }

    gchar *start_group = g_key_file_get_start_group(kf);
    printf("start group: %s\n", start_group);

    gchar **groups = g_key_file_get_groups(kf, NULL);
    int i = 0;
    gchar *group = NULL;
	for (int i = 0; (group = groups[i]); i++) {
        printf("group: %s\n", group);
        /* if group name starts with route, setup route */
        if (g_strstr_len(group, -1, "route") == group) {
            printf("route config found: %s\n", group);
			gchar *listen_address_str = g_key_file_get_value(kf, group, "listen_address", NULL);
			gchar *remote_address_str = g_key_file_get_value(kf, group, "remote_address", NULL);
			if (!listen_address_str || !remote_address_str) continue;
			addr_t *listen_addr = g_slice_new0(addr_t);
			addr_t *remote_addr = g_slice_new0(addr_t);
			/* TODO: leaks memory on error */
			if (strtoaddr(listen_address_str, listen_addr) != 1) {
				printf("invalid address: %s\n", listen_address_str);
				continue;
			}
			if (strtoaddr(remote_address_str, remote_addr) != 1) {
				printf("invalid address: %s\n", remote_address_str);
				continue;
			}
            char addrbuf[INET6_ADDRSTRLEN];
			printf("listening address: %s:%u\n",
				ADDR_STRING(*listen_addr, addrbuf, sizeof(addrbuf)),
				ntohs(listen_addr->port));
			printf("remote address: %s:%u\n",
				ADDR_STRING(*remote_addr, addrbuf, sizeof(addrbuf)),
				ntohs(remote_addr->port));
			g_hash_table_insert(netmap, listen_addr, remote_addr);
        }
    }
free_groups:
    g_strfreev(groups);

free_key_file:
    g_key_file_free(kf);
}

int main(int argc, char *argv[]) {
    g_thread_init(NULL);

    if (st_init() < 0) {
        perror("st_init");
        exit(1);
    }

    printf("sizeof(addr_t) = %zu\n", sizeof(addr_t));
    printf("sizeof(struct sockaddr) = %zu\n", sizeof(struct sockaddr));
    printf("sizeof(struct sockaddr_in) = %zu\n", sizeof(struct sockaddr_in));
    printf("sizeof(struct sockaddr_in6) = %zu\n", sizeof(struct sockaddr_in6));
    printf("sizeof(struct sockaddr_storage) = %zu\n", sizeof(struct sockaddr_storage));
    printf("sizeof(address_t) = %zu\n", sizeof(address_t));

    netmap = g_hash_table_new(g_int_hash, addr_match);
    parse_config();

    int sockets[2];
    int status;
    /* TODO: should require a mode and either be a tunnel listener or connector */
    status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    g_assert(status ==  0);
    tun_write_fd = sockets[0];
    tun_read_fd = sockets[1];

    status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    g_assert(status ==  0);
    out_write_fd = sockets[0];
    out_read_fd = sockets[1];

    read_packet_queue = g_async_queue_new_full(packet_free);
    write_packet_queue = g_async_queue_new_full(packet_free);

    out_read_packet_queue = g_async_queue_new_full(packet_free);
    out_write_packet_queue = g_async_queue_new_full(packet_free);

    connections = g_hash_table_new(g_direct_hash, g_direct_equal);
    tun_connections = g_hash_table_new(g_int_hash, addr_match);

    g_thread_create(tunnel_thread, NULL, TRUE, NULL);
    st_thread_create(write_sthread, NULL, 0, 4*1024);
    g_thread_create(tunnel_out_thread, NULL, TRUE, NULL);

    st_thread_t t1 = listen_server(9000, handle_connection);
    st_thread_t t2 = listen_server(9001, tunnel_handler);
    st_thread_join(t1, NULL);
    st_thread_join(t2, NULL);

    st_thread_exit(NULL);
    g_warn_if_reached();
    return EXIT_FAILURE;
}
