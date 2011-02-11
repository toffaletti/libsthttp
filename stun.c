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

enum packet_flag_e {
    TUN_FLAG_CLOSE = 1,
};

struct packet_header_s {
    /* local addr */
    addr_t laddr;
    /* remote addr */
    addr_t raddr;
    /* packet size and data */
    u_int32_t flags;
    u_int16_t size;
} __attribute__((__packed__));
#define PACKET_HEADER_SIZE sizeof(struct packet_header_s)

struct packet_s {
    struct packet_header_s hdr;
    char buf[4*1024];
} __attribute__((__packed__));

/* TODO: replace server_s */
struct server_s {
    st_netfd_t nfd;
    void *(*start)(void *arg);

    GHashTable *connections;
    GAsyncQueue *read_queue;
    GAsyncQueue *write_queue;
    int read_fd; /* used to notify when read_queue becomes not empty */
    int write_fd; /* used to notify when write queue becomes not empty */

    addr_t listen_addr;
    addr_t remote_addr; /* remote address to send packets to on the other side of tunnel */
    addr_t tunnel_addr; /* address of remote tunnel */

    st_thread_t listen_sthread;
    st_thread_t write_sthread;
};
typedef struct server_s server_t;

static GHashTable *netmap;
static server_t *tunnel_server;

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
    pds[1].fd = tunnel_server->write_fd;
    pds[1].events = POLLIN;

    for (;;) {
        pds[0].revents = 0;
        pds[1].revents = 0;
        if (st_poll(pds, 2, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            struct packet_s *p = g_slice_new(struct packet_s);
            ssize_t nr = st_read_fully(client_nfd, p, PACKET_HEADER_SIZE, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            nr = st_read_fully(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
            printf("tunnel slave read %zd out of %d\n", nr, p->hdr.size);
            if (nr != p->hdr.size) { g_slice_free(struct packet_s, p); break; }
            queue_push_notify(tunnel_server->write_fd, tunnel_server->write_queue, p);
        }

        if (pds[1].revents & POLLIN) {
            char tmp[1];
            read(tunnel_server->write_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(tunnel_server->read_queue))) {
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

    st_netfd_t client_nfd = g_hash_table_lookup(tunnel_server->connections, laddr);
    g_assert(client_nfd);

    slen = sizeof(remote_addr);
    status = getpeername(st_netfd_fileno(client_nfd), &remote_addr.sa, &slen);
    g_assert(status == 0);

    char addrbuf[INET6_ADDRSTRLEN];
    printf("new out tunnel remote peer: %s:%u\n",
        ADDRESS_STRING(remote_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(remote_addr)));
    printf("local peer addr: %s:%u\n",
        ADDR_STRING(*laddr, addrbuf, sizeof(addrbuf)),
        ntohs(laddr->port));

    printf("client: %p (%d)\n",
        client_nfd, st_netfd_fileno(client_nfd));

    for (;;) {
        struct packet_s *p = g_slice_new0(struct packet_s);
        ssize_t nr = st_read(client_nfd, p->buf, sizeof(p->buf), ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
        if (!g_hash_table_lookup(tunnel_server->connections, laddr)) {
            /* client has been removed from table. probably got close packet */
            g_slice_free(struct packet_s, p);
            break;
        }
        memcpy(&p->hdr.laddr, laddr, sizeof(addr_t));
        address_to_addr(&remote_addr, &p->hdr.raddr);
        p->hdr.size = nr;
        queue_push_notify(tunnel_server->read_fd, tunnel_server->read_queue, p);
    }

    printf("closing out tunnel connection: %s:%u\n",
        ADDRESS_STRING(remote_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(remote_addr)));
    /* if the connection isnt found, it was likely closed by the other side first */
    if (g_hash_table_remove(tunnel_server->connections, laddr)) {
        /* push empty packet to notify remote end of close */
        struct packet_s *p = g_slice_new0(struct packet_s);
        memcpy(&p->hdr.laddr, laddr, sizeof(addr_t));
        address_to_addr(&remote_addr, &p->hdr.raddr);
        p->hdr.flags |= TUN_FLAG_CLOSE;
        queue_push_notify(tunnel_server->read_fd, tunnel_server->read_queue, p);
    }

    g_slice_free(addr_t, laddr);
    st_netfd_close(client_nfd);
    return NULL;
}

static void *tunnel_out_thread(void *arg) {
    st_init();

    struct pollfd pds[1];
    pds[0].fd = tunnel_server->read_fd;
    pds[0].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        if (st_poll(pds, 1, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("out write queue notified\n");
            char tmp[1];
            read(tunnel_server->read_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(tunnel_server->write_queue))) {
                printf("packet out write queue local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                st_netfd_t client_nfd = g_hash_table_lookup(tunnel_server->connections, &p->hdr.laddr);
                if ((p->hdr.flags & TUN_FLAG_CLOSE) && client_nfd) {
                    printf("got close flag packet. removing tunnel out client: %p (%d)\n",
                        client_nfd, st_netfd_fileno(client_nfd));
                    g_hash_table_remove(tunnel_server->connections, &p->hdr.laddr);
                } else if (client_nfd) {
                    printf("found tunnel out client!\n");
                    ssize_t nw = st_write(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                    printf("%zd bytes written to client\n", nw);
                    if (nw <= 0) { printf("write failed\n"); }
                } else if (!(p->hdr.flags & TUN_FLAG_CLOSE)) {
                    printf("tunnel out client not found, creating one\n");
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
                        g_hash_table_insert(tunnel_server->connections, laddr, rmt_nfd);

                        ssize_t nw = st_write(rmt_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                        printf("%zd bytes written to tunnel out client\n", nw);
                        st_thread_t t = st_thread_create(tunnel_out_read_sthread, laddr, 0, 4*1024);
                        g_assert(t);
                    } else {
                        printf("connection to remote host failed. notify client through tunnel.\n");
                        struct packet_s *rp = g_slice_new0(struct packet_s);
                        memcpy(&rp->hdr.laddr, &p->hdr.laddr, sizeof(addr_t));
                        memcpy(&rp->hdr.raddr, &p->hdr.raddr, sizeof(addr_t));
                        rp->hdr.flags |= TUN_FLAG_CLOSE;
                        queue_push_notify(tunnel_server->read_fd, tunnel_server->read_queue, rp);
                    }
                } else {
                    printf("no client found, dropping packet\n");
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

    address_to_addr(&listening_addr, &laddr);
    server_t *s = g_hash_table_lookup(netmap, &laddr);
    g_assert(s);

    hkey = (gpointer)ADDRESS_PORT(local_addr);
    g_hash_table_insert(s->connections, hkey, client_nfd);

    char addrbuf[INET6_ADDRSTRLEN];
    printf("new peer: %s:%u\n",
        ADDRESS_STRING(local_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(local_addr)));

    for (;;) {
        struct packet_s *p = g_slice_new0(struct packet_s);
        ssize_t nr = st_read(client_nfd, p->buf, sizeof(p->buf), ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
        /* TODO: maybe don't do think  translation every time through the loop. could just be a memcpy */
        if (!g_hash_table_lookup(s->connections, hkey)) {
            /* connection missing from hash, probably got close packet from tunnel */
            g_slice_free(struct packet_s, p);
            break;
        }
        address_to_addr(&local_addr, &p->hdr.laddr);
        memcpy(&p->hdr.raddr, &s->remote_addr, sizeof(addr_t));
        p->hdr.size = nr;
        queue_push_notify(s->write_fd, s->write_queue, p);
    }
    printf("closing peer\n");
    if (g_hash_table_remove(s->connections, hkey)) {
        /* push empty packet to notify remote end of close */
        struct packet_s *p = g_slice_new0(struct packet_s);
        address_to_addr(&local_addr, &p->hdr.laddr);
        memcpy(&p->hdr.raddr, &s->remote_addr, sizeof(addr_t));
        p->hdr.flags |= TUN_FLAG_CLOSE;
        queue_push_notify(s->write_fd, s->write_queue, p);
    } else {
        printf("peer connection not found. must have been closed already.\n");
    }
    st_netfd_close(client_nfd);
    return NULL;
}

static void *tunnel_thread(void *arg) {
    server_t *s = (server_t *)arg;
    st_init();

    address_t rmt_addr;
    int sock;
    st_netfd_t rmt_nfd;

    addr_to_address(&s->tunnel_addr, &rmt_addr);

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
    pds[1].fd = s->read_fd;
    pds[1].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        pds[1].revents = 0;
        if (st_poll(pds, 2, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("data to be read from tunnel\n");
            struct packet_s *p = g_slice_new(struct packet_s);
            ssize_t nr = st_read_fully(rmt_nfd, p, PACKET_HEADER_SIZE, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            nr = st_read_fully(rmt_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
            printf("tunnel master read %zd out of %d\n", nr, p->hdr.size);
            if (nr != p->hdr.size) { g_slice_free(struct packet_s, p); break; }
            queue_push_notify(s->read_fd, s->read_queue, p);
        }

        if (pds[1].revents & POLLIN) {
            char tmp[1];
            read(s->read_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(s->write_queue))) {
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
}

static st_thread_t listen_server(server_t *s, void *(*start)(void *arg)) {
    int sock;
    int n;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
    }

    n = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0) {
        perror("setsockopt SO_REUSEADDR");
    }

    address_t serv_addr;
    addr_to_address(&s->listen_addr, &serv_addr);
    char addrbuf[INET6_ADDRSTRLEN];
    printf("binding listening socket to: %s:%u\n",
        ADDRESS_STRING(serv_addr, addrbuf, sizeof(addrbuf)),
        ntohs(ADDRESS_PORT(serv_addr)));

    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
    }

    if (listen(sock, 10) < 0) {
        perror("listen");
    }

    s->nfd = st_netfd_open_socket(sock);
    s->start = start;
    return st_thread_create(accept_loop, (void *)s, 0, 4 * 1024);
}

static void *write_sthread(void *arg) {
    server_t *s = (server_t *)arg;
    struct pollfd pds[1];
    pds[0].fd = s->write_fd;
    pds[0].events = POLLIN;
    for (;;) {
        pds[0].revents = 0;
        if (st_poll(pds, 1, ST_UTIME_NO_TIMEOUT) <= 0) break;

        if (pds[0].revents & POLLIN) {
            printf("read queue notified\n");
            char tmp[1];
            read(s->write_fd, tmp, 1);
            struct packet_s *p;
            char laddrbuf[INET6_ADDRSTRLEN];
            char raddrbuf[INET6_ADDRSTRLEN];
            while ((p = g_async_queue_try_pop(s->read_queue))) {
                printf("packet read queue local: %s:%u remote: %s:%u size: %u\n",
                    ADDR_STRING(p->hdr.laddr, laddrbuf, sizeof(laddrbuf)), ntohs(p->hdr.laddr.port),
                    ADDR_STRING(p->hdr.raddr, raddrbuf, sizeof(raddrbuf)), ntohs(p->hdr.raddr.port),
                    p->hdr.size);
                st_netfd_t client_nfd = g_hash_table_lookup(s->connections, (gpointer)p->hdr.laddr.port);
                if (p->hdr.flags & TUN_FLAG_CLOSE && client_nfd) {
                    printf("found peer client, disconnecting\n");
                    g_hash_table_remove(s->connections, (gpointer)p->hdr.laddr.port);
                } else if (client_nfd) {
                    printf("found peer client!\n");
                    ssize_t nw = st_write(client_nfd, p->buf, p->hdr.size, ST_UTIME_NO_TIMEOUT);
                    printf("%zd bytes written to client\n", nw);
                    if (nw <= 0) { printf("write failed\n"); }
                } else {
                    printf("peer client not found\n");
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

    gchar *tun_listen_address_str = g_key_file_get_value(kf, "tunnel", "listen_address", NULL);
    g_assert(tun_listen_address_str);
    if (strtoaddr(tun_listen_address_str, &tunnel_server->listen_addr) != 1) {
        printf("invalid address: %s\n", tun_listen_address_str);
    }
    g_free(tun_listen_address_str);

    gchar **groups = g_key_file_get_groups(kf, NULL);
    gchar *group = NULL;
    for (int i = 0; (group = groups[i]); i++) {
        printf("group: %s\n", group);
        /* if group name starts with route, setup route */
        if (g_strstr_len(group, -1, "route") == group) {
            printf("route config found: %s\n", group);
            gchar *listen_address_str = g_key_file_get_value(kf, group, "listen_address", NULL);
            gchar *remote_address_str = g_key_file_get_value(kf, group, "remote_address", NULL);
            gchar *tunnel_address_str = g_key_file_get_value(kf, group, "tunnel_address", NULL);
            if (!listen_address_str || !remote_address_str || !tunnel_address_str) continue;
            server_t *s = g_slice_new0(server_t);
            /* TODO: leaks memory on error */
            if (strtoaddr(listen_address_str, &s->listen_addr) != 1) {
                printf("invalid address: %s\n", listen_address_str);
                continue;
            }
            if (strtoaddr(remote_address_str, &s->remote_addr) != 1) {
                printf("invalid address: %s\n", remote_address_str);
                continue;
            }
            if (strtoaddr(tunnel_address_str, &s->tunnel_addr) != 1) {
                printf("invalid address: %s\n", tunnel_address_str);
                continue;
            }
            char addrbuf[INET6_ADDRSTRLEN];
            printf("listening address: %s:%u\n",
                ADDR_STRING(s->listen_addr, addrbuf, sizeof(addrbuf)),
                ntohs(s->listen_addr.port));
            printf("remote address: %s:%u\n",
                ADDR_STRING(s->remote_addr, addrbuf, sizeof(addrbuf)),
                ntohs(s->remote_addr.port));
            g_hash_table_insert(netmap, &s->listen_addr, s);
            g_free(listen_address_str);
            g_free(remote_address_str);
            g_free(tunnel_address_str);
        }
    }
    g_free(start_group);
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

    int sockets[2];
    int status;

    netmap = g_hash_table_new(g_int_hash, addr_match);

    /* start tunnel listener */
    tunnel_server = g_slice_new0(server_t);
    status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    g_assert(status ==  0);
    tunnel_server->write_fd = sockets[0];
    tunnel_server->read_fd = sockets[1];
    tunnel_server->read_queue = g_async_queue_new_full(packet_free);
    tunnel_server->write_queue = g_async_queue_new_full(packet_free);
    tunnel_server->connections = g_hash_table_new(g_int_hash, addr_match);

    parse_config();

    /* TODO: should require a mode and either be a tunnel listener or connector */
    tunnel_server->listen_sthread = listen_server(tunnel_server, tunnel_handler);
    g_thread_create(tunnel_out_thread, NULL, TRUE, NULL);

    /* start port listeners */
    GHashTableIter iter;
    addr_t *listen_addr;
    server_t *s;
    g_hash_table_iter_init(&iter, netmap);
    while (g_hash_table_iter_next(&iter, (gpointer *)&listen_addr, (gpointer *)&s)) {
        status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
        g_assert(status ==  0);
        s->write_fd = sockets[0];
        s->read_fd = sockets[1];
        s->read_queue = g_async_queue_new_full(packet_free);
        s->write_queue = g_async_queue_new_full(packet_free);
        s->connections = g_hash_table_new(g_direct_hash, g_direct_equal);
        s->listen_sthread = listen_server(s, handle_connection);
        s->write_sthread = st_thread_create(write_sthread, s, 0, 4*1024);
        g_thread_create(tunnel_thread, s, TRUE, NULL);
    }

    st_thread_join(tunnel_server->listen_sthread, NULL);

    st_thread_exit(NULL);
    g_warn_if_reached();
    return EXIT_FAILURE;
}
