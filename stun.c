#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "st.h"

struct packet_s {
    /* listening addr */
    u_int32_t laddr;
    u_int16_t lport;
    /* remote addr */
    u_int32_t raddr;
    u_int16_t rport;
    /* packet size and data */
    u_int16_t size;
    char buf[4*1024];
} __attribute__((__packed__));

static GHashTable *connections;
/* verbs read and write here refer to the actions taken on the tunnel socket */
static GAsyncQueue *read_packet_queue;
static GAsyncQueue *write_packet_queue;
static int tun_read_fd; /* used to notify when tunnel has read */
static int tun_write_fd; /* used to notify when tunnel needs write */

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
    for (;;) {
        char buf[8 * 1024];
        ssize_t nr = st_read(client_nfd, buf, sizeof(buf), ST_UTIME_NO_TIMEOUT);
        printf("read %zd bytes\n", nr);
        if (nr <= 0) break;
        st_sleep(2);
        st_write(client_nfd, buf, nr, ST_UTIME_NO_TIMEOUT);
    }
    st_netfd_close(client_nfd);
    return NULL;
}

static void *handle_connection(void *arg) {
    st_netfd_t client_nfd = (st_netfd_t)arg;
    struct sockaddr listening_addr;
    struct sockaddr remote_addr;
    socklen_t slen;
    int status;
    gpointer hkey;

    slen = sizeof(listening_addr);
    status = getsockname(st_netfd_fileno(client_nfd), &listening_addr, &slen);
    g_assert(status == 0);
    slen = sizeof(remote_addr);
    status = getpeername(st_netfd_fileno(client_nfd), &remote_addr, &slen);
    g_assert(status == 0);

    hkey = (gpointer)((struct sockaddr_in *)&remote_addr)->sin_port;
    g_hash_table_insert(connections, hkey, client_nfd);

    printf("new peer: %s:%u\n",
        inet_ntoa(((struct sockaddr_in *)&remote_addr)->sin_addr),
       ((struct sockaddr_in *)&remote_addr)->sin_port);

    for (;;) {
        struct packet_s *p = g_slice_new(struct packet_s);
        ssize_t nr = st_read(client_nfd, p->buf, sizeof(p->buf), ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
        p->laddr = ((struct sockaddr_in *)&listening_addr)->sin_addr.s_addr;
        p->lport = ((struct sockaddr_in *)&listening_addr)->sin_port;
        p->raddr = ((struct sockaddr_in *)&remote_addr)->sin_addr.s_addr;
        p->rport = ((struct sockaddr_in *)&remote_addr)->sin_port;
        p->size = nr;
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

    struct sockaddr_in rmt_addr;
    int sock;
    st_netfd_t rmt_nfd;

    memset(&rmt_addr, 0, sizeof(rmt_addr));
    rmt_addr.sin_family = AF_INET;
    rmt_addr.sin_port = htons(9001);
    inet_aton("127.0.0.1", &rmt_addr.sin_addr);

    /* Connect to remote host */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
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
            ssize_t nr = st_read(rmt_nfd, p, 18, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            nr = st_read(rmt_nfd, p->buf, p->size, ST_UTIME_NO_TIMEOUT);
            if (nr <= 0) { g_slice_free(struct packet_s, p); break; }
            queue_push_notify(tun_read_fd, read_packet_queue, p);
        }

        if (pds[1].revents & POLLIN) {
            char tmp[1];
            read(tun_read_fd, tmp, 1);
            struct packet_s *p;
            while ((p = g_async_queue_try_pop(write_packet_queue))) {
                printf("packet local: %s:%u remote: %s:%u size: %u\n",
                    inet_ntoa(*((struct in_addr *)&p->laddr)), ntohs(p->lport),
                    inet_ntoa(*((struct in_addr *)&p->raddr)), ntohs(p->rport),
                    p->size);
                ssize_t nw = st_write(rmt_nfd, p, 18+p->size, ST_UTIME_NO_TIMEOUT);
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
            while ((p = g_async_queue_try_pop(read_packet_queue))) {
                printf("packet read queue local: %s:%u remote: %s:%u size: %u\n",
                    inet_ntoa(*((struct in_addr *)&p->laddr)), ntohs(p->lport),
                    inet_ntoa(*((struct in_addr *)&p->raddr)), ntohs(p->rport),
                    p->size);
                st_netfd_t client_nfd = g_hash_table_lookup(connections, (gpointer)p->rport);
                if (client_nfd) {
                    printf("found client!\n");
                    ssize_t nw = st_write(client_nfd, p->buf, p->size, ST_UTIME_NO_TIMEOUT);
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

int main(int argc, char *argv[]) {
    g_thread_init(NULL);

    if (st_init() < 0) {
        perror("st_init");
        exit(1);
    }

    int sockets[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    tun_write_fd = sockets[0];
    tun_read_fd = sockets[1];

    read_packet_queue = g_async_queue_new_full(packet_free);
    write_packet_queue = g_async_queue_new_full(packet_free);
    connections = g_hash_table_new(g_direct_hash, g_direct_equal);

    g_thread_create(tunnel_thread, NULL, TRUE, NULL);
    st_thread_create(write_sthread, NULL, 0, 4*1024);

    st_thread_t t1 = listen_server(9000, handle_connection);
    st_thread_t t2 = listen_server(9001, tunnel_handler);
    st_thread_join(t1, NULL);
    st_thread_join(t2, NULL);

    st_thread_exit(NULL);
    g_warn_if_reached();
    return EXIT_FAILURE;
}
