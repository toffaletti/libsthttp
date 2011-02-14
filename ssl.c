#include <openssl/ssl.h>
#include <openssl/err.h>
#include "st.h"
#include <arpa/inet.h>

static int netfd_write(BIO *b, const char *buf, int num);
static int netfd_read(BIO *b, char *buf, int size);
static int netfd_puts(BIO *b, const char *str);
static long netfd_ctrl(BIO *b, int cmd, long num, void *ptr);
static int netfd_new(BIO *b);
static int netfd_free(BIO *b);
int BIO_netfd_should_retry(int s);

static BIO_METHOD methods_st = {
    /*BIO_TYPE_FD,*/
    BIO_TYPE_SOCKET,
    "state threads netfd",
    netfd_write,
    netfd_read,
    netfd_puts,
    NULL, /* gets() */
    netfd_ctrl,
    netfd_new,
    netfd_free,
    NULL,
};

BIO_METHOD *BIO_s_netfd(void) {
    return (&methods_st);
}

BIO *BIO_new_netfd(int fd, int close_flag) {
    BIO *ret = BIO_new(BIO_s_netfd());
    if (ret == NULL) return NULL;
    BIO_set_fd(ret, fd, close_flag);
    return ret;
}

static int netfd_new(BIO *b) {
    b->init = 0;
    b->num = 0;
    b->ptr = NULL;
    b->flags = 0;
    return 1;
}

static int netfd_free(BIO *b) {
    if (b == NULL) return 0;
    if (b->ptr) {
        if (b->shutdown) {
            st_netfd_close(b->ptr);
        } else {
            st_netfd_free(b->ptr);
        }
    }
    b->ptr = NULL;
    return 1;
}

static int netfd_write(BIO *b, const char *buf, int num) {
    return st_write(b->ptr, buf, num, ST_UTIME_NO_TIMEOUT);
}

static int netfd_read(BIO *b, char *buf, int size) {
    return st_read_fully(b->ptr, buf, size, ST_UTIME_NO_TIMEOUT);
}

static int netfd_puts(BIO *b, const char *str) {
    size_t n = strlen(str);
    return st_write(b->ptr, str, n, ST_UTIME_NO_TIMEOUT);
}

static long netfd_ctrl(BIO *b, int cmd, long num, void *ptr) {
    long ret = 1;
    int *ip;
    switch (cmd) {
        case BIO_C_SET_FD:
            netfd_free(b);
            b->num = *((int *)ptr);
            b->shutdown = (int)num;
            b->init = 1;
            b->ptr = st_netfd_open(b->num);
            break;
        case BIO_C_GET_FD:
            if (b->init) {
                ip = (int *)ptr;
                if (ip) *ip=b->num;
                ret = b->num;
            } else {
                ret = -1;
            }
            break;
        case BIO_C_GET_FILE_PTR:
            if (b->init) {
                *((st_netfd_t *)ptr) = b->ptr;
            } else {
                ret = -1;
            }
            break;
        case BIO_CTRL_GET_CLOSE:
            ret = b->shutdown;
            break;
        case BIO_CTRL_SET_CLOSE:
            b->shutdown = (int)num;
            break;
        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}


int main(int argc, char *argv[]) {
    st_init();
    SSL_load_error_strings();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    int sock;
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        abort();
    }

    BIO *ssl_bio = BIO_new_ssl(ctx, 1);
    BIO *nfd_bio = BIO_new_netfd(sock, 1);
    BIO *bio = BIO_push(ssl_bio, nfd_bio);

    SSL *ssl = NULL;
    BIO_get_ssl(ssl_bio, &ssl);
    if (!ssl) {
        abort();
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    st_netfd_t nfd;
    BIO_get_fp(bio, &nfd);

    struct sockaddr_in addr;
    // www.google.com
    inet_pton(AF_INET, "74.125.224.48", &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    //BIO_set_conn_hostname(bio, "www.google.com:https");

    if (st_connect(nfd, (struct sockaddr *)&addr, sizeof(addr), ST_UTIME_NO_TIMEOUT) < 0) {
        abort();
    }

    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);
        abort();
    }

    char tmpbuf[1024];
    BIO_puts(bio, "GET / HTTP/1.0\r\nHost: encrypted.google.com\r\n\r\n");
    int len;
    for(;;) {
        len = BIO_read(bio, tmpbuf, 1024);
        if(len <= 0) break;
        fwrite(tmpbuf, sizeof(char), len, stdout);
    }

    BIO_free_all(bio);

    return 0;
}
