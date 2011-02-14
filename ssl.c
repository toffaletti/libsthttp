#include <openssl/ssl.h>
#include "st.h"

static int netfd_write(BIO *b, const char *buf, int num);
static int netfd_read(BIO *b, char *buf, int size);
static int netfd_puts(BIO *b, const char *str);
static long netfd_ctrl(BIO *b, int cmd, long num, void *ptr);
static int netfd_new(BIO *b);
static int netfd_free(BIO *b);
int BIO_netfd_should_retry(int s);

static BIO_METHOD methods_st = {
    BIO_TYPE_FD,
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
    return 0;
}
