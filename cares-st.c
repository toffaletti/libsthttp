#include "st.h"
#include <ares.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* deep copy hostent struct. memory allocation scheme
 * borrowed from ares_free_hostent.
 */
void copy_hostent(struct hostent *from, struct hostent **to) {
  *to = calloc(1, sizeof(struct hostent));
  (*to)->h_name = strdup(from->h_name);
  int n = 0;
  while (from->h_aliases && from->h_aliases[n]) {
    n++;
  }
  (*to)->h_aliases = calloc(n+1, sizeof(char *));
  while (n) {
    (*to)->h_aliases[n] = strdup(from->h_aliases[n]);
    n--;
  }
  (*to)->h_addrtype = from->h_addrtype;
  n = 0;
  while (from->h_addr_list && from->h_addr_list[n]) {
    n++;
  }
  (*to)->h_length = from->h_length;
  (*to)->h_addr_list = calloc(n+1, sizeof(char *));
  (*to)->h_addr_list[0] = calloc(n, from->h_length);
  memcpy((*to)->h_addr_list[0], from->h_addr_list[0], n*from->h_length);
  while (n > 1) {
    n--;
    (*to)->h_addr_list[n] = (*to)->h_addr_list[0] + (n * from->h_length);
  }
}

/* convert read and write fd_set to pollfd
 * max_fd pollfds will be malloced and returned in fds_p
 * actual number of fds will be returned in nfds;
 */
void fd_sets_to_pollfd(fd_set *read_fds, fd_set *write_fds, int max_fd, struct pollfd **fds_p, int *nfds) {
  /* using max_fd is over allocating */
  struct pollfd *fds = calloc(max_fd, sizeof(struct pollfd));
  int ifd = 0;
  for (int fd = 0; fd<max_fd; fd++) {
    fds[ifd].fd = fd;
    if (FD_ISSET(fd, read_fds)) {
      fds[ifd].events |= POLLIN;
    }
    if (FD_ISSET(fd, write_fds)) {
      fds[ifd].events |= POLLOUT;
    }
    /* only increment the fd index if it exists in the fd sets */
    if (fds[ifd].events != 0) {
      ifd++;
    }
  }
  *fds_p = fds;
  *nfds = ifd;
}

/* convert pollfd to read and write fd_sets */
void pollfd_to_fd_sets(struct pollfd *fds, int nfds, fd_set *read_fds, fd_set *write_fds) {
  FD_ZERO(read_fds);
  FD_ZERO(write_fds);
  for (int i = 0; i<nfds; i++) {
    if (fds[i].revents & POLLIN) {
      FD_SET(fds[i].fd, read_fds);
    }
    if (fds[i].revents & POLLOUT) {
      FD_SET(fds[i].fd, write_fds);
    }
  }
}

static void callback(void *arg, int status, int timeouts, struct hostent *host) {
  struct hostent **_host = (struct hostent **)arg;

  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "%s\n", ares_strerror(status));
    return;
  }

  copy_hostent(host, _host);
}

void *do_lookup(void *arg) {
  ares_channel channel;
  int status;

  status = ares_init(&channel);
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ares_init: %s\n", ares_strerror(status));
    return (void*)1;
  }

  struct hostent *host;
  ares_gethostbyname(channel, "google.com", AF_INET, callback, &host);

  fd_set read_fds, write_fds;
  struct timeval *tvp, tv;
  int max_fd, nfds;
  for (;;)
  {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    max_fd = ares_fds(channel, &read_fds, &write_fds);
    printf("max_fd: %u\n", max_fd);
    if (max_fd == 0)
      break;

    struct pollfd *fds;
    fd_sets_to_pollfd(&read_fds, &write_fds, max_fd, &fds, &nfds);
    tvp = ares_timeout(channel, NULL, &tv);
    //select(nfds, &read_fds, &write_fds, NULL, tvp);
    // TODO: get timeout working
    if (st_poll(fds, nfds, ST_UTIME_NO_TIMEOUT) == -1) {
      fprintf(stderr, "poll error\n");
      break;
    }
    pollfd_to_fd_sets(fds, nfds, &read_fds, &write_fds);
    free(fds);
    ares_process(channel, &read_fds, &write_fds);
  }

  char **p = NULL;
  for (p = host->h_addr_list; *p; p++)
  {
    char addr_buf[46] = "??";
    inet_ntop(host->h_addrtype, *p, addr_buf, sizeof(addr_buf));
    printf("%-32s\t%s", host->h_name, addr_buf);
    puts("");
  }

  ares_free_hostent(host);

  ares_destroy(channel);
  return NULL;
}

int main(int argc, char *argv[]) {
  int status;
  st_init();
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    return 1;
  }

  st_thread_t t = st_thread_create(do_lookup, NULL, 1, 1024 * 128);
  st_thread_t t2 = st_thread_create(do_lookup, NULL, 1, 1024 * 128);
  st_thread_join(t, NULL);
  st_thread_join(t2, NULL);

  ares_library_cleanup();
  return 0;
}