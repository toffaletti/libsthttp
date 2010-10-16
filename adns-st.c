#include "st.h"
#include <adns.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static adns_state adns;

void type_info(adns_rrtype type, const char **typename_r,
                          const void *datap, char **data_r) {
  static char buf[12];
  adns_status st;

  st= adns_rr_info(type, typename_r, 0,0, datap,data_r);
  if (typename_r && !*typename_r) {
    sprintf(buf,"TYPE%d", (int)(type & adns_rrt_typemask));
    *typename_r= buf;
  }
}

void *do_lookup(void *arg) {
  adns_query query;
  adns_answer *answer = NULL;
  int status = 0;
  status = adns_submit(adns, "google.com", adns_r_addr,
    adns_qf_quoteok_cname|adns_qf_cname_loose,
    NULL, &query);
  if (status != 0) {
    fprintf(stderr, "adns_submit error\n");
  }

  for (;;) {
    int nfds_io = 0;
    status = adns_beforepoll(adns, NULL, &nfds_io, NULL, NULL);
    if (status != ERANGE) {
      fprintf(stderr, "error getting nfds\n");
    }
    printf("nfds_io: %d\n", nfds_io);
    struct pollfd *fds = calloc(nfds_io, sizeof(struct pollfd));
    status = adns_beforepoll(adns, fds, &nfds_io, NULL, NULL);

    for (int i = 0; i < nfds_io; i++) {
      printf("poll fd: %u events: %u revents: %u\n",
        fds[i].fd, fds[i].events, fds[i].revents);
    }

    if (st_poll(fds, nfds_io, ST_UTIME_NO_TIMEOUT) == -1) {
      fprintf(stderr, "poll error\n");
    }

    for (int i = 0; i < nfds_io; i++) {
      printf("poll fd: %u events: %u revents: %u\n",
        fds[i].fd, fds[i].events, fds[i].revents);
    }

    adns_afterpoll(adns, fds, nfds_io, NULL);

    free(fds);

    status = adns_check(adns, &query, &answer, NULL);
    fprintf(stderr, "adns_check: %d\n", status);
    if (status == adns_s_ok && answer) {
      adns_status st;
      int rrn, nrrs;
      const char *rrp, *realowner, *typename;
      char *datastr;

      st= answer->status;
      nrrs= answer->nrrs;

      if (nrrs) {
        for (rrn=0, rrp = answer->rrs.untyped; rrn < nrrs;
                               rrn++, rrp += answer->rrsz)
        {
          type_info(answer->type,&typename, rrp,&datastr);
          printf("%s\n",datastr);
          free(datastr);
        }
      }
      fflush(stdout);
      free(answer);
      /*fprintf(stderr, "answer status: %d ip: %s\n",
        answer->status, inet_ntoa(answer[0].rrs.addr->addr.inet.sin_addr));*/
      break;
    }

  }

  return NULL;
}

int main(int argc, char *argv[]) {
  st_init();
  adns_init(&adns, adns_if_debug, 0);

  st_thread_t t = st_thread_create(do_lookup, NULL, 1, 1024 * 128);
  st_thread_t t2 = st_thread_create(do_lookup, NULL, 1, 1024 * 128);
  st_thread_join(t, NULL);
  st_thread_join(t2, NULL);

  adns_finish(adns);
  return 0;
}