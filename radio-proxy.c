#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <signal.h>
#include "err.h"


#define UNUSED(x) (void)(x)

#define ADDRLEN 15
#define DEFAULT_TIMEOUT 5
#define BUF_SIZE 512
#define MAX_RADIO_NAME 255

#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6


static int radio_proxy_exit_code = EXIT_SUCCESS;


typedef struct client_elem {
  struct timeval last_seen;
  struct sockaddr_in *addr;
  struct client_elem *next;
  struct client_elem *prev;
} client_elem;

typedef struct clients_list {
  struct timeval timeout;
  size_t len;
  client_elem *head;
  client_elem *last;
} clients_list;


clients_list *clist_create(struct timeval);
void clist_push(clients_list *, struct sockaddr_in *);
void clist_pop(clients_list *, client_elem *);
void clist_refresh(clients_list *);
client_elem *clist_find(const clients_list *, struct sockaddr_in *);
void clist_stream(const clients_list *, evutil_socket_t, const unsigned char [], size_t, uint16_t);
void clist_free(clients_list *);


void get_parameters(int, char *[], char *[], char *[], char *[], bool *, struct timeval *,
		    char *[], char *[], struct timeval *);
bool cmp_header_key(char *, size_t, char *, size_t);


void radio_event_cb(struct bufferevent *, short, void *);
void radio_read_response_line_cb(struct bufferevent *, void *);
void radio_read_headers_cb(struct bufferevent *, void *);
void radio_read_data_only_cb(struct bufferevent *, void *);
void radio_read_data_cb(struct bufferevent *, void *);
void radio_read_metadata_cb(struct bufferevent *, void *);
struct buffer_arg {
  bool metadata;
  size_t metaint;
  bool isproxy;
  evutil_socket_t proxy_sock;
  char *radio_name;
  clients_list *clist;
  struct event_base *base;
};


void proxy_listen_cb(evutil_socket_t, short, void *);
struct proxy_listen_arg {
  struct timeval proxy_timeout;
  char *radio_name;
  clients_list *clist;
  struct event_base *base;
};

void proxy_iam_cb(evutil_socket_t, short, void *);
struct proxy_iam_arg {
  struct timeval proxy_timeout;
  struct sockaddr_in *addr;
  char *radio_name;
  clients_list *clist;
  struct event_base *base;
};


void sigint_cb(evutil_socket_t, short, void *);


int main(int argc, char *argv[]) {
  char *host, *resource, *radio_port, *proxy_port, *multi;
  bool metadata;
  struct timeval radio_timeout, proxy_timeout;

  get_parameters(argc, argv, &host, &resource, &radio_port, &metadata, &radio_timeout,
		 &proxy_port, &multi, &proxy_timeout);

  struct event_base *base = event_base_new();
  if (!base) syserr("event_base_new");

  evutil_socket_t proxy_sock = 0;
  struct sockaddr_in sin = {0};
  struct event *listen_event = NULL;
  char radio_name[MAX_RADIO_NAME + 1]= {0};
  clients_list *clist = clist_create(proxy_timeout);
  struct proxy_listen_arg *listen_arg = NULL;
  struct ip_mreq ip_mreq;
  
  if (proxy_port) {
    proxy_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (proxy_sock < 0)
      syserr("socket");
    if (evutil_make_listen_socket_reuseable(proxy_sock))
      syserr("evutil_make_listen_socket_reuseable");
    if(evutil_make_socket_nonblocking(proxy_sock))
      syserr("evutil_make_socket_nonblocking");

    if (multi) {
      ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      if (inet_aton(multi, &ip_mreq.imr_multiaddr) == 0)	  
	syserr("inet_aton");
      
      if (setsockopt(proxy_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
	syserr("setsockopt");
    }
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(atoi(proxy_port));
    if (bind(proxy_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
      syserr("bind");

    
    listen_arg = malloc(sizeof(struct proxy_listen_arg));
    listen_arg->proxy_timeout = proxy_timeout;
    listen_arg->radio_name = radio_name;
    listen_arg->clist = clist;
    listen_arg->base = base;
    
    listen_event = event_new(base, proxy_sock, EV_READ|EV_TIMEOUT|EV_PERSIST, proxy_listen_cb, (void *) listen_arg);
    if (!listen_event) syserr("event_new");
    
    if (event_add(listen_event, &proxy_timeout) < 0) syserr("event_add");
  }
  
  struct buffer_arg *buffer_arg = malloc(sizeof(struct buffer_arg));
  buffer_arg->metadata = metadata;
  buffer_arg->metaint = 0;
  buffer_arg->isproxy = proxy_port != NULL;
  buffer_arg->proxy_sock = proxy_sock;
  buffer_arg->radio_name = radio_name;
  buffer_arg->clist = clist;
  buffer_arg->base = base;

  struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!bev) syserr("bufferevent_socket_new");

  bufferevent_setcb(bev, NULL, NULL, radio_event_cb, buffer_arg);
  bufferevent_set_timeouts(bev, &radio_timeout, NULL);

  struct addrinfo addr_hints = {0};
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;
  
  struct addrinfo *addr_results;
  if (getaddrinfo(host, radio_port, &addr_hints, &addr_results)) syserr("getaddrinfo");

  if (bufferevent_socket_connect(bev, addr_results->ai_addr, addr_results->ai_addrlen) == -1)
    syserr("bufferevent_socket_connect");

  freeaddrinfo(addr_results);

  if (evbuffer_add_printf(bufferevent_get_output(bev),
			  "GET %s HTTP/1.0\r\n"
			  "Host:%s\r\n"
			  "%s"
			  "\r\n",
			  resource, host, metadata? "Icy-MetaData:1\r\n" : "") < 0)
    syserr("evbuffer_add_printf");
  
  struct event *sigint_event = evsignal_new(base, SIGINT, sigint_cb, (void *) base);
  if (!sigint_event || evsignal_add(sigint_event, NULL) < 0)
    syserr("Could not create SIGINT event.");
  
  if (event_base_dispatch(base) < 0) syserr("event_base_dispatch");

  clist_free(clist);
  event_free(sigint_event);
  
  free(buffer_arg);
  bufferevent_free(bev);
  
  if (proxy_port) {
    free(listen_arg);
    event_free(listen_event);
    if (multi) {
      if (setsockopt(proxy_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        syserr("setsockopt");
    }
    if (close(proxy_sock) < 0)
      syserr("close");
  }

  event_base_free(base);
  
  return radio_proxy_exit_code;
}


void get_parameters(int argc, char *argv[], char *host[], char *resource[], char *radio_port[], bool *metadata, struct timeval *radio_timeout, char *proxy_port[], char *multi[], struct timeval *proxy_timeout) {
  *host = NULL;
  *resource = NULL;
  *radio_port = NULL;
  *metadata = false;
  radio_timeout->tv_sec = DEFAULT_TIMEOUT;
  radio_timeout->tv_usec = 0;
  
  *proxy_port = NULL;
  *multi = NULL;
  proxy_timeout->tv_sec = DEFAULT_TIMEOUT;

  int to;
  int opt;
  while ((opt = getopt(argc, argv, ":h:r:p:m:t:P:B:T:")) != -1) {
    switch (opt) {
    case 'h':
      *host = optarg;
      break;
    case 'r':
      *resource = optarg;
      break;
    case 'p':
      *radio_port = optarg;
      break;
    case 'm':
      if (strcmp(optarg, "no") == 0)
	*metadata = false;
      else if (strcmp(optarg, "yes") == 0)
	*metadata = true;
      else
	fatal("incorrect option argument -- 'm'");
      break;
    case 't':
      to = atoi(optarg);
      if (to <= 0)
	fatal("incorrect option argument -- 't'");
      radio_timeout->tv_sec = (time_t) to;
      break;
    case 'P':
      *proxy_port = optarg;
      break;
    case 'B':
      *multi = optarg;
      break;
    case 'T':
      to = atoi(optarg);
      if (to <= 0)
	fatal("incorrect option argument -- 'T'");
      proxy_timeout->tv_sec = (time_t) to;
      break;
    case ':':
      fatal("option requires an argument -- '%c'", optopt);
      break;
    case '?':
      fatal("unknown option: %c", optopt);
      break;  
    }
  }

  if (*host == NULL)
    fatal("missing required option -- 'h'");
  if (*resource == NULL)
    fatal("missing required option -- 'r'");
  if (*radio_port == NULL)
    fatal("missing required option -- 'p'");
}


void radio_event_cb(struct bufferevent *bev, short what, void *raw_arg) {
  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;
  
  if (what & BEV_EVENT_ERROR) {
    syserr_event(arg->base, &radio_proxy_exit_code, "bufferevent");
    return;
  }
  
  if (what & BEV_EVENT_CONNECTED) {
    bufferevent_setcb(bev, radio_read_response_line_cb, NULL, radio_event_cb, raw_arg);
    bufferevent_enable(bev, EV_READ);
    return;
  }

  if (what & BEV_EVENT_TIMEOUT) {
    fatal_event(arg->base, &radio_proxy_exit_code, "A timeout occured.");
    return;
  }
  
  if (what & BEV_EVENT_EOF)
    fprintf(stderr, "EOF encountered.\n");
  
  if (event_base_loopexit(arg->base, NULL) == -1)
    syserr("event_base_loopexit");
}


void radio_read_response_line_cb(struct bufferevent *bev, void *raw_arg) {
  struct evbuffer *buf = bufferevent_get_input(bev);

  size_t len;
  char *response_line = evbuffer_readln(buf, &len, EVBUFFER_EOL_CRLF);
  if (!response_line) {
    fprintf(stderr, "The first line has not arrived yet.\n");
    return;
  }

  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;

  size_t i = 0;
  if (!strncmp(response_line, "ICY ", 4)) {
    i += 4;
  } else if (!strncmp(response_line, "HTTP/1.", 7) &&
	     (!strncmp(response_line + 7, "0 ", 2) ||
	      !strncmp(response_line + 7, "1 ", 2))) {
    i += 9;
  } else {
    fatal_event(arg->base, &radio_proxy_exit_code, "Unexpected response line -- %s\n", response_line);
    return;
  }

  if (!strncmp(response_line + i, "200", 3)) {
    free(response_line);
    bufferevent_setcb(bev, radio_read_headers_cb, NULL, radio_event_cb, raw_arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_headers_cb(bev, raw_arg);
  } else {
    fprintf(stderr, "ERROR: Unexpected response code -- %s\n", response_line + i);
    radio_proxy_exit_code = EXIT_FAILURE;
    free(response_line);
    if (event_base_loopbreak(arg->base) == -1)
      syserr("event_base_loopbreak");
  }
}


bool cmp_header_key(char *header_line, size_t len, char *key, size_t klen) {
  size_t i;
  for (i = 0; i < len && header_line[i] != ':'; ++i)
    header_line[i] = tolower(header_line[i]);
  return klen < len && strncmp(header_line, key, klen) == 0 && header_line[klen] == ':';
}


void radio_read_headers_cb(struct bufferevent *bev, void *raw_arg) {
  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;
  struct evbuffer *buf = bufferevent_get_input(bev);

  size_t len;
  char *header_line;
  while ((header_line = evbuffer_readln(buf, &len, EVBUFFER_EOL_CRLF)) && len > 0) {
    if (cmp_header_key(header_line, len, "icy-metaint", 11)) {
      if (!arg->metadata) {
	fatal_event(arg->base, &radio_proxy_exit_code, "Unexpected icy-metaint header.");
	return;
      }
      char *endptr;
      errno = 0;
      uintmax_t val = strtoumax(header_line + 12, &endptr, 10);
      if (endptr == header_line + 12 || *endptr != '\0'
	  || (errno == ERANGE && val == UINTMAX_MAX) || (errno != 0 && val == 0)) {
	fatal_event(arg->base, &radio_proxy_exit_code, "Could not parse received icy-metaint value.");
	return;
      }
      if (val == 0) {
        fatal_event(arg->base, &radio_proxy_exit_code, "Incorrect icy-metaint value.");
	return;
      }
      arg->metaint = (size_t) val;
    } else if (cmp_header_key(header_line, len, "icy-name", 8)) {
      strncpy(arg->radio_name, header_line + 9, MAX_RADIO_NAME);
    }
  }
  
  if (header_line && len == 0) {
    if (arg->metadata && arg->metaint == 0)
      arg->metadata = 0;
    if (arg->metadata) {
      bufferevent_setcb(bev, radio_read_data_cb, NULL, radio_event_cb, raw_arg);
      if (evbuffer_get_length(bufferevent_get_input(bev)))
	radio_read_data_cb(bev, raw_arg);
    } else {
      bufferevent_setcb(bev, radio_read_data_only_cb, NULL, radio_event_cb, raw_arg);
      if (evbuffer_get_length(bufferevent_get_input(bev)))
	radio_read_data_only_cb(bev, raw_arg);
    }
  }
}


void radio_read_data_only_cb(struct bufferevent *bev, void *raw_arg) {
  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;
  unsigned char buf[BUF_SIZE];
  size_t r;
  while ((r = bufferevent_read(bev, buf, BUF_SIZE))) {
    if (arg->isproxy)
      clist_stream(arg->clist, arg->proxy_sock, buf, r, AUDIO);
    else
      fwrite(buf, 1, r, stdout);
  }
}


void radio_read_data_cb(struct bufferevent *bev, void *raw_arg) {
  static size_t counter = 0;

  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;
  unsigned char buf[BUF_SIZE];

  size_t remains = arg->metaint - counter;
  size_t r;
  while (remains > 0 && (r = bufferevent_read(bev, buf, remains < BUF_SIZE ? remains : BUF_SIZE))) {
    if (arg->isproxy)
      clist_stream(arg->clist, arg->proxy_sock, buf, r, AUDIO);
    else
      fwrite(buf, 1, r, stdout);
    counter += r;
    remains = arg->metaint - counter;
  }

  if (remains == 0) {
    counter = 0;
    bufferevent_setcb(bev, radio_read_metadata_cb, NULL, radio_event_cb, raw_arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_metadata_cb(bev, raw_arg);
  }
}


void radio_read_metadata_cb(struct bufferevent *bev, void *raw_arg) {
  static size_t counter = 0;
  static size_t len = 0;

  struct buffer_arg *arg = (struct buffer_arg *) raw_arg;
  
  char buf[BUF_SIZE + 1];

  if (len == 0) {
    bufferevent_read(bev, buf, 1);
    len = ((size_t) buf[0]) << 4;
  }

  size_t remains = len - counter;
  size_t r;
  while (remains > 0 && (r = bufferevent_read(bev, buf, remains < BUF_SIZE ? remains : BUF_SIZE))) {
    if (arg->isproxy) {
      clist_stream(arg->clist, arg->proxy_sock, (unsigned char *) buf, r, METADATA);
    } else {
      buf[r] = 0;
      fprintf(stderr, buf);
    }
    counter += r;
    remains = len - counter;
  }

  if (remains == 0) {
    counter = 0;
    len = 0;
    bufferevent_setcb(bev, radio_read_data_cb, NULL, radio_event_cb, raw_arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_data_cb(bev, raw_arg);
  }
}


void proxy_listen_cb(evutil_socket_t sock, short what, void *raw_arg) {
  struct proxy_listen_arg *arg = (struct proxy_listen_arg *) raw_arg;

  clist_refresh(arg->clist);

  if (what & EV_TIMEOUT)
    return;
  
  struct sockaddr_in *client_addr = malloc(sizeof(struct sockaddr_in));
  if (!client_addr) {
    syserr_event(arg->base, &radio_proxy_exit_code, "malloc");
    return;
  }
  
  socklen_t caddr_len = (socklen_t) sizeof(struct sockaddr_in);
  uint16_t mes[2];
  ssize_t len = recvfrom(sock, mes, 4, 0, (struct sockaddr *) client_addr, &caddr_len);
  
  if (len < 0) {
      syserr_event(arg->base, &radio_proxy_exit_code, "recvfrom");
      return;
  }

  char client_addr_str[ADDRLEN + 1];
  inet_ntop(AF_INET, &(client_addr->sin_addr), client_addr_str, ADDRLEN + 1);

  if (len < 4) {
    fprintf(stderr, "Ignoring message from %s:%d.\n", client_addr_str, ntohs(client_addr->sin_port));
  }

  mes[0] = ntohs(mes[0]);
  
  switch (mes[0]) {
  case DISCOVER:
    fprintf(stderr, "DISCOVER from %s:%d.\n", client_addr_str, ntohs(client_addr->sin_port));

    struct proxy_iam_arg *iam_arg = malloc(sizeof(struct proxy_iam_arg));
    if (!iam_arg) {
      syserr_event(arg->base, &radio_proxy_exit_code, "malloc");
      return;
    }
    
    iam_arg->proxy_timeout = arg->proxy_timeout;
    iam_arg->radio_name = arg->radio_name;
    iam_arg->clist = arg->clist;
    iam_arg->addr = client_addr;
    iam_arg->base = arg->base;

    if (event_base_once(arg->base, sock, EV_WRITE, proxy_iam_cb, (void *) iam_arg, NULL) < 0) {
      syserr_event(arg->base, &radio_proxy_exit_code, "event_base_once");
      return;
    }    
    break;
    
  case KEEPALIVE:
    fprintf(stderr, "KEEPALIVE from %s:%d.", client_addr_str, ntohs(client_addr->sin_port));

    client_elem *found = clist_find(arg->clist, client_addr);
    if (found)
      evutil_gettimeofday(&(found->last_seen), NULL);
    else    
      fprintf(stderr, " Unknown address - ignoring.");
    fprintf(stderr, "\n");
    free(client_addr);
    break;

  default:
    fprintf(stderr, "Ignoring message from %s:%d.\n", client_addr_str, ntohs(client_addr->sin_port));
  }
}


void proxy_iam_cb(evutil_socket_t sock, short what, void *raw_arg) {
  UNUSED(what);
  struct proxy_iam_arg *arg = (struct proxy_iam_arg *) raw_arg;

  socklen_t caddr_len = (socklen_t) sizeof(struct sockaddr_in);

  unsigned char buf[4 + MAX_RADIO_NAME];
  size_t radio_name_len = strnlen(arg->radio_name, MAX_RADIO_NAME);
  
  uint16_t type = htons(IAM);
  uint16_t length = htons((uint16_t) radio_name_len);
  memcpy(buf, &type, 2);
  memcpy(buf + 2, &length, 2);
  memcpy(buf + 4, arg->radio_name, radio_name_len);

  if (sendto(sock, buf, 4 + radio_name_len, 0, (struct sockaddr *) arg->addr, caddr_len) < 0)
    fprintf(stderr, "ERROR: %s\n", strerror(errno));

  client_elem *found = clist_find(arg->clist, arg->addr);
  if (found) {
    free(arg->addr);
    evutil_gettimeofday(&(found->last_seen), NULL);
  } else {
    clist_push(arg->clist, arg->addr);
  }
  
  free(arg);
  return;
}


void sigint_cb(evutil_socket_t desc, short what, void *raw_arg) {
  UNUSED(desc); UNUSED(what);
  struct event_base *base = (struct event_base *) raw_arg;
  if (event_base_loopexit(base, NULL) == -1)
    syserr("event_base_loopexit");
}


clients_list *clist_create(struct timeval timeout) {
  clients_list *clist = malloc(sizeof(clients_list));
  if (!clist) syserr("malloc");
  clist->timeout = timeout;
  clist->len = 0;
  clist->head = NULL;
  clist->last = NULL;
  return clist;
}


void clist_push(clients_list *clist, struct sockaddr_in *addr) {
  client_elem *celem = malloc(sizeof(client_elem));
  if (!celem) syserr("malloc");

  celem->addr = addr;
  evutil_gettimeofday(&(celem->last_seen), NULL);
  celem->next = NULL;

  if (clist->len != 0) {
    celem->prev = clist->last;
    clist->last->next = celem;
    clist->last = celem;
  } else {
    celem->prev = NULL;
    clist->last = celem;
    clist->head = celem;
  }
  ++(clist->len);
}


void clist_pop(clients_list *clist, client_elem *celem) {
  if (celem->prev)
    celem->prev->next = celem->next;
  else
    clist->head = celem->next;
  if (celem->next)
    celem->next->prev = celem->prev;
  else
    clist->last = celem->prev;
  free(celem->addr);
  free(celem);
  --(clist->len);
}


void clist_refresh(clients_list *clist) {
  struct timeval now, deadline;
  evutil_gettimeofday(&now, NULL);
  evutil_timersub(&now, &(clist->timeout), &deadline);
  for (client_elem *celem = clist->head; celem != NULL; celem = celem->next) {
    if (evutil_timercmp(&(celem->last_seen), &deadline, <)) {
      char client_addr_str[ADDRLEN + 1];
      inet_ntop(AF_INET, &(celem->addr->sin_addr), client_addr_str, ADDRLEN + 1);
      fprintf(stderr, "Timeout for %s:%d.\n", client_addr_str, ntohs(celem->addr->sin_port));
      clist_pop(clist, celem);
    }
  }
}


client_elem *clist_find(const clients_list *clist, struct sockaddr_in *addr) {
  for (client_elem *celem = clist->head; celem != NULL; celem = celem->next) {
    if (celem->addr->sin_port == addr->sin_port &&
	celem->addr->sin_addr.s_addr == addr->sin_addr.s_addr)
      return celem;
  }
  return NULL;
}


void clist_stream(const clients_list *clist, evutil_socket_t proxy_sock, const unsigned char buf[], size_t length, uint16_t type) {
  unsigned char mes[4 + BUF_SIZE];
  type = htons(type);
  memcpy(mes, &type, 2);
  uint16_t len = htons((uint16_t) length);
  memcpy(mes + 2, &len, 2);
  memcpy(mes + 4, buf, length);

  socklen_t caddr_len = (socklen_t) sizeof(struct sockaddr_in);


  for (client_elem *celem = clist->head; celem != NULL; celem = celem->next) {
    if (sendto(proxy_sock, mes, 4 + length, 0, (struct sockaddr *) celem->addr, caddr_len) < 0)
      fprintf(stderr, "ERROR: %s\n", strerror(errno));
  }
}


void clist_free(clients_list *clist) {
  while (clist->len != 0)
    clist_pop(clist, clist->head);
  free(clist);
}
