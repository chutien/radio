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


#define DEFAULT_TIMEOUT 5
#define BUF_SIZE 4096

int RADIO_PROXY_EXIT_CODE = 0;

struct env {
  bool metadata;
  size_t metaint;
  struct event_base *base;
};

void get_parameters(int, char *[], char *[], char *[], char *[], bool *, struct timeval *);
bool cmp_header_key(char *, size_t, char *, size_t);
void radio_event_cb(struct bufferevent *, short, void *);
void radio_read_response_line(struct bufferevent *, void *);
void radio_read_headers_cb(struct bufferevent *, void *);
void radio_read_data_only_cb(struct bufferevent *, void *);
void radio_read_data_cb(struct bufferevent *, void *);
void radio_read_metadata_cb(struct bufferevent *, void *);
void sigint_handler(evutil_socket_t, short, void *);


int main(int argc, char *argv[]) {
  char *host, *resource, *port;
  bool metadata;
  struct timeval timeout;
  get_parameters(argc, argv, &host, &resource, &port, &metadata, &timeout);

  struct addrinfo addr_hints = {0};
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo *addr_results;
  if (getaddrinfo(host, port, &addr_hints, &addr_results))
    syserr("getaddrinfo");

  struct event_base *base = event_base_new();
  if (!base)
    syserr("event_base_new");

  struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!bev)
    syserr("bufferevent_socket_new");

  struct env *env = malloc(sizeof(struct env));
  env->base = base;
  env->metadata = metadata;
  env->metaint = 0;

  bufferevent_setcb(bev,  radio_read_response_line, NULL, radio_event_cb, env);
  bufferevent_set_timeouts(bev, &timeout, NULL);

  if (bufferevent_socket_connect(bev, addr_results->ai_addr, addr_results->ai_addrlen) == -1)
    syserr("bufferevent_socket_connect");
  freeaddrinfo(addr_results);

  evbuffer_add_printf(bufferevent_get_output(bev),
		      "GET %s HTTP/1.0\r\n"
		      "Host:%s\r\n"
		      "%s"
		      "\r\n",
		      resource, host, metadata? "Icy-MetaData:1\r\n" : "");

  struct event *sigint_event = evsignal_new(base, SIGINT, sigint_handler, (void *) base);
  evsignal_add(sigint_event, NULL);
  
  event_base_dispatch(base);

  event_free(sigint_event);
  bufferevent_free(bev);
  event_base_free(base);
  free(env);
  
  return RADIO_PROXY_EXIT_CODE;
}


void get_parameters(int argc, char *argv[], char *host[], char *resource[], char *port[], bool *metadata, struct timeval *timeout) {
  *host = NULL;
  *resource = NULL;
  *port = NULL;
  *metadata = false;
  timeout->tv_sec = DEFAULT_TIMEOUT;
  timeout->tv_usec = 0;

  int t;
  int opt;
  while ((opt = getopt(argc, argv, ":h:r:p:m:t:")) != -1) {
    switch(opt) {
    case 'h':
      *host = optarg;
      break;
    case 'r':
      *resource = optarg;
      break;
    case 'p':
      *port = optarg;
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
      t = atoi(optarg);
      if (t <= 0)
	fatal("incorrect option argument -- 't'");
      timeout->tv_sec = (time_t) t;
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
  if (*port == NULL)
    fatal("missing required option -- 'p'");
}

void fatal_event(struct event_base *base, const char *fmt, ...) {
  va_list fmt_args;
  
  fprintf(stderr, "ERROR: ");

  va_start(fmt_args, fmt);
  if (vfprintf(stderr, fmt, fmt_args) < 0) {
    fprintf(stderr, " (also error in fatal) ");
  }
  va_end(fmt_args);

  fprintf(stderr, "\n");
  RADIO_PROXY_EXIT_CODE = EXIT_FAILURE;
  if (event_base_loopexit(base, NULL) == -1)
    syserr("event_base_loopbreak");
}

void radio_event_cb(struct bufferevent *bev, short what, void *arg) {
  struct env *env = (struct env *) arg;
  
  if (what & BEV_EVENT_ERROR) {
    fatal_event(env->base, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    return;
  }
  
  if (what & BEV_EVENT_CONNECTED) {
    if (bufferevent_enable(bev, EV_READ) == -1)
      syserr("bufferevent_enable");
    return;
  }
  
  if (what & BEV_EVENT_EOF)
    fprintf(stderr, "EOF encountered.\n");
  else if (what & BEV_EVENT_TIMEOUT)
    fprintf(stderr, "A timeout occured.\n");

  if (event_base_loopexit(env->base, NULL) == -1)
    syserr("event_base_loopbreak");
}

bool cmp_header_key(char *header_line, size_t len, char *key, size_t klen) {
  size_t i;
  for (i = 0; i < len && header_line[i] != ':'; ++i)
    header_line[i] = tolower(header_line[i]);
  return klen < len && strncmp(header_line, key, klen) == 0 && header_line[klen] == ':';
}

void radio_read_metadata_cb(struct bufferevent *bev, void *arg) {
  static size_t counter = 0;
  static size_t len = 0;

  char buf[BUF_SIZE + 1];

  if (len == 0) {
    bufferevent_read(bev, buf, 1);
    len = ((size_t) buf[0]) << 4;
  }

  size_t remains = len - counter;
  size_t r;
  while (remains > 0 && (r = bufferevent_read(bev, buf, remains < BUF_SIZE ? remains : BUF_SIZE))) {
    buf[r] = 0;
    fprintf(stderr, buf);
    counter += r;
    remains = len - counter;
  }

  if (remains == 0) {
    if (len > 0)
      fputc('\n', stderr);
    counter = 0;
    len = 0;
    bufferevent_setcb(bev, radio_read_data_cb, NULL, radio_event_cb, arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_data_cb(bev, arg);
  }
}

void radio_read_data_cb(struct bufferevent *bev, void *arg) {
  static size_t counter = 0;

  struct env *env = (struct env *) arg;
  unsigned char buf[BUF_SIZE];

  size_t remains = env->metaint - counter;
  size_t r;
  while (remains > 0 && (r = bufferevent_read(bev, buf, remains < BUF_SIZE ? remains : BUF_SIZE))) {
    fwrite(buf, 1, r, stdout);
    counter += r;
    remains = env->metaint - counter;
  }

  if (remains == 0) {
    counter = 0;
    bufferevent_setcb(bev, radio_read_metadata_cb, NULL, radio_event_cb, arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_metadata_cb(bev, arg);
  }
}

void radio_read_data_only_cb(struct bufferevent *bev, void *arg) {
  unsigned char buf[BUF_SIZE];
  size_t r;
  while ((r = bufferevent_read(bev, buf, BUF_SIZE)))
    fwrite(buf, 1, r, stdout);
}

void radio_read_headers_cb(struct bufferevent *bev, void *arg) {
  struct env *env = (struct env *) arg;
  struct evbuffer *buf = bufferevent_get_input(bev);

  size_t len;
  char *header_line;
  while ((header_line = evbuffer_readln(buf, &len, EVBUFFER_EOL_CRLF)) && len > 0) {
    if (cmp_header_key(header_line, len, "icy-metaint", 11)) {
      if (!env->metadata) {
	fatal_event(env->base, "Unexpected icy-metaint header.");
	return;
      }
      char *endptr;
      errno = 0;
      uintmax_t val = strtoumax(header_line + 12, &endptr, 10);
      if (endptr == header_line + 12 || *endptr != '\0'
	  || (errno == ERANGE && val == UINTMAX_MAX) || (errno != 0 && val == 0)) {
	fatal_event(env->base, "Could not parse received icy-metaint value.");
	return;
      }
      if (val == 0) {
        fatal_event(env->base, "Incorrect icy-metaint value.");
	return;
      }
      env->metaint = (size_t) val;
    }
  }
  
  if (header_line && len == 0) {
    if (env->metadata && env->metaint == 0)
      env->metadata = 0;
    if (env->metadata) {
      bufferevent_setcb(bev, radio_read_data_cb, NULL, radio_event_cb, arg);
      if (evbuffer_get_length(bufferevent_get_input(bev)))
	radio_read_data_cb(bev, arg);
    } else {
      bufferevent_setcb(bev, radio_read_data_only_cb, NULL, radio_event_cb, arg);
      if (evbuffer_get_length(bufferevent_get_input(bev)))
	radio_read_data_only_cb(bev, arg);
    }
  }
}

void radio_read_response_line(struct bufferevent *bev, void *arg) {
  struct evbuffer *buf = bufferevent_get_input(bev);

  size_t len;
  char *response_line = evbuffer_readln(buf, &len, EVBUFFER_EOL_CRLF);
  if (!response_line) {
    fprintf(stderr, "The first line has not arrived yet.\n");
    return;
  }

  struct env *env = (struct env *) arg;

  size_t i = 0;
  if (!strncmp(response_line, "ICY ", 4)) {
    i += 4;
  } else if (!strncmp(response_line, "HTTP/1.0 ", 9)) {
    i += 9;
  } else {
    fatal_event(env->base, "Unexpected response line -- %s\n", response_line);
    return;
  }

  if (!strncmp(response_line + i, "200", 3)) {
    free(response_line);
    bufferevent_setcb(bev, radio_read_headers_cb, NULL, radio_event_cb, arg);
    if (evbuffer_get_length(bufferevent_get_input(bev)))
      radio_read_headers_cb(bev, arg);
  } else {
    fprintf("ERROR: Unexpected response code -- %s\n", response_line + i);
    RADIO_PROXY_EXIT_CODE = EXIT_FAILURE;
    free(response_line);
    if (event_base_loopexit(env->base, NULL) == -1)
      syserr("event_base_loopbreak");
  }
}

void sigint_handler(evutil_socket_t desc, short what, void *arg) {
  struct event_base *base = (struct event_base *) arg;
  if (event_base_loopexit(base, NULL) == -1)
    syserr("event_base_loopexit");
}
