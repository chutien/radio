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
#define QUEUE_LENGTH 5
#define MAX_RADIO_NAME 255
#define TTL_VALUE 4
#define MAX_UDP 65536
#define MAX_METADATA 255
#define KEEP_ALIVE_SEC 3
#define KEEP_ALIVE_USEC 500000

#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6

#define IAC "\xff"
#define WILL "\xfb"
#define DO "\xfd"
#define ECHO "\x1"
#define SUPPRESS_GO_AHEAD "\x3"

#define LF "\n"
#define CR "\r"
#define NUL "\0"

#define CSI(C) "\e["#C

#define SGR_REVERSE_VIDEO CSI(7m)
#define SGR_RESET CSI(0m)
#define UP CSI(A)
#define DOWN CSI(B)

 
static int radio_client_exit_code = EXIT_SUCCESS;


typedef struct radio {
  char name[MAX_RADIO_NAME + 1];
  struct sockaddr_in *addr;
  struct radio *next;
  struct radio *prev;
} radio_elem;

typedef struct radio_list {
  size_t len;
  radio_elem *head;
  radio_elem *last;
} radio_list;

radio_list *rlist_create();
radio_elem *rlist_push(radio_list *, struct sockaddr_in *, char []);
void rlist_pop(radio_list *, radio_elem *);
radio_elem *rlist_get(const radio_list *, size_t);
radio_elem *rlist_find(const radio_list *, struct sockaddr_in *);
void rlist_free(radio_list *);


struct menu {
  bool connected_client;
  size_t cursor;
  radio_elem *connected_radio;
  struct event *keep_alive_timer;
  radio_list *radios;
  char metadata[MAX_METADATA];
};

struct menu *menu_create();
void menu_cursor_up(struct menu *);
void menu_cursor_down(struct menu *);
void menu_connect_radio(struct event_base *, struct menu *, radio_elem *, evutil_socket_t);
void menu_disconnect_radio(struct event_base *, struct menu *, evutil_socket_t);
int option_render(struct bufferevent *, struct event_base *, char *, bool, bool);
int menu_render(struct bufferevent *, struct event_base *, struct menu *);
int menu_clear(struct bufferevent *, struct event_base *, struct menu *);
int menu_rerender(struct bufferevent *, struct event_base *, struct menu *);
void menu_exec(struct bufferevent *, struct event_base *, struct menu *, evutil_socket_t, struct sockaddr_in *);
bool is_addr_eq(const struct sockaddr_in *, const struct sockaddr_in *);
  
void get_parameters(int, char *[], char *[], char *[], char *[], struct timeval *);


void telnet_listen_cb(evutil_socket_t, short, void *);
struct telnet_listen_arg {
  struct bufferevent *bev;
  struct event_base *base;
};


void radio_listen_cb(evutil_socket_t, short, void *);
struct radio_listen_arg {
  struct menu *menu;
  struct bufferevent *bev;
  struct event_base *base;
};


void telnet_control_init_cb(struct bufferevent *, void *);
void telnet_control_read_cb(struct bufferevent *, void *);
void telnet_control_event_cb(struct bufferevent *, short, void *);
struct telnet_control_arg {
  evutil_socket_t radio_sock;
  struct sockaddr_in *radio_addr;
  struct menu *menu;
  struct event_base *base;
};


void radio_keep_alive_cb(evutil_socket_t, short, void *);


int main(int argc, char *argv[]) {
  char *host, *radio_port, *telnet_port;
  struct timeval timeout;
  get_parameters(argc, argv, &host, &radio_port, &telnet_port, &timeout);

  struct event_base *base = event_base_new();
  if (!base) syserr("event_base_new");

  struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!bev) syserr("bufferevent_socket_new");

  struct menu *menu = menu_create();


  evutil_socket_t telnet_sock = socket(PF_INET, SOCK_STREAM, 0);
  if (telnet_sock < 0)
    syserr("socket");
  if (evutil_make_listen_socket_reuseable(telnet_sock))
    syserr("evutil_make_listen_socket_reuseable");
  if (evutil_make_socket_nonblocking(telnet_sock))
    syserr("evutil_make_socket_nonblocking");

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(atoi(telnet_port));
  
  if(bind(telnet_sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    syserr("bind");

  if (listen(telnet_sock, QUEUE_LENGTH) == -1) syserr("listen");

  struct telnet_listen_arg *listen_arg = malloc(sizeof(struct telnet_listen_arg));
  if (!listen_arg) syserr("malloc");
  listen_arg->base = base;
  listen_arg->bev = bev;
  
  struct event *telnet_listen = event_new(base, telnet_sock, EV_READ|EV_PERSIST, telnet_listen_cb, (void *) listen_arg);
  if (!telnet_listen) syserr("event_new");

  if (event_add(telnet_listen, NULL) < 0) syserr("event_add");

  
  struct addrinfo addr_hints = {0};
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_DGRAM;
  addr_hints.ai_protocol = IPPROTO_UDP;

  struct addrinfo *addr_results;
  if (getaddrinfo(host, radio_port, &addr_hints, &addr_results)) syserr("getaddrinfo");

  struct sockaddr_in radio_addr;
  radio_addr.sin_family = AF_INET;
  radio_addr.sin_addr.s_addr = ((struct sockaddr_in *) (addr_results->ai_addr))->sin_addr.s_addr;
  radio_addr.sin_port = ((struct sockaddr_in *) (addr_results->ai_addr))->sin_port;

  free(addr_results);
  
  evutil_socket_t radio_sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (radio_sock < 0) syserr("socket");
  if (evutil_make_listen_socket_reuseable(radio_sock))
    syserr("evutil_make_listen_socket_reuseable");
  if(evutil_make_socket_nonblocking(radio_sock))
    syserr("evutil_make_socket_nonblocking");

  int optval;
  optval = 1;
  if (setsockopt(radio_sock, SOL_SOCKET, SO_BROADCAST, (void*)&optval, sizeof optval) < 0)
    syserr("setsockopt broadcast");
  
  optval = TTL_VALUE;
  if (setsockopt(radio_sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&optval, sizeof optval) < 0)
    syserr("setsockopt multicast ttl");

  struct radio_listen_arg *radio_arg = malloc(sizeof(struct radio_listen_arg));
  if (!radio_arg) syserr("malloc");

  radio_arg->menu = menu;
  radio_arg->bev = bev;
  radio_arg->base = base;
  
  struct event *radio_listen = event_new(base, radio_sock, EV_READ|EV_TIMEOUT|EV_PERSIST, radio_listen_cb, (void *) radio_arg);
  if (!radio_listen) syserr("event_new");

  if (event_add(radio_listen, &timeout) < 0) syserr("event_add");
  
  struct event *radio_keep_alive = event_new(base, radio_sock, EV_TIMEOUT|EV_PERSIST, radio_keep_alive_cb, (void *) base);

  menu->keep_alive_timer = radio_keep_alive;

  struct telnet_control_arg *control_arg = malloc(sizeof(struct telnet_control_arg));
  if (!control_arg) syserr("malloc");

  control_arg->radio_sock = radio_sock;
  control_arg->radio_addr = &radio_addr;
  control_arg->menu = menu;
  control_arg->base = base;
  
  bufferevent_setcb(bev, NULL, telnet_control_init_cb, telnet_control_event_cb, control_arg);
  
  if (event_base_dispatch(base) < 0) syserr("event_base_dispatch");

  close(telnet_sock);
  close(radio_sock);
  free(listen_arg);
  free(control_arg);
  free(radio_arg);
  event_free(radio_keep_alive);
  event_free(telnet_listen);
  event_free(radio_listen);
  event_base_free(base);
  bufferevent_free(bev);

  return radio_client_exit_code;
}


void get_parameters(int argc, char *argv[], char *host[], char *radio_port[],
		    char *telnet_port[], struct timeval *timeout) {
  *host = NULL;
  *radio_port = NULL;
  *telnet_port = NULL;
  timeout->tv_sec = DEFAULT_TIMEOUT;
  timeout->tv_usec = 0;

  int t;
  int opt;
  while ((opt = getopt(argc, argv, ":H:P:p:T:")) != -1) {
    switch(opt) {
    case 'H':
      *host = optarg;
      break;
    case 'P':
      *radio_port = optarg;
      break;
    case 'p':
      *telnet_port = optarg;
      break;
    case 'T':
      t = atoi(optarg);
      if (t <= 0)
	fatal("incorrect option argument -- 'T'");
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
    fatal("missing required option -- 'H'");
  if (*radio_port == NULL)
    fatal("missing required option -- 'P'");
  if (*telnet_port == NULL)
    fatal("missing required option -- 'p'");
}


void syserr_event(struct event_base *base, const char *fmt, ...) {
  va_list fmt_args;
  int err;

  fprintf(stderr, "ERROR: ");
  err = errno;

  va_start(fmt_args, fmt);
  if (vfprintf(stderr, fmt, fmt_args) < 0) {
    fprintf(stderr, " (also error in syserr) ");
  }
  va_end(fmt_args);
  fprintf(stderr, " (%d; %s)\n", err, strerror(err));
  radio_client_exit_code = EXIT_FAILURE;
  if (event_base_loopbreak(base) == -1)
    syserr("event_base_loopbreak");
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
  radio_client_exit_code = EXIT_FAILURE;
  if (event_base_loopbreak(base) == -1)
    syserr("event_base_loopbreak");
}


void telnet_listen_cb(evutil_socket_t sock, short what, void *raw_arg) {
  UNUSED(what);
  struct telnet_listen_arg *arg = (struct telnet_listen_arg *) raw_arg;
  
  struct sockaddr_in sin;
  socklen_t addr_size = sizeof(struct sockaddr_in);

  evutil_socket_t control_sock = accept(sock, (struct sockaddr *)&sin, &addr_size);
  if (control_sock < 0) {
    syserr_event(arg->base, "accept");
    return;
  }
  
  if (evutil_make_listen_socket_reuseable(control_sock)) {
    syserr_event(arg->base, "evutil_make_listen_socket_reuseable");
    close(control_sock);
    return;
  }
  
  if(evutil_make_socket_nonblocking(control_sock)) {
    syserr_event(arg->base, "evutil_make_socket_nonblocking");
    close(control_sock);
    return;
  }

  if (bufferevent_setfd(arg->bev, control_sock) < 0) {
    syserr_event(arg->base, "bufferevent_setfd");
    close(control_sock);
    return;
  }

  bufferevent_enable(arg->bev, EV_READ|EV_WRITE);
}


void telnet_control_init_cb(struct bufferevent *bev, void *raw_arg) {
  struct telnet_control_arg *arg = (struct telnet_control_arg *) raw_arg;

  if (bufferevent_write(bev, IAC WILL ECHO IAC WILL SUPPRESS_GO_AHEAD, 6) < 0) {
    syserr_event(arg->base, "bufferevent_write");
    return;
  }									     

  arg->menu->connected_client = true;
  menu_render(bev, arg->base, arg->menu);
  bufferevent_setcb(bev, telnet_control_read_cb, NULL, telnet_control_event_cb, arg);
}


void telnet_control_read_cb(struct bufferevent *bev, void *raw_arg) {
  struct telnet_control_arg *arg = (struct telnet_control_arg *) raw_arg;
  unsigned char buf[3];
  size_t r;

  struct menu *menu = arg->menu;
  
  while ((r = bufferevent_read(bev, buf, 3))) {
    if (r == 2 && (!memcmp(buf, CR LF, 2) || !memcmp(buf, CR NUL, 2))) {
      menu_exec(bev, arg->base, menu, arg->radio_sock, arg->radio_addr);
    } else if (r == 3 && !memcmp(buf, UP, 3)) {
      menu_cursor_down(menu);
    } else if (r == 3 && !memcmp(buf, DOWN, 3)) {
      menu_cursor_up(menu);
    } else {
      continue;
    }
    menu_clear(bev, arg->base, menu);
    menu_render(bev, arg->base, menu);
  }
}


void telnet_control_event_cb(struct bufferevent *bev, short what, void *raw_arg) {
  struct telnet_control_arg *arg = (struct telnet_control_arg *) raw_arg;  
  if (what & BEV_EVENT_ERROR)
    syserr_event(arg->base, "bufferevent");
  else if (what & BEV_EVENT_EOF) {
    arg->menu->connected_client = false;
    bufferevent_setcb(bev, NULL, telnet_control_init_cb, telnet_control_event_cb, arg);
  } else {
    fprintf(stderr, "what"); //TODO
  }
}


void radio_listen_cb(evutil_socket_t sock, short what, void *raw_arg) {
  struct radio_listen_arg *arg = (struct radio_listen_arg *) raw_arg;
  if (what & EV_TIMEOUT) {
    if (!(arg->menu->connected_radio))
      return;
    
    if (arg->menu->connected_client)
      menu_clear(arg->bev, arg->base, arg->menu);
    
    rlist_pop(arg->menu->radios, arg->menu->connected_radio);
    
    menu_disconnect_radio(arg->base, arg->menu, sock);
    
    return;
  }

  char buf[MAX_UDP + 4 + 1];

  struct sockaddr_in *client_addr = malloc(sizeof(struct sockaddr_in));
  if (!client_addr) {
    syserr_event(arg->base, "malloc");
    return;
  }

  socklen_t caddr_len = (socklen_t) sizeof(struct sockaddr_in);
  ssize_t r = recvfrom(sock, buf, MAX_UDP, 0, (struct sockaddr *) client_addr, &caddr_len);
  if (r < 0) {
      syserr_event(arg->base, "recvfrom");
      return;
  }

  char client_addr_str[ADDRLEN + 1];
  inet_ntop(AF_INET, &(client_addr->sin_addr), client_addr_str, ADDRLEN + 1);

  if (r < 4) {
    fprintf(stderr, "Ignoring message from %s:%d.\n", client_addr_str, ntohs(client_addr->sin_port));
    return;
  }

  uint16_t type, length;
  memcpy(&type, buf, 2);
  memcpy(&length, buf + 2, 2);
  type = ntohs(type);
  length = ntohs(length);
  
  switch (type) {
  case IAM:
    buf[4 + length] = 0;
    radio_elem *found = rlist_find(arg->menu->radios, client_addr);
    if (found) {
      strcpy(found->name, buf + 4);
      if (arg->menu->connected_client)
	menu_rerender(arg->bev, arg->base, arg->menu);
    } else {
      if (arg->menu->connected_client)
	menu_clear(arg->bev, arg->base, arg->menu);
      rlist_push(arg->menu->radios, client_addr, buf + 4);
      if (arg->menu->connected_client)
	menu_render(arg->bev, arg->base, arg->menu);
    }
    break;
    
  case AUDIO:
    if (arg->menu->connected_radio &&
	is_addr_eq(arg->menu->connected_radio->addr, client_addr))
      fwrite(buf + 4, 1, length, stdout);
    break;
    
  case METADATA:
    if (arg->menu->connected_radio &&
	is_addr_eq(arg->menu->connected_radio->addr, client_addr)) {
      buf[4 + length] = 0;
      strcpy(arg->menu->metadata, buf + 4);
      if (arg->menu->connected_client)
	menu_rerender(arg->bev, arg->base, arg->menu);
    }
    break;
    
  default:
    fprintf(stderr, "Ignoring message from %s:%d.\n", client_addr_str, ntohs(client_addr->sin_port));
  }
}


void radio_keep_alive_cb(evutil_socket_t sock, short what, void *raw_arg) {
  UNUSED(what);
  struct event_base *base = (struct event_base *) raw_arg;
  uint16_t mes[2];
  mes[0] = htons(KEEPALIVE);
  mes[1] = 0;
  if (write(sock, mes, 4) != 4) syserr_event(base, "write");
}



struct menu *menu_create() {
  struct menu *menu = malloc(sizeof(struct menu));
  if (!menu) syserr("malloc");
  menu->connected_client = false;
  menu->cursor = 0;
  menu->connected_radio = NULL;
  menu->keep_alive_timer = NULL;
  menu->radios = rlist_create();  
  menu->metadata[0] = 0;
  return menu;
}

void menu_cursor_up(struct menu *menu) {
  menu->cursor = (menu->cursor + 1) % (menu->radios->len + 2);
}

void menu_cursor_down(struct menu *menu) {
  if (menu->cursor == 0)
    menu->cursor = menu->radios->len + 1;
  else
    menu->cursor = menu->cursor - 1;
}

void menu_connect_radio(struct event_base *base, struct menu *menu, radio_elem *radio, evutil_socket_t radio_sock) {

  menu->connected_radio = radio;
  
  if (connect(radio_sock, (struct sockaddr *) radio->addr, (socklen_t) sizeof(struct sockaddr_in)) < 0) {
    syserr_event(base, "connect");
    return;
  }

  struct timeval tv;
  tv.tv_sec = KEEP_ALIVE_SEC;
  tv.tv_usec = KEEP_ALIVE_USEC;
  if (event_add(menu->keep_alive_timer, &tv) < 0) {
    syserr_event(base, "event_add");
    return;
  }
}

void menu_disconnect_radio(struct event_base *base, struct menu *menu, evutil_socket_t radio_sock) {
  if (event_del(menu->keep_alive_timer) < 0) {
    syserr_event(base, "event_add");
    return;
  }
  
  menu->connected_radio = NULL;

  struct sockaddr unspec = {0};
  unspec.sa_family = AF_UNSPEC;
      
  if (connect(radio_sock, &unspec, (socklen_t) sizeof(struct sockaddr)) < 0) {
    syserr_event(base, "connect");
    return;
  }
}

int option_render(struct bufferevent *bev, struct event_base *base, char *str, bool ind, bool sel) {
  struct evbuffer *output = bufferevent_get_output(bev);
  int r;
  if (ind)
    r = evbuffer_add_printf(output, SGR_REVERSE_VIDEO "%s%s" SGR_RESET CR LF, str, sel ? " *" : "");
  else
    r = evbuffer_add_printf(output, "%s%s" CR LF, str, sel ? " *" : "");  
  if (r < 0) syserr_event(base, "evbuffer_add_printf");
  return r;
}


int menu_render(struct bufferevent *bev, struct event_base *base, struct menu *menu) {
  if (option_render(bev, base, "Szukaj pośrednika", menu->cursor == 0, false) == -1) return -1;

  size_t i = 1;
  for (radio_elem *radio = menu->radios->head; radio != NULL; radio = radio->next) {
    if (option_render(bev, base, radio->name, menu->cursor == i, menu->connected_radio == radio) == -1) return -1;
    ++i;
  }
  
  if (option_render(bev, base, "Koniec", menu->cursor == menu->radios->len + 1, false) == -1) return -1;
  
  if (option_render(bev, base, menu->metadata, false, false) == -1) return -1;
  return 0;
}


int menu_clear(struct bufferevent *bev, struct event_base *base, struct menu *menu) {
  struct evbuffer *output = bufferevent_get_output(bev);
  int r;
  size_t n = menu->radios->len + 4;
  
  for (size_t i = 0; i < n - 1; ++i) {
    r = evbuffer_add_printf(output, CSI(2K) CSI(A));
    if (r < 0) {
      syserr_event(base, "evbuffer_add_printf");
      return r;
    }
  }
  r = evbuffer_add_printf(output, CSI(2K));
  if (r < 0) {
    syserr_event(base, "evbuffer_add_printf");
    return r;
  }
  return 0;
}


int menu_rerender(struct bufferevent *bev, struct event_base *base, struct menu *menu) {
  if (menu_clear(bev, base, menu) == -1 ||
      menu_render(bev, base, menu) == -1)
    return -1;
  return 0;
}


void menu_exec(struct bufferevent *bev, struct event_base *base, struct menu *menu, evutil_socket_t radio_sock, struct sockaddr_in *radio_addr) {
  uint16_t mes[2];

  if (menu->cursor == 0) {
    if (menu->connected_radio) menu_disconnect_radio(base, menu, radio_sock);
    
    mes[0] = htons(DISCOVER);
    mes[1] = 0;
    
    if (sendto(radio_sock, mes, 4, 0, (struct sockaddr *) radio_addr, (socklen_t) sizeof(struct sockaddr_in)) < 0)
      fprintf(stderr, "ERROR %s\n", strerror(errno));

  } else if (1 <= menu->cursor && menu->cursor <= menu->radios->len) {
    menu_connect_radio(base, menu, rlist_get(menu->radios, menu->cursor - 1), radio_sock);
    
    mes[0] = htons(DISCOVER);
    mes[1] = 0;

    if (write(radio_sock, mes, 4) != 4) {
      syserr_event(base, "write");
      return;
    }
    
    menu_rerender(bev, base, menu);

  } else if (menu->cursor == menu->radios->len + 1) {
    if (event_base_loopexit(base, NULL) == -1)
      syserr("event_base_loopexit");

  } else {
    fatal("incorrect menu state");
  }
}


radio_list *rlist_create() {
  radio_list *rlist = malloc(sizeof(radio_list));
  if (!rlist) syserr("mallloc");
  rlist->len = 0;
  rlist->head = NULL;
  rlist->last = NULL;
  return rlist;
}


radio_elem *rlist_push(radio_list *rlist, struct sockaddr_in *addr, char name[]) {
  radio_elem *radio = malloc(sizeof(radio_elem));
  if (!radio) syserr("malloc");

  radio->addr = addr;
  strncpy(radio->name, name, MAX_RADIO_NAME);
  if (rlist->len != 0) {
    radio->prev = rlist->last;
    rlist->last->next = radio;
    rlist->last = radio;
  } else {
    radio->prev = NULL;
    rlist->last = radio;
    rlist->head = radio;
  }
  ++(rlist->len);
  return radio;
}


void rlist_pop(radio_list *rlist, radio_elem *radio) {
  if (radio->prev)
    radio->prev->next = radio->next;
  else
    rlist->head = radio->next;
  if (radio->next)
    radio->next->prev = radio->prev;
  else
    rlist->last = radio->prev;
  free(radio->addr);
  free(radio);
  --(rlist->len);
}


radio_elem *rlist_get(const radio_list *rlist, size_t i) {
  size_t j = 0;
  radio_elem *radio;
  for (radio = rlist->head; j < i && radio != NULL; radio = radio->next)
    ++j;
  return radio;
}


radio_elem *rlist_find(const radio_list *rlist, struct sockaddr_in *addr) {
  for (radio_elem *radio = rlist->head; radio != NULL; radio = radio->next)
    if (is_addr_eq(radio->addr, addr)) return radio;
  return NULL;
}


void rlist_free(radio_list *rlist) {
  while (rlist->len != 0)
    rlist_pop(rlist, rlist->head);
  free(rlist);
}


bool is_addr_eq(const struct sockaddr_in *addr1, const struct sockaddr_in *addr2) {
  return addr1->sin_port == addr2->sin_port
    && addr1->sin_addr.s_addr == addr2->sin_addr.s_addr;
}
