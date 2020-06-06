#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "err.h"

void syserr(const char *fmt, ...) {
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
  exit(EXIT_FAILURE);
}

void fatal(const char *fmt, ...) {
  va_list fmt_args;
  
  fprintf(stderr, "ERROR: ");

  va_start(fmt_args, fmt);
  if (vfprintf(stderr, fmt, fmt_args) < 0) {
    fprintf(stderr, " (also error in fatal) ");
  }
  va_end(fmt_args);

  fprintf(stderr, "\n");
  exit(EXIT_FAILURE);
}

void syserr_event(struct event_base *base, int *exit_code, const char *fmt, ...) {
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
  *exit_code = EXIT_FAILURE;
  if (event_base_loopbreak(base) == -1)
    syserr("event_base_loopbreak");
}

void fatal_event(struct event_base *base, int *exit_code, const char *fmt, ...) {
  va_list fmt_args;
  
  fprintf(stderr, "ERROR: ");

  va_start(fmt_args, fmt);
  if (vfprintf(stderr, fmt, fmt_args) < 0) {
    fprintf(stderr, " (also error in fatal) ");
  }
  va_end(fmt_args);

  fprintf(stderr, "\n");
  *exit_code = EXIT_FAILURE;
  if (event_base_loopbreak(base) == -1)
    syserr("event_base_loopbreak");
}
