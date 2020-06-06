#ifndef _ERR_
#define _ERR_

extern void syserr(const char *fmt, ...);

extern void fatal(const char *fmt, ...);

void syserr_event(struct event_base *, int *, const char *, ...);

void fatal_event(struct event_base *, int *, const char *, ...);

#endif
