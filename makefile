CC 	= gcc
CFLAGS 	= -g -Wall -Wextra -O2
TARGET = radio-proxy

all: $(TARGET)

radio-proxy.o err.o: err.h

radio-proxy: radio-proxy.o err.o
	$(CC) $(CFLAGS) $^ -o $@ -levent

.PHONY: clean TARGET
clean:
	rm -f *.o *~ *.bak $(TARGET)
