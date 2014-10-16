CC=gcc
INCLUDE=-I. -I../lib/
OPTIMIZATIONS=-O2
SHAREDFLAGS=-fPIE
DEBUGFLAGS=-ggdb
WARNINGS=-Wall -Wsign-compare -Wpointer-arith -Wnested-externs -Wcast-align
CFLAGS=$(DEBUGFLAGS) $(WARNINGS) $(OPTIMIZATIONS) $(SHAREDFLAGS) -D_GNU_SOURCE $(INCLUDE)
LIBRARIES=-lrt -lpcre -lpcap -lnet -lm

TARGETS=anonymize_tool anonymize_ipfix anonymize_netflow_v5 anonymize_netflow_v9
all: ../lib/anonlib.so $(TARGETS)

anonymize_tool: anonymize_tool.c
	$(CC) $(CFLAGS) -o $@ $^ ../lib/anonlib.so ../lib/libnids.so $(LIBRARIES)
anonymize_netflow_v9: anonymize_netflow_v9.c
	$(CC) $(CFLAGS) -o $@ $^ ../lib/anonlib.so ../lib/libnids.so $(LIBRARIES)
anonymize_netflow_v5: anonymize_netflow_v5.c
	$(CC) $(CFLAGS) -o $@ $^ ../lib/anonlib.so ../lib/libnids.so $(LIBRARIES)
anonymize_ipfix: anonymize_ipfix.c
	$(CC) $(CFLAGS) -o $@ $^ ../lib/anonlib.so ../lib/libnids.so $(LIBRARIES)

clean:
	rm -f *.o *.so *~ $(TARGETS)
