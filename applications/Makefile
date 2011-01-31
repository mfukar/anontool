WITH_FUNCT_STATS=1
INCLUDE=-I. -I../lib/
OPTIMIZATIONS=-O3
DEBUGFLAGS=-ggdb
WARNINGS=-Wall -Wsign-compare -Wpointer-arith -Wnested-externs -Wcast-align
CFLAGS=$(DEBUGFLAGS) $(WARNINGS) $(OPTIMIZATIONS) -D_GNU_SOURCE $(INCLUDE)
LIBRARIES=-lrt -lpcre -lpcap -lnet -lm

TARGETS=anonymize_tool anonymize_ipfix anonymize_netflow_v5 anonymize_netflow_v9
all: ../lib/anonlib.so $(TARGETS) 

anonymize_tool: anonymize_tool.c
	gcc $(CFLAGS) `xml2-config --cflags --libs` -o $@ $^ ../lib/libnids.so ../lib/anonlib.so $(LIBRARIES)
anonymize_netflow_v9: anonymize_netflow_v9.c
	gcc $(CFLAGS) -o $@ $^ ../lib/libnids.so ../lib/anonlib.so $(LIBRARIES)
anonymize_netflow_v5: anonymize_netflow_v5.c
	gcc $(CFLAGS) -o $@ $^ ../lib/libnids.so ../lib/anonlib.so $(LIBRARIES)
anonymize_ipfix: anonymize_ipfix.c
	gcc $(CFLAGS) -o $@ $^ ../lib/libnids.so ../lib/anonlib.so $(LIBRARIES)

clean:
	rm -f *.o *.so *~ $(TARGETS)
