WITH_FUNCT_STATS=1
INCLUDE=-I. -I../lib/
CFLAGS=-g -Wall -Wsign-compare -Wpointer-arith -Wnested-externs \
-Wcast-align -D_GNU_SOURCE $(INCLUDE)

all: apps 

apps: ../lib/anonlib.so 
	gcc $(CFLAGS) `xml2-config --cflags --libs` -O3 -o anonymize_tool anonymize_tool.c ../lib/libnids.so ../lib/anonlib.so -lrt -lpcre -lpcap -lnet -lm
	gcc $(CFLAGS) -O3 -o anonymize_netflow_v9 anonymize_netflow_v9.c ../lib/libnids.so ../lib/anonlib.so -lrt -lpcre -lpcap -lnet -lm
	gcc $(CFLAGS) -O3 -o anonymize_netflow_v5 anonymize_netflow_v5.c ../lib/libnids.so ../lib/anonlib.so -lrt -lpcre -lpcap -lnet -lm
	gcc $(CFLAGS) -O3 -o anonymize_ipfix anonymize_ipfix.c ../lib/libnids.so ../lib/anonlib.so -lrt -lpcre -lpcap -lnet -lm
	
clean:
	rm -f *.o *.so *~ anonymize_netflow_v5 anonymize_netflow_v9 anonymize_tool anonymize_ipfix $(TARGETS)
