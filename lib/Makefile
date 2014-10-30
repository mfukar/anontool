CC=gcc
INCLUDE=-I. -I..
WARNINGS=-Wall -Wsign-compare -Wpointer-arith -Wnested-externs -Wcast-align
SHAREDFLAGS=-fPIC
DEBUGFLAGS=-ggdb
OPTIMIZATIONFLAGS=-O2
CFLAGS=$(OPTIMIZATIONFLAGS) $(WARNINGS) $(INCLUDE) $(SHAREDFLAGS) -D_GNU_SOURCE
LIBRARIES=-lpcap -lpcre -lm -lnids

TARGETS=libnids.so anonlib.so
all: $(TARGETS)

anonlib.so:tool.o bpf.o pcap_input.o cooking.o flist.o strsearch.o mstring.o callback.o printpacket.o anonymize.o decoders.o anon_snort_decode.o anon_print_packet.o anon_checksums.o anon_prefix_preserving.o prefix_preserving_map.o md5.o sha1.o sha256.o sha512.o anonymization_functions.o crc32.o des.o aes.o uncook.o binaryPayload.o util.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -L.. -L. $(LIBRARIES)

libnids.so:
	cd libnids && ./configure --disable-libnet --disable-libglib --enable-shared && make shared
	if [ -e libnids.so ]; then unlink libnids.so; fi
	ln -s libnids/src/libnids.so.1.21 libnids.so

tool.o: tool.c internal.h
	$(CC) $(CFLAGS) -c $<

cooking.o: cooking.c
	$(CC) $(CFLAGS) -c $<

pcap_input.o: pcap_input.c
	$(CC) $(CFLAGS) -c $<

bpf.o: bpf.c
	$(CC) $(CFLAGS) -c $<

flist.o: flist.c
	$(CC) $(CFLAGS) -c $<

strsearch.o: strsearch.c
	$(CC) $(CFLAGS) -c $<

mstring.o: mstring.c
	$(CC) $(CFLAGS) -c $<

printpacket.o: printpacket.c
	$(CC) $(CFLAGS) -c $<

callback.o: callback.c
	$(CC) $(CFLAGS) -c $<

anonymize.o: anonymize.c anonymization.h
	$(CC) $(CFLAGS) -c $<

anon_print_packet.o: anon_print_packet.c
	$(CC) $(CFLAGS) -c $<

anon_snort_decode.o: anon_snort_decode.c
	$(CC) $(CFLAGS) -c $<

anon_checksums.o: anon_checksums.c
	$(CC) $(CFLAGS) -c $<

anon_prefix_preserving.o: anon_prefix_preserving.c
	$(CC) $(CFLAGS) -c $<

prefix_preserving_map.o: prefix_preserving_map.c
	$(CC) $(CFLAGS) -c $<

decoders.o: decoders.c
	$(CC) $(CFLAGS) -c $<

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c $<

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c $<

sha512.o: sha512.c sha512.h
	$(CC) $(CFLAGS) -std=c99 -c $<

crc32.o: crc32.c crc32.h
	$(CC) $(CFLAGS) -c $<

des.o: des.c des.h
	$(CC) $(CFLAGS) -c $<

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c $<

uncook.o: uncook.c
	$(CC) $(CFLAGS) -c $<

binaryPayload.o: binaryPayload.c
	$(CC) $(CFLAGS) -c $<

anonymization_functions.o: anonymization_functions.c anonymization_functions.h
	$(CC) $(CFLAGS) -c $<

util.o: util.c util.h
	$(CC) $(CFLAGS) -std=c99 -c $<

clean:
	cd libnids && make distclean
	if [ -h libnids.so ]; then unlink libnids.so; fi
	rm -f *.o *.so *~ $(TARGETS)
