INCLUDE=-I. -I..
WARNINGS=-Wall -Wsign-compare -Wpointer-arith -Wnested-externs -Wcast-align
SHAREDFLAGS=-fPIC
DEBUGFLAGS=-ggdb
OPTIMIZATIONFLAGS=-O3
CFLAGS=$(OPTIMIZATIONFLAGS) $(WARNINGS) $(INCLUDE) $(SHAREDFLAGS) -D_GNU_SOURCE
LIBRARIES=-lpcap -lpcre -lm

TARGETS=libnids.a anonlib.so
all: $(TARGETS)

anonlib.so:tool.o bpf.o pcap_input.o cooking.o flist.o strsearch.o mstring.o callback.o printpacket.o anonymize.o decoders.o anon_snort_decode.o anon_print_packet.o anon_checksums.o anon_prefix_preserving.o prefix_preserving_map.o md5.o sha1.o sha256.o sha512.o anonymization_functions.o crc32.o des.o aes.o uncook.o binaryPayload.o util.o
	gcc $(CFLAGS) -shared -o $@ $^ -L.. -L. $(LIBRARIES)

libnids.a: 
	cd libnids && ./configure --disable-libnet --enable-shared && make
	if [ -e libnids.so ]; then unlink libnids.so; fi
	ln -s libnids/src/libnids.so.1.21 libnids.so

tool.o: tool.c internal.h
	gcc $(CFLAGS) -c $<

cooking.o: cooking.c
	gcc $(CFLAGS) -c $<

pcap_input.o: pcap_input.c
	gcc $(CFLAGS) -c $<

bpf.o: bpf.c
	gcc $(CFLAGS) -c $<

flist.o: flist.c
	gcc $(CFLAGS) -c $<
	
strsearch.o: strsearch.c
	gcc $(CFLAGS) -c $<

mstring.o: mstring.c
	gcc $(CFLAGS) -c $<
	
printpacket.o: printpacket.c
	gcc $(CFLAGS) -c $<

callback.o: callback.c
	gcc $(CFLAGS) -c $<

anonymize.o: anonymize.c anonymization.h
	gcc $(CFLAGS) -c $<

anon_print_packet.o: anon_print_packet.c
	gcc $(CFLAGS) -c $<

anon_snort_decode.o: anon_snort_decode.c
	gcc $(CFLAGS) -c $<

anon_checksums.o: anon_checksums.c
	gcc $(CFLAGS) -c $<

anon_prefix_preserving.o: anon_prefix_preserving.c
	gcc $(CFLAGS) -c $<

prefix_preserving_map.o: prefix_preserving_map.c
	gcc $(CFLAGS) -c $<

decoders.o: decoders.c
	gcc $(CFLAGS) -c $<

md5.o: md5.c md5.h
	gcc $(CFLAGS) -c $<
	
sha1.o: sha1.c sha1.h
	gcc $(CFLAGS) -c $<

sha256.o: sha256.c sha256.h
	gcc $(CFLAGS) -c $<

sha512.o: sha512.c sha512.h
	gcc $(CFLAGS) -c $<

crc32.o: crc32.c crc32.h
	gcc $(CFLAGS) -c $<

des.o: des.c des.h
	gcc $(CFLAGS) -c $<

aes.o: aes.c aes.h
	gcc $(CFLAGS) -c $<

uncook.o: uncook.c
	gcc $(CFLAGS) -c $<

binaryPayload.o: binaryPayload.c
	gcc $(CFLAGS) -c $<

anonymization_functions.o: anonymization_functions.c anonymization_functions.h
	gcc $(CFLAGS) -c $<

util.o: util.c util.h
	gcc $(CFLAGS) -std=c99 -c $<

clean:
	cd libnids && make distclean
	if [ -h libnids.so ]; then unlink libnids.so; fi
	rm -f *.o *.so *~ $(TARGETS)
