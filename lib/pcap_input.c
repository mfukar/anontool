/*
 * anontool Copyright Notice, License & Disclaimer
 *
 * Copyright 2006 by Antonatos Spiros, Koukis Demetres & Foukarakis Michael
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both the
 * copyright notice and this permission notice and warranty disclaimer appear
 * in supporting documentation, and that the names of the authors not be used
 * in advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.
 *
 * The authors disclaim all warranties with regard to this software, including all
 * implied warranties of merchantability and fitness.  In no event shall we be liable
 * for any special, indirect or consequential damages or any damages whatsoever
 * resulting from loss of use, data or profits, whether in an action of contract,
 * negligence or other tortious action, arising out of or in connection with the
 * use or performance of this software.
 */
#include <stdlib.h>
#include <stdio.h>
//#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include "anonymization.h"

extern void    *pkt_handler;
extern void     process_packet(unsigned char *packet, anon_pkthdr_t * header, int cont);

/* init input */
void init_tcpdump_trace(struct anonflow *flow)
{
	flow->link_type = pcap_datalink((pcap_t *) pkt_handler);
	flow->cap_length = pcap_snapshot((pcap_t *) pkt_handler);
	return;
}

/* open input */
int open_tcpdump_trace(char *filename)
{
	char            errbuf[PCAP_ERRBUF_SIZE];
	pkt_handler = (void *)pcap_open_offline(filename, errbuf);
	//printf(" in here %d\n",pkt_handler);
	if (pkt_handler == NULL) {
		printf("Error in open_tcpdump_trace: %s\n", errbuf);
		return -1;
	}
	return 1;
}

void dump_tcpdump_packet(void *handler, unsigned char *packet, anon_pkthdr_t * header)
{
	struct pcap_pkthdr pkthdr;

	if (handler == NULL)
		return;

	pkthdr.caplen = header->caplen;
	pkthdr.len = header->wlen;
	pkthdr.ts.tv_sec = header->ts.tv_sec;
	pkthdr.ts.tv_usec = header->ts.tv_usec;
	pcap_dump((unsigned char *)handler, &pkthdr, packet);
}

void process_tcpdump_trace()
{
	unsigned char  *packet;
	struct pcap_pkthdr phdr;
	anon_pkthdr_t   mhdr;

	if (pkt_handler == NULL)
		return;

	mhdr.ts.tv_sec = mhdr.ts.tv_usec = 0;

	while ((packet = (unsigned char *)pcap_next((pcap_t *) pkt_handler, &phdr)) != NULL) {
		mhdr.caplen = phdr.caplen;
		mhdr.wlen = phdr.len;
		mhdr.ts.tv_sec = phdr.ts.tv_sec;
		mhdr.ts.tv_usec = phdr.ts.tv_usec;
		// Process packet
		process_packet(packet, &mhdr, -1);
	}
	//clear_stream_buffers();
}

/* init output */
void           *init_tcpdump_output_handler(char *name, int linktype)
{
	pcap_t         *readfd;
	pcap_dumper_t  *mydumper;

	readfd = pcap_open_dead(linktype, /*DLT_RAW, */ 65535);
	if (readfd == NULL) {
		pcap_perror(readfd, NULL);
		return (NULL);
	}

	if ((mydumper = pcap_dump_open(readfd, name)) == NULL) {
		printf("Error creating new trace %s\n", name);
		return NULL;
	}

	return mydumper;
}

struct sourceinfo tcpdumptraceinfo = {
	TCPDUMP_TRACE,
	open_tcpdump_trace,	/*open input */
	init_tcpdump_trace,	/*init input */
	init_tcpdump_output_handler,	/*init output */
	dump_tcpdump_packet,	/*dump packet to output */
	process_tcpdump_trace	/*process packets */
};

/****************** LIVE Traffic *****************************/

int open_nic_dev(char *dev)
{
	char            errbuf[PCAP_ERRBUF_SIZE];
	//printf(" in here\n");
	pkt_handler = (void *)pcap_open_live(dev, NIC_PKTCAP_LEN, 1, 0, errbuf);
	if (pkt_handler == NULL) {
		printf("Error in open_nic_dev: %s\n", errbuf);
		return -1;
	}
	return 1;
}

extern void     wrap_ppacket(unsigned char *, const struct pcap_pkthdr *,
			     const unsigned char *bytes);

void process_nic_data()
{
	unsigned char  *packet;

	if (pkt_handler == NULL)
		return;
	pcap_loop(pkt_handler, -1, (*wrap_ppacket), packet);
}

void init_tcpdump_nic(struct anonflow *flow)
{
	flow->link_type = pcap_datalink((pcap_t *) pkt_handler);
	flow->cap_length = pcap_snapshot((pcap_t *) pkt_handler);
	return;
}

struct sourceinfo tcpdumpnicinfo = {
	ETHERNET_NIC,
	open_nic_dev,		/*open input */
	init_tcpdump_nic,	/*init input */
	NULL,			/*init output */
	NULL,			/*dump packet to output */
	process_nic_data	/*process packets */
};
