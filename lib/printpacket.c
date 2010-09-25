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
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include "anonymization.h"

int anonprint_init(va_list vl, void *fu, struct anonflow *fl)
{

	return 1;
}

int anonprint_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
		      anon_pkthdr_t * pkt_head)
{
	struct pcap_pkthdr pkthdr;
	anonpacket      decoded_pkt;

	pkthdr.caplen = pkt_head->caplen;
	pkthdr.len = pkt_head->wlen;
	pkthdr.ts.tv_sec = pkt_head->ts.tv_sec;
	pkthdr.ts.tv_usec = pkt_head->ts.tv_usec;

	decode_packet(flow->link_type, flow->cap_length, &pkthdr, (unsigned char *)dev_pkt,
		      &decoded_pkt);
	PrintPacket(stdout, &decoded_pkt, flow->link_type);

	return 1;
}

struct finfo    anonprint_info = {
	"PRINT_PACKET",		//name
	"Prints a packet to standard output",	//descr
	anonprint_init,		//init
	anonprint_process,	//process
};
