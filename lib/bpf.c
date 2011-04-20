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

struct bpf_data {
	char           *expression;
	struct bpf_program compiled;
};

int bpf_init(va_list vl, void *fu, struct anonflow *flow)
{
	struct function *f;
	struct bpf_data *data;
	char           *tmps;
	pcap_t         *pcap;

	f = (struct function *)fu;
	data = (struct bpf_data *)malloc(sizeof(struct bpf_data));

	tmps = va_arg(vl, char *);
	data->expression = (char *)strdup(tmps);

	pcap = pcap_open_dead(flow->link_type, flow->cap_length);

	if (pcap_compile(pcap, &(data->compiled), data->expression, 1, 0)) {
		fprintf(stderr, "BPF filter compilation error\n");
		return 0;
	}

	f->internal_data = (void *)data;
	return 1;
}

int bpf_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
		anon_pkthdr_t * pkt_head)
{
	struct bpf_data *bpfd = (struct bpf_data *)internal_data;
	int             match;

	match = bpf_filter((bpfd->compiled).bf_insns, dev_pkt, pkt_head->caplen, pkt_head->wlen);

	return match;
}

struct finfo    bpf_info = {
	"BPF_FILTER",		//name
	"Filters a packet",	//descr
	bpf_init,		//init
	bpf_process,		//process
};
