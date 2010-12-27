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

struct callback_data {
	int             (*packet_callback) (unsigned char *pkt, anon_pkthdr_t * hdr);
};

int anoncallback_init(va_list vl, void *fu, struct anonflow *fl)
{
	struct function *f;
	struct callback_data *data;
	void           *tmps;

	f = (struct function *)fu;
	data = (struct callback_data *)malloc(sizeof(struct callback_data));

	tmps = va_arg(vl, void *);
	data->packet_callback = (int (*)(unsigned char *pkt, anon_pkthdr_t * hdr))tmps;
	f->internal_data = (void *)data;

	return 1;
}

int anoncallback_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
			 anon_pkthdr_t * pkt_head)
{

	int             status;
	struct callback_data *data = (struct callback_data *)internal_data;
	status = data->packet_callback((unsigned char *)dev_pkt, pkt_head);

	return status;
}

struct finfo    anoncallback_info = {
	"CALLBACK",		//name
	"Call a function for each packet",	//descr
	anoncallback_init,	//init
	anoncallback_process,	//process
};
