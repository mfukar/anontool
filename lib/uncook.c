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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "anonymization.h"

int uncook_init(va_list vl, void *fu, struct anonflow *flow)
{
	return 1;
}

extern int      client_size, server_size;
extern char    *ret_client_data;
extern char    *ret_server_data;

void rebuild_fragments(struct anonflow *flow, flist_t * list, unsigned char *payload,
		       int large_payload_size)
{
	flist_node_t   *n, *prev;
	struct headers_data *data;
	int             p_offset = 0;
	anonpacket      frag_decoded;
	struct pcap_pkthdr pkthdr;
	int             cnt = 0;

	if (!list) {
		fprintf(stderr, "No list report in rebuild_fragments\n");
		return;
	}

	if (!payload) {
		//fprintf(stderr,"No payload report in rebuild_fragments\n");
		return;
	}

	for (n = flist_head(list); n != NULL; prev = n, n = flist_next(n)) {
		data = (struct headers_data *)(n->data);
		pkthdr.caplen = data->caplen;
		pkthdr.len = data->wlen;
		pkthdr.ts.tv_sec = data->ts.tv_sec;
		pkthdr.ts.tv_usec = data->ts.tv_usec;

		decode_packet(flow->link_type, flow->cap_length, &pkthdr,
			      (unsigned char *)(data->header), &frag_decoded);
		if (frag_decoded.dsize == 0) {
			continue;
		}

		if ((large_payload_size - p_offset) == 0)
			break;

		if (frag_decoded.dsize >= (uint16_t) (large_payload_size - p_offset)) {
			int             fit_len = frag_decoded.dsize;
			if (frag_decoded.dsize > (uint16_t) (large_payload_size - p_offset))
				fit_len = (large_payload_size - p_offset);
			memcpy(frag_decoded.data, payload + p_offset, fit_len);
			p_offset += frag_decoded.dsize;
		} else {
			int             new_frag_size;
			new_frag_size = frag_decoded.dsize;

			if (p_offset < large_payload_size) {	//copy the rest
				memcpy(frag_decoded.data, payload + p_offset, new_frag_size);
			}

			p_offset += new_frag_size;
		}

		cnt++;
	}

	if ((large_payload_size - p_offset) > 0) {
		fprintf(stderr, "remaining: %d\n", large_payload_size - p_offset);
		fprintf(stderr, "wtf!!! %s %d %d\n", inet_ntoa(frag_decoded.iph->ip_src),
			ntohs(frag_decoded.tcph->th_sport), ntohs(frag_decoded.tcph->th_dport));
		fprintf(stderr, "wtf!!! %s\n", inet_ntoa(frag_decoded.iph->ip_dst));
		return;
	}

	if ((large_payload_size - p_offset) > 0) {
		data = (struct headers_data *)prev->data;
		data->caplen = data->wlen = data->caplen + large_payload_size - p_offset;
		fprintf(stderr, "I have %d flow headers and there are %d bytes remaining \n", cnt,
			large_payload_size - p_offset);
		fprintf(stderr, "new data caplen: %d\n", data->caplen);
		pkthdr.caplen = data->caplen;
		pkthdr.len = data->wlen;

		//frag_decoded points contains the last decoded packet
		memcpy(frag_decoded.data + frag_decoded.dsize, payload + p_offset,
		       large_payload_size - p_offset);

		if (frag_decoded.iph) {
			int             previous_len = ntohs(frag_decoded.iph->ip_len);
			previous_len += (large_payload_size - p_offset);
			frag_decoded.iph->ip_len = ntohs(previous_len);
		}
	}
}

flist_t        *merge_lists(flist_t * cl, flist_t * sv)
{
	flist_node_t   *n, *g;
	struct headers_data *sv_data, *cl_data;

	if (cl && !sv)
		return cl;
	if (sv && !cl)
		return sv;
	if (!sv && !cl)
		return NULL;

	for (n = flist_head(sv); n != NULL; n = flist_next(n)) {
		sv_data = (struct headers_data *)(n->data);
		for (g = flist_head(cl); g != NULL; g = flist_next(g)) {
			cl_data = (struct headers_data *)(g->data);
			if (cl_data->ts.tv_sec > sv_data->ts.tv_sec
			    || (cl_data->ts.tv_sec == sv_data->ts.tv_sec
				&& cl_data->ts.tv_usec >= sv_data->ts.tv_usec))
				break;
		}

		if (g == NULL)
			flist_append(cl, 0, (void *)sv_data);
		else
			flist_insert_before(cl, g, (void *)sv_data);
	}

	return cl;

}

int uncook_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
		   anon_pkthdr_t * pkt_head)
{

	if (flow->client_headers || flow->server_headers) {
		flow->uncook_ready = 1;

		//fprintf(stderr,"client : %d - %d %x\n",client_size,flist_size(flow->client_headers),flow->client_headers);
		//fprintf(stderr,"server : %d - %d %x\n",server_size,flist_size(flow->server_headers),flow->server_headers);

		if (flow->decoded_packet != NULL) {
			rebuild_fragments(flow, flow->client_headers, flow->decoded_packet->data,
					  flow->client_size);
		} else {
			rebuild_fragments(flow, flow->client_headers, flow->ret_client_data,
					  flow->client_size);
		}

		//rebuild_fragments(flow,flow->server_headers,ret_server_data,server_size);     

		flow->client_headers = merge_lists(flow->client_headers, flow->server_headers);
	}

	return 1;
}

struct finfo    uncook_info = {
	"UNCOOK",		//name
	"Uncooks a stream back to the original packets",	//descr
	uncook_init,		//init
	uncook_process,		//process
};
