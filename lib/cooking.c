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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "libnids/src/nids.h"
#include "cooking.h"
#include "pcapio.h"

#define COOKING "COOKING"
#define SERVER 0
#define CLIENT 1
#define FRAG_BUF_SIZE 16*1024

#define CHECKED 15
#define NON_CHECKED 16

/* #define COOK_DEBUG 1*/

static int			threshold = 0;
static unsigned int		timeout = 0;
unsigned char			*to_free = NULL;
unsigned char			*to_free2 = NULL;
extern struct pcap_pkthdr	*nids_last_pcap_header;
static int			cooking_id = 0;
unsigned char			*last_dev_pkt;

int				status;

extern struct tcp_stream *find_stream(struct tcphdr *this_tcphdr, struct ip *this_iphdr,
				      int *from_client, int id);
extern void     process_flushed_data(struct anonflow *flow);

/* extern struct anonflow *flowArray[MAX_NUM_OF_SETS]; */

int             callbacks = 0;

void tcp_callback(struct tcp_stream *ns, void **param)
{
	struct anonflow *flow = (struct anonflow *)(ns->flow);

	callbacks++;

	if(ns->nids_state == NIDS_JUST_EST) {
		ns->client.collect++;
		if(threshold == -1) {
			ns->client.reassembled_data = NULL;
			ns->client_reassembly_limit = 0;
		} else {
			ns->client.reassembled_data =
			    malloc(sizeof(char) * threshold + 2000);
		}
		ns->client.read = 0;
		ns->client.total_read = 0;
		if(ns->client.headers == NULL) {
			fprintf(stderr, "Initing 2..\n");
			ns->client.headers = malloc(sizeof(flist_t));
			flist_init(ns->client.headers);
		}
		ns->client.pkt_count = 0;

		// and by a server
		ns->server.collect++;
		if(threshold == -1) {
			ns->server.reassembled_data = NULL;
			ns->server_reassembly_limit = 0;
		} else {
			ns->server.reassembled_data =
			    malloc(sizeof(char) * threshold + 2000);
		}

		ns->server.read = 0;
		ns->server.total_read = 0;
		if(ns->server.headers == NULL) {
			ns->server.headers = malloc(sizeof(flist_t));
			flist_init(ns->server.headers);
		}
		ns->server.pkt_count = 0;
		ns->flow = NULL;
		return;
	}

	status = CHECKED;

	if(ns->nids_state == NIDS_EXITING) {

		flow->ret_client_data = (unsigned char *)ns->client.reassembled_data;
		flow->ret_server_data = (unsigned char *)ns->server.reassembled_data;
		flow->client_size = ns->client.read;
		flow->server_size = ns->server.read;
		flow->ret_client_headers = ns->client.headers;
		flow->ret_server_headers = ns->server.headers;

		create_mod_pkt(last_dev_pkt, flow, &flow->mod_pkt_head);
		process_flushed_data(flow);
		return;
	}

	if(ns->nids_state == NIDS_CLOSE || ns->nids_state == NIDS_RESET
	   || ns->nids_state == NIDS_TIMED_OUT || ns->nids_state == NIDS_EXITING) {

		if(to_free != NULL) {
			free(to_free);
			to_free = NULL;
		}
		if(to_free2 != NULL) {
			free(to_free2);
			to_free2 = NULL;
		}

		if(ns->client.total_read < ns->client.count || threshold == -1) {
			if(flow->ret_client_data == NULL) {
				flow->ret_client_data =
				    (unsigned char *)ns->client.reassembled_data;
				flow->ret_server_data =
				    (unsigned char *)ns->server.reassembled_data;

				to_free = flow->ret_client_data;
				to_free2 = flow->ret_server_data;

				flow->client_size = ns->client.read;
				flow->server_size = ns->server.read;

				flow->ret_client_headers = ns->client.headers;
				flow->ret_server_headers = ns->server.headers;

				return;
			}
		} else if(ns->server.total_read < ns->server.count || threshold == -1) {
			if(flow->ret_server_data == NULL) {
				flow->ret_server_data =
				    (unsigned char *)ns->server.reassembled_data;
				flow->ret_client_data =
				    (unsigned char *)ns->client.reassembled_data;
				to_free = flow->ret_server_data;
				to_free2 = flow->ret_client_data;

				flow->server_size = ns->server.read;
				flow->client_size = ns->client.read;

				flow->ret_server_headers = ns->server.headers;
				flow->ret_client_headers = ns->client.headers;

				return;
			}
		}

		return;
	}

	if(ns->nids_state == NIDS_DATA) {
		if(ns->client.count_new) {
			char           *dest = NULL;
			ns->client.pkt_count++;

			if(threshold == -1) {
				if((ns->client.read + ns->client.count_new) >
				   ns->client_reassembly_limit) {
					ns->client.reassembled_data =
					    realloc(ns->client.reassembled_data,
						    ns->client_reassembly_limit + INCR_SIZE);
					ns->client_reassembly_limit += INCR_SIZE;
				}

				dest = &ns->client.reassembled_data[ns->client.read];
				ns->client.total_read = ns->client.count;
				ns->client.read += (ns->client.count_new);
				memcpy(dest, ns->client.data, ns->client.count_new);
				return;
			}

			if((ns->client.read + ns->client.count_new) > threshold) {
				dest = &ns->client.reassembled_data[ns->client.read];

				flow->ret_client_headers = ns->client.headers;
				flow->ret_client_data =
				    (unsigned char *)ns->client.reassembled_data;
				flow->client_size = ns->client.read + ns->client.count_new;
				ns->client.total_read = ns->client.count;
				ns->client.read = 0;

				flow->ret_server_headers = ns->server.headers;
				flow->ret_server_data =
				    (unsigned char *)ns->server.reassembled_data;
				flow->server_size = ns->server.read;
				ns->server.total_read = ns->server.count;
				ns->server.read = 0;

				memcpy(dest, ns->client.data, ns->client.count_new);
				return;
			} else if((ns->client.count - ns->client.count_new) == 0) {
				dest = ns->client.reassembled_data;
			} else {
				dest = &ns->client.reassembled_data[ns->client.read];
			}

			memcpy(dest, ns->client.data, ns->client.count_new);
			ns->client.read += (ns->client.count_new);
		}

		if(ns->server.count_new) {
			char           *dest = NULL;
			ns->server.pkt_count++;

			if(threshold == -1) {
				if((ns->server.read + ns->server.count_new) >
				   ns->server_reassembly_limit) {
					ns->server.reassembled_data =
					    realloc(ns->server.reassembled_data,
						    ns->server_reassembly_limit + INCR_SIZE);
					ns->server_reassembly_limit += INCR_SIZE;
				}

				dest = &ns->server.reassembled_data[ns->server.read];
				ns->server.total_read = ns->server.count;
				ns->server.read += (ns->server.count_new);
				memcpy(dest, ns->server.data, ns->server.count_new);
				return;
			}

			if((ns->server.read + ns->server.count_new) > threshold) {
				dest = &ns->server.reassembled_data[ns->server.read];

				flow->ret_server_headers = ns->server.headers;
				flow->ret_server_data =
				    (unsigned char *)ns->server.reassembled_data;
				flow->server_size = ns->server.read + ns->server.count_new;

				flow->ret_client_headers = ns->client.headers;
				flow->ret_client_data =
				    (unsigned char *)ns->client.reassembled_data;
				flow->client_size = ns->client.read;
				ns->client.total_read = ns->client.count;
				ns->client.read = 0;

				ns->server.total_read = ns->server.count;
				ns->server.read = 0;

				memcpy(dest, ns->server.data, ns->server.count_new);
				return;
			} else if((ns->server.count - ns->server.count_new) == 0) {
				dest = ns->server.reassembled_data;
			} else {
				dest = &ns->server.reassembled_data[ns->server.read];
			}
			memcpy(dest, ns->server.data, ns->server.count_new);
			ns->server.read += ns->server.count_new;
		}
	}

	return;
}

static int cook_init(va_list vl, void *fu, struct anonflow *fl)
{
	// used by libnids
	struct pcap     desc;
	int             tmp;
	struct function *funct = (struct function *)fu;

	// cooking data
	struct cooking_data *data = malloc(sizeof(struct cooking_data));
	tmp = va_arg(vl, int);	//threshold
	data->threshold = tmp;

	tmp = va_arg(vl, int);	//timeout
	data->timeout = tmp;
	data->id = cooking_id;
	cooking_id++;

	desc.fd = 1;
	desc.linktype = fl->link_type;
	desc.bufsize = fl->cap_length;

	nids_anon_init(&desc, fl->link_type, data->id);
	nids_anon_register_tcp(tcp_callback, data->id);

	if(data->threshold <= 0) {
		data->threshold = -1;
	}

	funct->internal_data = (void *)data;
	fl->modifies = 1;

	return 1;
}

/* 
 * return 1 in order for processing to continue in other functions
 * return 0 otherwise
 */

int cook_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
		 anon_pkthdr_t * pkt_head)
{
	struct pcap_pkthdr h;
	ether_header   *eth = NULL;
	struct ip      *iph;
	struct tcphdr  *tcph;
	int             ether_len = 0, ip_len = 0;
	struct headers_data *headers;
	struct cooking_data *data = (struct cooking_data *)internal_data;

	last_dev_pkt = dev_pkt;

	h.caplen = pkt_head->caplen;
	h.len = pkt_head->wlen;
	h.ts.tv_sec = pkt_head->ts.tv_sec;
	h.ts.tv_usec = pkt_head->ts.tv_usec;

	threshold = data->threshold;
	timeout = data->timeout;

	status = NON_CHECKED;

	flow->ret_client_data = NULL;
	flow->ret_server_data = NULL;
	flow->client_size = flow->server_size = 0;

	callbacks = 0;

	eth = (ether_header *) dev_pkt;
	ether_len = sizeof(ether_header);
	iph = (struct ip *)(dev_pkt + ether_len);
	ip_len = (iph->ip_hl & 0xf) * 4;
	if(iph->ip_p != IPPROTO_TCP)	// no TCP packet
		return 1;

	nids_anon_next(&h, dev_pkt, data->id);

	if(status == NON_CHECKED) {
		struct tcp_stream *stream;
		int             from_client;

		tcph = (struct tcphdr *)(dev_pkt + ether_len + ip_len);

		stream = find_stream(tcph, iph, &from_client, data->id);
		if(stream) {
			headers = malloc(sizeof(struct headers_data));
			headers->header = malloc(pkt_head->caplen);	//added 100 more bytes
			memcpy(headers->header, dev_pkt, pkt_head->caplen);
			headers->caplen = pkt_head->caplen;
			headers->wlen = pkt_head->wlen;
			headers->ts.tv_sec = pkt_head->ts.tv_sec;
			headers->ts.tv_usec = pkt_head->ts.tv_usec;
			if(from_client == 0) {
				if(stream->client.headers == NULL) {
					stream->client.headers = malloc(sizeof(flist_t));
					flist_init(stream->client.headers);
				}
				flist_append(stream->client.headers, stream->client.pkt_count,
					     (void *)headers);
			} else {
				if(stream->server.headers == NULL) {
					stream->server.headers = malloc(sizeof(flist_t));
					flist_init(stream->server.headers);
				}
				flist_append(stream->server.headers, stream->server.pkt_count,
					     (void *)headers);
			}
			stream->flow = (void *)flow;
		} else {	//unsolicited data
			//fprintf(stderr,"Stream not found\n");
			return 1;
		}
		return 0;
	} else {
		struct tcp_stream *stream;
		int             from_client;

		tcph = (struct tcphdr *)(dev_pkt + ether_len + ip_len);

		headers = malloc(sizeof(struct headers_data));
		headers->header = malloc(pkt_head->caplen);
		memcpy(headers->header, dev_pkt, pkt_head->caplen);
		headers->caplen = pkt_head->caplen;
		headers->wlen = pkt_head->wlen;
		headers->ts.tv_sec = pkt_head->ts.tv_sec;
		headers->ts.tv_usec = pkt_head->ts.tv_usec;

		stream = find_stream(tcph, iph, &from_client, data->id);
		if(stream == NULL) {
			create_mod_pkt(dev_pkt, flow, pkt_head);
			flist_append(flow->server_headers, 0, (void *)headers);
			return 1;
		}

		stream->flow = (void *)flow;

		if(from_client == 0) {
			if(stream->client.headers == NULL) {
				stream->client.headers = malloc(sizeof(flist_t));
				flist_init(stream->client.headers);
			}
			flist_append(stream->client.headers, stream->client.pkt_count,
				     (void *)headers);
		} else {
			if(stream->server.headers == NULL) {
				stream->server.headers = malloc(sizeof(flist_t));
				flist_init(stream->server.headers);
			}
			flist_append(stream->server.headers, stream->server.pkt_count,
				     (void *)headers);
		}
	}

	if(flow->ret_client_data != NULL || flow->ret_server_data != NULL) {
		// Set pseudoheader and new cooked packet to return to the daemon
		create_mod_pkt(dev_pkt, flow, pkt_head);
		return 1;
	}

	return 0;
}

void create_mod_pkt(unsigned char *dev_pkt, struct anonflow *flow, anon_pkthdr_t * pkt_head)
{

	ether_header   *eth = NULL;
	ip_header      *ip = NULL;
	tcp_header     *tcp = NULL;
	int             ether_len = 0, ip_len = 0, tcp_len = 0;

	eth = (ether_header *) dev_pkt;
	ether_len = sizeof(ether_header);
	ip = (ip_header *) (dev_pkt + ether_len);
	ip_len = (ip->ver_ihl & 0xf) * 4;

	tcp = (tcp_header *) (dev_pkt + ether_len + ip_len);
	tcp_len = tcp->off * 4;
	tcp->seq = 0;

	ip->tlen = ntohs(flow->client_size + ip_len + tcp_len);

	flow->mod_pkt = malloc(sizeof(char) * (flow->client_size + ether_len + ip_len + tcp_len));
	if(flow->mod_pkt == NULL) {
		exit(-1);
	}
	memcpy(flow->mod_pkt, eth, ether_len);
	memcpy(&flow->mod_pkt[ether_len], ip, ip_len);
	memcpy(&flow->mod_pkt[ether_len + ip_len], tcp, tcp_len);

	memcpy(&flow->mod_pkt[ether_len + ip_len + tcp_len], flow->ret_client_data,
	       flow->client_size);

	//server packet
	flow->server_mod_pkt = malloc(sizeof(char) * (flow->server_size + ether_len + ip_len + tcp_len));
	if(flow->server_mod_pkt == NULL) {
		exit(-1);
	}
	memcpy(flow->server_mod_pkt, eth, ether_len);
	memcpy(&flow->server_mod_pkt[ether_len], ip, ip_len);
	memcpy(&flow->server_mod_pkt[ether_len + ip_len], tcp, tcp_len);
	memcpy(&flow->server_mod_pkt[ether_len + ip_len + tcp_len], flow->ret_server_data,
	       flow->server_size);
	flow->server_mod_pkt_head.caplen = flow->server_mod_pkt_head.wlen =
	    flow->server_size + ether_len + ip_len + tcp_len;

	flow->client_headers = flow->ret_client_headers;
	flow->server_headers = flow->ret_server_headers;

	pkt_head->caplen = flow->client_size + ether_len + ip_len + tcp_len;
	pkt_head->wlen = flow->client_size + ether_len + ip_len + tcp_len;
}

struct finfo    cooking_info = {
	COOKING,		//name
	"Cooking TCP/IP packets\nParameters:\n\tthreshold : int\n\ttimeout : int\n",	//Description
	cook_init,
	cook_process
};
