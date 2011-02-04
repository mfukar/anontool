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
#include "internal.h"
#include "pcap_input.h"

unsigned char   modified_packet_buf[NIC_PKTCAP_LEN];

extern void     clear_stream_buffers();
extern struct finfo anonymize_info;
extern struct finfo anonprint_info;
extern struct finfo anoncallback_info;
extern struct finfo uncook_info;
extern struct finfo bpf_info;
extern struct finfo strsearch_info;
extern struct finfo cooking_info;

void            do_uncook_loop(struct anonflow *flow, struct function *flist);

struct anonflow *flowArray[MAX_NUM_OF_SETS];
void           *pkt_handler = NULL;
int             source_type = -1, output_type = 0;
int             autoreorder = OFF;
int             optimize = ON;
int             num_of_sets = 0;
int             sources_loaded = 0;

struct sourceinfo *search_for_registered_source(int type);

/* <antonat> */
struct registeredFuncs {
	struct finfo   *function_info;
	struct registeredFuncs *next;
};

struct registeredFuncs *registered_functions_header = NULL;

struct registeredSources {
	struct sourceinfo *source_info;
	struct registeredSources *next;
};

struct registeredSources *registered_sources_header = NULL;

/* </antonat> */

void init()
{
	memset(flowArray, 0, MAX_NUM_OF_SETS * sizeof(struct anonflow *));
}

void initSet(struct anonflow *flow)
{
	int             i;
	struct sourceinfo *info;

	memset(flow, 0, sizeof(struct anonflow));
	flow->output_type = NONE;
	flow->output_filename = NULL;
	flow->cont_set = 0;

	flow->nf9_templates = malloc(sizeof(flist_t));
	flow->nf9_option_templates = malloc(sizeof(flist_t));
	flist_init(flow->nf9_templates);
	flist_init(flow->nf9_option_templates);

	flow->ipfix_templates = malloc(sizeof(flist_t));
	flow->ipfix_options = malloc(sizeof(flist_t));
	flist_init(flow->ipfix_templates);
	flist_init(flow->ipfix_options);

	for (i = 0; i < MAX_CONT; i++)
		flow->give_output[i] = -1;

	info = search_for_registered_source(source_type);
	if (!info) {
		printf("Unknown source type in initSet\n");
		return;
	}

	if (info->init_input) {
		info->init_input(flow);
	}

	binaryGenericWgetInit();
	binaryGenericXORInit();
	binaryStuttgartInit();
	binaryWuerzburgInit();
}

int create_set()
{
	static char     inited = 0;
	int             sd;

	if (!inited) {
		inited = 1;
		init();
	}

	if (num_of_sets == MAX_NUM_OF_SETS) {
		printf("Maximum number of sets reached\n");
		return 0;
	}

	flowArray[num_of_sets] = (struct anonflow *)malloc(sizeof(struct anonflow));
	if (flowArray[num_of_sets] == NULL) {
		printf("Malloc failed\n");
		return -1;
	}
	initSet(flowArray[num_of_sets]);

	sd = num_of_sets;
	num_of_sets++;

	return sd;
}

/******** Source registering function ******************/

struct sourceinfo *search_for_registered_source(int type)
{
	struct registeredSources *f;

	f = registered_sources_header;
	while (f) {
		if (f->source_info->type == type)
			return f->source_info;
		f = f->next;
	}

	return NULL;
}

int register_source(struct sourceinfo *source_info)
{
	struct registeredSources *f, *prev = NULL, *newf;

	if (!source_info)
		return -1;

	f = registered_sources_header;
	while (f) {
		if (f->source_info->type == source_info->type) {
			printf("Source is already registered\n");
			return -1;
		}
		prev = f;
		f = f->next;
	}

	newf = (struct registeredSources *)malloc(sizeof(struct registeredSources));
	newf->source_info = source_info;
	newf->next = NULL;

	if (prev == NULL) {
		registered_sources_header = newf;
	} else {
		prev->next = newf;
	}

	return 1;

}

extern struct sourceinfo tcpdumptraceinfo;
extern struct sourceinfo tcpdumpnicinfo;

void load_sources()
{
	if (register_source(&tcpdumptraceinfo) == -1 || register_source(&tcpdumpnicinfo) == -1) {
		printf("Cannot register basic sources\n");
		exit(-1);
	}
}

/******** End of Source registering function ******************/

struct finfo   *search_for_registered_function(char *name)
{
	struct registeredFuncs *f;

	f = registered_functions_header;
	while (f) {
		if (strcmp(f->function_info->name, name) == 0)
			return f->function_info;
		f = f->next;
	}

	return NULL;
}

int register_function(struct finfo *funct_info)
{
	struct registeredFuncs *f, *prev = NULL, *newf;

	if (!funct_info)
		return -1;

	f = registered_functions_header;
	while (f) {
		if (strcmp(f->function_info->name, funct_info->name) == 0) {
			printf("Function %s is already registered\n", funct_info->name);
			return -1;
		}
		prev = f;
		f = f->next;
	}

	newf = (struct registeredFuncs *)malloc(sizeof(struct registeredFuncs));
	newf->function_info = funct_info;
	newf->next = NULL;

	if (prev == NULL) {
		registered_functions_header = newf;
	} else {
		prev->next = newf;
	}

	return 1;

}

void load_defaults()
{
	//register ANONYMIZE
	if (register_function(&anonymize_info) == -1 ||
	    register_function(&anonprint_info) == -1 ||
	    register_function(&anoncallback_info) == -1 ||
	    register_function(&uncook_info) == -1 ||
	    register_function(&bpf_info) == -1 ||
	    register_function(&cooking_info) == -1 || register_function(&strsearch_info) == -1) {
		printf("Cannot register basic anonymization functions\n");
		exit(-1);
	}
}

int add_function(int sd, char *funcName, ...)
{
	struct function *f, *flist;
	struct finfo   *function_info;
	struct anonflow *flow;
	static char     defaults_loaded = 0;
	va_list         vl;

	if (!defaults_loaded) {
		load_defaults();
		defaults_loaded = 1;
	}

	if (sd >= num_of_sets) {
		printf("Wrong set number\n");
		return -1;
	}

	flow = flowArray[sd];

	if ((function_info = search_for_registered_function(funcName)) == NULL) {
		printf("Function %s is not a registered function\n", funcName);
		return -1;
	}

	f = (struct function *)malloc(sizeof(struct function));
	f->next = NULL;

	va_start(vl, funcName);

	if (function_info->init != NULL && !function_info->init(vl, (void *)f, flow)) {
		printf("Function %s couldn't be initialized\n", funcName);
		return -1;
	}

	f->function_info = function_info;

	if (flow->function_list == NULL) {
		f->fid = 1;
		flow->function_list = f;
	} else {
		f->fid = 0;
		flist = flow->function_list;
		while (flist->next) {
			flist = flist->next;
		}
		f->fid = flist->fid + 1;
		flist->next = f;
	}

	return 1;

}

void           *init_output_handler(struct anonflow *flow)
{
	int             type;
	char           *name;
	struct sourceinfo *info;

	type = flow->output_type;
	name = flow->output_filename;

	info = search_for_registered_source(type);
	if (!info) {
		printf("Unknown output type in init_output_handler!\n");
		return NULL;
	}

	if (!info->init_output) {
		printf("This source has no output functionality\n");
		return NULL;
	}

	flow->output_info = (void *)info;

	return info->init_output(name, flow->link_type);
}

void dump_packet(struct anonflow *flow, unsigned char *packet, anon_pkthdr_t * header)
{
	int             i = 0;
	struct anonflow *fl;

	if (flow->output_handler == NULL) {
		for (i = 0; i < num_of_sets; i++) {
			fl = flowArray[i];
			if (fl->output_type != NONE && fl != flow &&
			    fl->output_filename != NULL &&
			    strcmp(flow->output_filename, fl->output_filename) == 0) {
				//another flow has the same output as we do
				if (fl->output_handler) {
					flow->output_handler = fl->output_handler;
					flow->output_info = fl->output_info;
					break;
				}
			}
		}

		if (!flow->output_handler) {
			flow->output_handler = init_output_handler(flow);
		}
	}

	if (flow->output_handler == NULL) {
		printf("Cannot write packet\n");
		return;
	}

	((struct sourceinfo *)(flow->output_info))->dump_packet(flow->output_handler, packet,
								header);
}

void free_header_list(flist_t * list, int method)
{
	flist_node_t   *node = flist_head(list), *node2;
	while (node) {
		struct headers_data *data = flist_data(node);
		node2 = flist_next(node);

		if (method == FLIST_FREE_DATA) {
			free(data->header);
			free(data);
		}

		free(node);
		node = node2;
	}
}

void process_flushed_data(struct anonflow *flow)
{
	struct function *flist;

	fprintf(stderr, "process_flushed_data\n");

	if (!flow->modifies)
		return;

	flist = flow->function_list;
	while (flist) {
		if (strcmp(flist->function_info->name, "COOKING") == 0) {
			flist = flist->next;
			break;
		}
		flist = flist->next;
	}

	while (flist) {
		if (flist->function_info->
		    process(flow, flist->internal_data, flow->mod_pkt, &flow->mod_pkt_head) == 0) {
			break;
		}

		if (flow->uncook_ready == 1) {
			fprintf(stderr, "do_uncook_loop: %d\n", flist_size(flow->client_headers));
			do_uncook_loop(flow, flist);
			break;
		} else {
			flist = flist->next;
		}
	}
}

void do_uncook_loop(struct anonflow *flow, struct function *flist)
{
	flist_node_t   *fn;
	struct function *next_func;
	struct headers_data *frag_data;

	flow->uncook_ready = 0;

	for (fn = flist_head(flow->client_headers); fn != NULL; fn = flist_next(fn)) {
		anon_pkthdr_t   frag_pkt_head;
		flow->decoded_packet = NULL;

		frag_data = (struct headers_data *)(fn->data);
		//fprintf(stderr,"(%d) frag_data->caplen: %d %d %x\n",ff++,frag_data->caplen,flist_size(flow->headers),frag_data);

		frag_pkt_head.caplen = frag_data->caplen;
		frag_pkt_head.wlen = frag_data->wlen;
		frag_pkt_head.ts.tv_sec = frag_data->ts.tv_sec;
		frag_pkt_head.ts.tv_usec = frag_data->ts.tv_usec;

		next_func = flist->next;

		while (next_func) {
			if (next_func->function_info->
			    process(flow, next_func->internal_data, frag_data->header,
				    &frag_pkt_head) == 0) {
				break;
			}
			next_func = next_func->next;
		}

		if (next_func == NULL && flow->output_type != NONE) {	//Flow reached its end
			dump_packet(flow, frag_data->header, &frag_pkt_head);
		}
	}

	return;
}

void            process_packet(unsigned char *, anon_pkthdr_t *, int);
void wrap_ppacket(unsigned char *user, const struct pcap_pkthdr *phdr, const unsigned char *bytes)
{
	anon_pkthdr_t   mhdr;
	mhdr.caplen = phdr->caplen;
	mhdr.wlen = phdr->len;
	mhdr.ts.tv_sec = phdr->ts.tv_sec;
	mhdr.ts.tv_usec = phdr->ts.tv_usec;
	process_packet((unsigned char *)bytes, &mhdr, -1);
}

void process_packet(unsigned char *packet, anon_pkthdr_t * header, int cont)
{
	struct anonflow *flow;
	struct function *flist;
	int             i = 0, j = 0, jcnt = 0, uncook_done;
	anon_pkthdr_t  *hd_temp_1 = malloc(sizeof(anon_pkthdr_t));
	anon_pkthdr_t  *hd_temp_2 = NULL;
	unsigned char  *temp_packet_buf = malloc(NIC_PKTCAP_LEN * sizeof(unsigned char));
	unsigned char  *temp_packet_buf2 = NULL;

	while (flowArray[i] != NULL && i < MAX_NUM_OF_SETS) {
		flow = flowArray[i];
		if ((cont != i) && (cont != -1)) {
			i++;
			continue;
		}
		if (flow->cont_set && (cont == -1)) {
			i++;
			continue;
		}
		flist = flow->function_list;

		flow->decoded_packet = NULL;
		flow->client_headers = NULL;
		flow->server_headers = NULL;
		memcpy(temp_packet_buf, packet, header->caplen);
		memcpy(hd_temp_1, header, sizeof(anon_pkthdr_t));

		if (flow->modifies && flow->mod_pkt != (unsigned char *)(&modified_packet_buf[0])) {
			free(flow->mod_pkt);
			flow->mod_pkt = &modified_packet_buf[0];
		}

		if (flow->modifies) {	//if we have cooking we have to copy the packet to flow->mod_pkt
			memcpy(modified_packet_buf, packet, header->caplen);
			memcpy(&flow->mod_pkt_head, header, sizeof(anon_pkthdr_t));
			flow->mod_pkt = &modified_packet_buf[0];
			if (flow->server_mod_pkt) {
				free(flow->server_mod_pkt);
				flow->server_mod_pkt = NULL;
			}
		}

		uncook_done = 0;

		while (flist) {
			if (flow->modifies) {
				if (flist->function_info->
				    process(flow, flist->internal_data, flow->mod_pkt,
					    &flow->mod_pkt_head) == 0) {
					break;
				}
			} else {
				if (flist->function_info->
				    process(flow, flist->internal_data, temp_packet_buf,
					    hd_temp_1) == 0) {
					break;
				}
			}

			if (flow->uncook_ready == 1) {
				uncook_done = 1;
				do_uncook_loop(flow, flist);
				break;
			} else {
				flist = flist->next;
			}
		}

		if (flow->client_headers) {
			free_header_list(flow->client_headers, FLIST_FREE_DATA);
			flist_init(flow->client_headers);
		}

		if (flow->server_headers) {
			if (uncook_done)
				free_header_list(flow->server_headers, FLIST_LEAVE_DATA);
			else
				free_header_list(flow->server_headers, FLIST_FREE_DATA);
			flist_init(flow->server_headers);
		}

		for (j = 0; j < MAX_CONT; j++) {
			if (flow->give_output[j] != -1) {
				temp_packet_buf2 = malloc(NIC_PKTCAP_LEN * sizeof(unsigned char));
				hd_temp_2 = malloc(sizeof(anon_pkthdr_t));
				jcnt++;
				memcpy(temp_packet_buf2, temp_packet_buf, header->caplen);
				memcpy(hd_temp_2, hd_temp_1, sizeof(anon_pkthdr_t));
				process_packet(temp_packet_buf2, hd_temp_2, flow->give_output[j]);

			}
		}

		if (jcnt == 0) {
			if (flist == NULL && flow->output_type != NONE) {	//Flow reached its end
				if (flow->modifies) {
					dump_packet(flow, flow->mod_pkt, &flow->mod_pkt_head);
				} else {
					dump_packet(flow, temp_packet_buf, hd_temp_1);
				}
			}
		}
		i++;
	}
	if (temp_packet_buf) {
		free(temp_packet_buf);
		temp_packet_buf = NULL;
	}
	if (temp_packet_buf2) {
		free(temp_packet_buf2);
		temp_packet_buf2 = NULL;
	}
	if (hd_temp_1) {
		free(hd_temp_1);
		hd_temp_1 = NULL;
	}
	if (hd_temp_2) {
		free(hd_temp_2);
		hd_temp_2 = NULL;
	}
}

int do_optimization()
{
	struct anonflow *flow = NULL;
	struct function *flist = NULL;
	int             i = 0;

	return 1;
	while (flowArray[i] != NULL && i < MAX_NUM_OF_SETS) {
		flow = flowArray[i];
		flist = flow->function_list;

		if (flist != NULL) {

			printf("flow %d\n", i);

			printf
			    ("=========================================== BEFORE =================================================\n");
			while (flist) {
				printf("%s %s\n", flist->function_info->name,
				       flist->function_info->description);

				if (strcmp(flist->function_info->name, "ANONYMIZE") == 0) {
					struct anonymize_data *data = NULL;
					data = (struct anonymize_data *)(flist->internal_data);

					if (data->protocol == IP) {
						printf("IP\n");
					} else if (data->protocol == TCP) {
						printf("TCP\n");
					} else if (data->protocol == UDP) {
						printf("UDP\n");
					} else if (data->protocol == HTTP) {
						printf("HTTP\n");
					} else if (data->protocol == FTP) {
						printf("FTP\n");
					}

					printf("id %d protocol %d name %d\n", flist->fid,
					       data->protocol, data->field);
				} else if (strcmp(flist->function_info->name, "COOKING") == 0) {
					printf("COOKING\n");
				} else if (strcmp(flist->function_info->name, "UNCOOK") == 0) {
					printf("UNCOOK\n");
				}

				flist = flist->next;
			}

			printf
			    ("=================================================================================================\n");

			printf("\n\n");

			flist = flow->function_list;
		}
		i++;
	}
	return 1;
}

int reordering()
{
	struct anonflow *flow = NULL;
	struct function *flist = NULL, *prev = NULL, *next = NULL, *input = NULL;
	struct function *cookingf = NULL, *uncookf = NULL;
	struct function *fproto = NULL, *lproto = NULL;
	struct function *prevfproto = NULL, *prevlproto = NULL;
	int             i = 0;
	int             upper = OFF;
	int             status = 0;

	while (flowArray[i] != NULL && i < MAX_NUM_OF_SETS) {
		flow = flowArray[i];
		flist = flow->function_list;

		if (flist != NULL) {

#ifdef DEBUG
			printf("flow %d\n", i);

			printf
			    ("=========================================== BEFORE =================================================\n");
			while (flist) {
				printf("%s %s\n", flist->function_info->name,
				       flist->function_info->description);

				if (strcmp(flist->function_info->name, "ANONYMIZE") == 0) {
					struct anonymize_data *data = NULL;
					data = (struct anonymize_data *)(flist->internal_data);

					if (data->protocol == IP) {
						printf("IP\n");
					} else if (data->protocol == TCP) {
						printf("TCP\n");
					} else if (data->protocol == UDP) {
						printf("UDP\n");
					} else if (data->protocol == HTTP) {
						printf("HTTP\n");
					} else if (data->protocol == FTP) {
						printf("FTP\n");
					}

					printf("id %d protocol %d name %d\n", flist->fid,
					       data->protocol, data->field);
				} else if (strcmp(flist->function_info->name, "COOKING") == 0) {
					printf("COOKING\n");
				} else if (strcmp(flist->function_info->name, "UNCOOK") == 0) {
					printf("UNCOOK\n");
				}

				flist = flist->next;
			}

			printf
			    ("=================================================================================================\n");

			printf("\n\n");

			flist = flow->function_list;
#endif

// DO the reordering

			flist = flow->function_list;
			input = flist;

			while (flist != NULL) {
				next = flist->next;

				if (strcmp(flist->function_info->name, "ANONYMIZE") == 0) {
					struct anonymize_data *data = NULL;
					data = (struct anonymize_data *)(flist->internal_data);

					if ((data->protocol != HTTP) & (data->protocol !=
									FTP) & (data->field !=
										CHECKSUM)) {
						if (flist != input) {
							if (prev != NULL) {
								prev->next = flist->next;
								flist->next = input->next;
								input->next = flist;
								input = flist;
								flist = prev->next;
							}
						}

					}

				}

				prev = flist;

				if (flist)
					flist = flist->next;
			}

			flist = flow->function_list;
			input = flist;

			while (flist != NULL) {
				next = flist->next;

				if (strcmp(flist->function_info->name, "ANONYMIZE") == 0) {
					struct anonymize_data *data = NULL;
					data = (struct anonymize_data *)(flist->internal_data);

					if ((data->protocol == HTTP) | (data->protocol == FTP)) {
						upper = ON;

						if (fproto == NULL) {
							prevfproto = prev;
							fproto = flist;
						}

						prevlproto = prev;
						lproto = flist;
					}
				} else if (strcmp(flist->function_info->name, "COOKING") == 0) {
					cookingf = flist;
				} else if (strcmp(flist->function_info->name, "UNCOOK") == 0) {
					uncookf = flist;
				}

				prev = flist;

				if (flist)
					flist = flist->next;
			}

			if (upper == ON) {
				if (cookingf == NULL) {
					// add cooking and uncooking
					status = add_function(i, "COOKING", 50000, 10);

					if (status == -1) {
						printf
						    ("error: can not auto-add cooking function\n");
						return -1;
					}
				}

				if (uncookf == NULL) {
					// add cooking and uncooking
					status = add_function(i, "UNCOOK");

					if (status == -1) {
						printf("error: can not auto-add uncook function\n");
						return -1;
					}
				}
			}

			cookingf = uncookf = NULL;

			flist = flow->function_list;
			input = flist;

			while (flist != NULL) {
				next = flist->next;

				if (strcmp(flist->function_info->name, "COOKING") == 0) {
					if (upper == ON) {
						if (cookingf == NULL) {
							// move before firstproto

							if (flist->next != fproto) {
								cookingf = flist;
								prev->next = flist->next;
								cookingf->next = fproto;
								prevfproto->next = cookingf;
								flist = prev;
							}
						} else {
							// remove function cause is duplicate
							struct function *temp;
							prev->next = flist->next;
							temp = flist;
							flist = prev;
							free(temp);
						}
					} else {
						// remove function cause is not needed
						struct function *temp;
						prev->next = flist->next;
						temp = flist;
						flist = prev;
						free(temp);
					}

				} else if (strcmp(flist->function_info->name, "UNCOOK") == 0) {
					if (upper == ON) {
						if (uncookf == NULL) {
							// move after lastproto
							uncookf = flist;
							prev->next = flist->next;
							uncookf->next = lproto->next;
							lproto->next = uncookf;
							flist = prev;
						} else {
							struct function *temp;
							// remove function cause is duplicate
							prev->next = flist->next;
							temp = flist;
							flist = prev;
							free(temp);
						}
					} else {
						struct function *temp;
						// remove function cause is duplicate
						prev->next = flist->next;
						temp = flist;
						flist = prev;
						free(temp);
					}
				}

				prev = flist;

				if (flist)
					flist = flist->next;
			}

#ifdef DEBUG
			printf
			    ("=========================================== AFTER =================================================\n");
			flist = flow->function_list;
			while (flist != NULL) {
				printf("%s %s\n", flist->function_info->name,
				       flist->function_info->description);

				if (strcmp(flist->function_info->name, "ANONYMIZE") == 0) {
					struct anonymize_data *data = NULL;
					data = (struct anonymize_data *)(flist->internal_data);

					if (data->protocol == IP) {
						printf("IP\n");
					} else if (data->protocol == TCP) {
						printf("TCP\n");
					} else if (data->protocol == UDP) {
						printf("UDP\n");
					} else if (data->protocol == HTTP) {
						printf("HTTP\n");
					} else if (data->protocol == FTP) {
						printf("FTP\n");
					}

					printf("id %d protocol %d name %d\n", flist->fid,
					       data->protocol, data->field);

					if (data->field == CHECKSUM)
						printf("CHECKSUM\n");
				} else if (strcmp(flist->function_info->name, "COOKING") == 0) {
					printf("COOKING\n");
				} else if (strcmp(flist->function_info->name, "UNCOOK") == 0) {
					printf("UNCOOK\n");
				}

				flist = flist->next;
			}

			printf
			    ("=================================================================================================\n");

			printf("\n\n");
#endif
		}

		i++;
	}

	return 1;
}

int set_source(int type, char *filename)
{
	struct sourceinfo *info;

	if (!sources_loaded) {
		load_sources();
		sources_loaded = 1;
	}

	info = search_for_registered_source(type);
	if (!info) {
		printf("Unknown source type\n");
		return -1;
	}

	source_type = type;
	if (!info->open_input) {
		printf("This source does not support input functionality\n");
		return -1;
	}

	return info->open_input(filename);

}

int set_cont_set(int sd, int type)
{
	struct anonflow *flow;

	if (sd >= num_of_sets) {
		printf("Wrong set number\n");
		return -1;
	}
	flow = flowArray[sd];
	flow->cont_set = type;
	return 1;
}

int append_get_anon(int sd, int cnt_fl)
{
	struct anonflow *flow;
	int             i;

	if (sd >= num_of_sets) {
		printf("Wrong set number\n");
		return -1;
	}
	flow = flowArray[sd];
	for (i = 0; i < MAX_CONT; i++) {
		if (flow->give_output[i] == -1) {
			flow->give_output[i] = cnt_fl;
			break;
		}
	}
	return 1;
}

int set_output(int sd, int type, char *filename)
{
	struct anonflow *flow;
	struct sourceinfo *info;

	if (sd >= num_of_sets) {
		printf("Wrong set number\n");
		return -1;
	}

	if (!sources_loaded) {
		printf("No sources loaded! Perhaps no set_source defined previously\n");
		return -1;
	}

	info = search_for_registered_source(type);
	if (!info) {
		printf("Unknown source type\n");
		return -1;
	}

	if (!info->init_output) {
		printf("This source does not support output functionality\n");
		return -1;
	}

	flow = flowArray[sd];
	flow->output_type = type;
	flow->output_filename = (char *)strdup(filename);

	return 1;
}

void auto_reorder(int state)
{
	autoreorder = state;
}

void set_optimize(int state)
{
	optimize = state;
}

void start_processing()
{
	struct sourceinfo *info;

	if (autoreorder == ON) {
		if (reordering() == -1) {
			fprintf(stderr, "Error during reordering.. Exiting\n");
			return;
		}
	}

	if (optimize == ON) {
		if (do_optimization() == -1) {
			fprintf(stderr, "Error during optimization.. Exiting\n");
			return;
		}
	}

	info = search_for_registered_source(source_type);
	if (!info) {
		fprintf(stderr, "Unknown source type.\n");
		return;
	}

	if (!info->process_packets) {
		fprintf(stderr, "This source does not support process packet functionality.\n");
		return;
	}

	info->process_packets();
	return;
}
