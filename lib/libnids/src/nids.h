/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
#define _NIDS_NIDS_H
#define NIDS_MAJOR 1
#define NIDS_MINOR 19
#include <sys/types.h>
#include <pcap.h>

#include "../../flist.h"

enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

#define NIDS_JUST_EST 1
#define NIDS_DATA 2
#define NIDS_CLOSE 3
#define NIDS_RESET 4
#define NIDS_TIMED_OUT 5
#define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

#define INCR_SIZE 1000000 //antonat
struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  char state;
  char collect;
  char collect_urg;

  char *data;
  char *reassembled_data;
 // int read;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_int curr_ts; 
  struct skbuff *list;
  struct skbuff *listtail;
 
 int read;
 int total_read;
 int pkt_count;
 flist_t *headers;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
 int client_reassembly_limit;
 int server_reassembly_limit;
 void *flow;
};

struct nids_prm
{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
};

int nids_init ();
int nids_anon_init(pcap_t *,int linktype,int id);
void nids_register_ip_frag (void (*),int id);
void nids_anon_register_ip (void (*),int id);
void nids_register_ip (void (*));
void nids_anon_register_tcp (void (*),int id);
void nids_register_tcp (void (*));
void nids_anon_register_udp (void (*),int id);
void nids_register_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
void nids_run ();
int nids_getfd ();
int nids_anon_next(struct pcap_pkthdr *h, unsigned char* data,int id);
int nids_next ();

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *last_pcap_header;


#define MAX_LIBNIDS_INSTANCES 32768

#endif /* _NIDS_NIDS_H */
