/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>
#include <errno.h>
#include <config.h>
#if (HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include "checksum.h"
#include "ip_fragment.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(char *);
extern int raw_init();
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);

static struct proc_node *ip_frag_procs[MAX_LIBNIDS_INSTANCES];
static struct proc_node *ip_procs[MAX_LIBNIDS_INSTANCES];
static struct proc_node *udp_procs[MAX_LIBNIDS_INSTANCES];

struct proc_node *tcp_procs[MAX_LIBNIDS_INSTANCES];

static unsigned int linkoffset[MAX_LIBNIDS_INSTANCES];
static int linktype[MAX_LIBNIDS_INSTANCES];
static pcap_t *desc[MAX_LIBNIDS_INSTANCES];

char nids_errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    1040,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024			/* pcap_timeout */
};

static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;

    case NIDS_WARN_SCAN:
	this_host = (struct host *) data;
	sprintf(buf, "Scan from %s. Scanned ports: ",
		int_ntoa(this_host->addr));
	for (i = 0; i < this_host->n_packets; i++) {
	    strcat(buf, int_ntoa(this_host->packets[i].addr));
	    sprintf(buf + strlen(buf), ":%hu,",
		    this_host->packets[i].port);
	    flagsand &= this_host->packets[i].flags;
	    flagsor |= this_host->packets[i].flags;
	}
	if (flagsand == flagsor) {
	    i = flagsand;
	    switch (flagsand) {
	    case 2:
		strcat(buf, "scan type: SYN");
		break;
	    case 0:
		strcat(buf, "scan type: NULL");
		break;
	    case 1:
		strcat(buf, "scan type: FIN");
		break;
	    default:
		sprintf(buf + strlen(buf), "flags=0x%x", i);
	    }
	} else
	    strcat(buf, "various flags");
	syslog(nids_params.syslog_level, "%s", buf);
	break;

    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

static void pcap_hand(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
    struct proc_node *i;
    u_char *data_aligned;
	int id=0;

	if(par) {
		id=*((unsigned int *)par);
	}

	
#ifdef DLT_IEEE802_11
    unsigned short fc;
    int linkoffset_tweaked_by_prism_code = 0;
#endif
    nids_last_pcap_header = hdr;
    (void)par; /* warnings... */
    switch (linktype[id]) {
    case DLT_EN10MB:
	if (hdr->caplen < 14)
	    return;
	/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
	if (data[12] == 8 && data[13] == 0) {
	    /* Regular ethernet */
	    linkoffset[id] = 14;
	} else if (data[12] == 0x81 && data[13] == 0) {
	    /* Skip 802.1Q VLAN and priority information */
	    linkoffset[id] = 18;
	} else
	    /* non-ip frame */
	    return;
	break;
#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
    case DLT_PRISM_HEADER:
	linkoffset[id] = 144; //sizeof(prism2_hdr);
	linkoffset_tweaked_by_prism_code = 1;
        //now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
    case DLT_IEEE802_11:
	/* I don't know why frame control is always little endian, but it 
	 * works for tcpdump, so who am I to complain? (wam)
	 */
	if (!linkoffset_tweaked_by_prism_code)
		linkoffset[id] = 0;
	fc = EXTRACT_LE_16BITS(data + linkoffset[id]);
	if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
	    return;
	}
	if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	    /* a wireless distribution system packet will have another
	     * MAC addr in the frame
	     */
	    linkoffset[id] += 30;
	} else {
	    linkoffset[id] += 24;
	}
	if (hdr->len < linkoffset[id] + LLC_FRAME_SIZE)
	    return;
	if (ETHERTYPE_IP !=
	    EXTRACT_16BITS(data + linkoffset[id] + LLC_OFFSET_TO_TYPE_FIELD)) {
	    /* EAP, LEAP, and other 802.11 enhancements can be 
	     * encapsulated within a data packet too.  Look only at
	     * encapsulated IP packets (Type field of the LLC frame).
	     */
	    return;
	}
	linkoffset[id] += LLC_FRAME_SIZE;
	break;
#endif
    default:;
    }
    if (hdr->caplen < linkoffset[id])
	return;

/*
* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
* handle->offset in pcap sources), so memcpy should not be called.
*/
#ifdef LBL_ALIGN
    if ((unsigned long) (data + linkoffset[id]) & 0x3) {
	data_aligned = alloca(hdr->caplen - linkoffset[id] + 4);
	data_aligned -= (unsigned long) data_aligned % 4;
	memcpy(data_aligned, data + linkoffset[id], hdr->caplen - linkoffset[id]);
    } else
#endif
	data_aligned = data + linkoffset[id];
    for (i = ip_frag_procs[id]; i; i = i->next) {
		(i->item) (data_aligned, hdr->caplen - linkoffset[id],id);
	}
}

static void gen_ip_frag_proc(u_char * data, int len,int id)
{
    struct proc_node *i;
    struct ip *iph = (struct ip *) data;
    int need_free = 0;
    int skblen;

    if (!nids_params.ip_filter(iph, len))
	return;

    if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	//ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
	nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
	return;
    }
    if (iph->ip_hl > 5 && ip_options_compile((char *)data)) {
	nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
	return;
    }
    switch (ip_defrag_stub((struct ip *) data, &iph,id)) {
    case IPF_ISF:
	return;
    case IPF_NOTF:
	need_free = 0;
	iph = (struct ip *) data;
	break;
    case IPF_NEW:
	need_free = 1;
	break;
    default:;
    }
    skblen = ntohs(iph->ip_len) + 16;
    if (!need_free)
	skblen += nids_params.dev_addon;
    skblen = (skblen + 15) & ~15;
    skblen += nids_params.sk_buff_size;

    for (i = ip_procs[id]; i; i = i->next) {
		(i->item) (iph, skblen,id);
	}
    if (need_free)
		free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data,int id)
{
    struct proc_node *ipp = udp_procs[id];
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    if (my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data);
	ipp = ipp->next;
    }
}

int mycnt=0;
static void gen_ip_proc(u_char * data, int skblen,int id)
{
    switch (((struct ip *) data)->ip_p) {
    case IPPROTO_TCP:
	process_tcp(data, skblen,id);
	break;
    case IPPROTO_UDP:
	process_udp((char *)data,id);
	break;
    case IPPROTO_ICMP:
	if (nids_params.n_tcp_streams)
	    process_icmp(data,id);
	break;
    default:
		//printf("other!\n");
	break;
    }
}

static void init_procs(int id)
{
    ip_frag_procs[id] = mknew(struct proc_node);
    ip_frag_procs[id]->item = gen_ip_frag_proc;
    ip_frag_procs[id]->next = 0;
    ip_procs[id] = mknew(struct proc_node);
    ip_procs[id]->item = gen_ip_proc;
    ip_procs[id]->next = 0;
    tcp_procs[id] = 0;
    udp_procs[id] = 0;
}

void nids_register_udp(void (*x)) {
	nids_anon_register_udp(x,0);
}

void nids_anon_register_udp(void (*x),int id)
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = udp_procs[id];
    udp_procs[id] = ipp;
}

void nids_register_ip(void (*x)) {
	nids_anon_register_ip(x,0);
}

void nids_anon_register_ip(void (*x),int id)
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = ip_procs[id];
    ip_procs[id] = ipp;
}

void nids_register_ip_frag(void (*x),int id)
{
    struct proc_node *ipp = mknew(struct proc_node);

    ipp->item = x;
    ipp->next = ip_frag_procs[id];
    ip_frag_procs[id] = ipp;
	
}
static int open_live()
{
    char *device;
    int promisc = 0;

    if (nids_params.device == NULL)
	nids_params.device = pcap_lookupdev(nids_errbuf);
    if (nids_params.device == NULL)
	return 0;

    device = nids_params.device;
    if (!strcmp(device, "all"))
	device = "any";
    else
	promisc = (nids_params.promisc != 0);

    if ((desc[0] = pcap_open_live(device, 16384, promisc,
			       nids_params.pcap_timeout, nids_errbuf)) == NULL)
	return 0;
#ifdef __linux__
    if (!strcmp(device, "any") && nids_params.promisc
	&& !set_all_promisc()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
#endif
    if (!raw_init()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
    return 1;
}

int nids_anon_init(pcap_t *d,int ltype,int id)
{
	desc[id] = d;
	linktype[id]=ltype;
	
    switch (linktype[id]) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
    case DLT_PRISM_HEADER:
#endif
    case DLT_IEEE802_11:
	/* wireless, need to calculate offset per frame */
	break;
#endif
#ifdef DLT_NULL
    case DLT_NULL:
        linkoffset[id] = 4;
        break;
#endif        
    case DLT_EN10MB:
	linkoffset[id] = 14;
	break;
    case DLT_PPP:
	linkoffset[id] = 4;
	break;
	/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
    case DLT_IEEE802:
	linkoffset[id] = 22;
	break;

    case DLT_RAW:
    case DLT_SLIP:
	linkoffset[id] = 0;
	break;
#define DLT_LINUX_SLL   113
    case DLT_LINUX_SLL:
	linkoffset[id] = 16;
	break;
#ifdef DLT_FDDI
    case DLT_FDDI:
        linkoffset[id] = 21;
        break;
#endif        
#ifdef DLT_PPP_SERIAL 
    case DLT_PPP_SERIAL:
        linkoffset[id] = 4;
        break;
#endif        
    default:
	strcpy(nids_errbuf, "link type unknown");
	printf("UNKNOWN LINK TYPE\n");
	return 0;
    }
    if (nids_params.dev_addon == -1) {
	if (linktype[id] == DLT_EN10MB)
	    nids_params.dev_addon = 16;
	else
	    nids_params.dev_addon = 0;
    }
    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);

    init_procs(id);
    tcp_init(nids_params.n_tcp_streams,id);
    ip_frag_init(nids_params.n_hosts,id);
    scan_init();
    return 1;
}

// nids to nids_anon

int nids_init()
{
    if (nids_params.filename) {
	if ((desc[0] = pcap_open_offline(nids_params.filename,
				      nids_errbuf)) == NULL)
	    return 0;
    } else if (!open_live())
	return 0;

    if (nids_params.pcap_filter != NULL) {
	u_int mask = 0;
	struct bpf_program fcode;

	if (pcap_compile(desc[0], &fcode, nids_params.pcap_filter, 1, mask) <
	    0) return 0;
	if (pcap_setfilter(desc[0], &fcode) == -1)
	    return 0;
    }
    switch ((linktype[0] = pcap_datalink(desc[0]))) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
    case DLT_PRISM_HEADER:
#endif
    case DLT_IEEE802_11:
	/* wireless, need to calculate offset per frame */
	break;
#endif
#ifdef DLT_NULL
    case DLT_NULL:
        linkoffset[0] = 4;
        break;
#endif        
    case DLT_EN10MB:
	linkoffset[0] = 14;
	break;
    case DLT_PPP:
	linkoffset[0] = 4;
	break;
	/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
    case DLT_IEEE802:
	linkoffset[0] = 22;
	break;

    case DLT_RAW:
    case DLT_SLIP:
	linkoffset[0] = 0;
	break;
#define DLT_LINUX_SLL   113
    case DLT_LINUX_SLL:
	linkoffset[0] = 16;
	break;
#ifdef DLT_FDDI
    case DLT_FDDI:
        linkoffset[0] = 21;
        break;
#endif        
#ifdef DLT_PPP_SERIAL 
    case DLT_PPP_SERIAL:
        linkoffset[0] = 4;
        break;
#endif        
    default:
	strcpy(nids_errbuf, "link type unknown");
	return 0;
    }
    if (nids_params.dev_addon == -1) {
	if (linktype[0] == DLT_EN10MB)
	    nids_params.dev_addon = 16;
	else
	    nids_params.dev_addon = 0;
    }
    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);

    init_procs(0);
    tcp_init(nids_params.n_tcp_streams,0);
    ip_frag_init(nids_params.n_hosts,0);
    scan_init();
    return 1;
}

void nids_run()
{
    if (!desc[0]) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return;
    }
    pcap_loop(desc[0], -1, (pcap_handler) pcap_hand, 0);
    clear_stream_buffers(0);
    strcpy(nids_errbuf, "loop: ");
    strncat(nids_errbuf, pcap_geterr(desc[0]), sizeof(nids_errbuf) - 7);
    pcap_close(desc[0]);
}

int nids_getfd()
{
    if (!desc[0]) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return -1;
    }
    return pcap_fileno(desc[0]);
}


// nids to nids_anon 

int nids_anon_next(struct pcap_pkthdr *h, unsigned char* data,int id)
{
	//printf("in nids_anon_next1\n");
	int mid=id;
	
	if(!desc[id]){
		strcpy(nids_errbuf, "Libnids not initialized");
		return 0;
	}

	if(!data){
		strcpy(nids_errbuf, "next: ");
		strncat(nids_errbuf,(char *)desc[id] , sizeof(nids_errbuf) - 7);
		return 0;
	}

//	printf("in nids_anon_next2\n");
	pcap_hand((unsigned char *)(&mid), h, data);
	return 1;
}

// nids to nids_anon

int nids_next()
{
    struct pcap_pkthdr h;
    char *data;

    if (!desc[0]) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return 0;
    }
    if (!(data = (char *) pcap_next(desc[0], &h))) {
	strcpy(nids_errbuf, "next: ");
	strncat(nids_errbuf, pcap_geterr(desc[0]), sizeof(nids_errbuf) - 7);
	return 0;
    }
    pcap_hand(0, &h,(unsigned char *)data);
    return 1;
}


