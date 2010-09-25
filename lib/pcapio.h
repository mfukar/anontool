/*
 * Copyright (c) 2002,2003 Endace Technology Ltd, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This source code is proprietary to Endace Technology Limited and no part
 * of it may be redistributed, published or disclosed except as outlined in
 * the written contract supplied with this product.
 *
 * $Id: pcapio.h,v 1.1.1.1 2006/11/14 13:35:28 antonat Exp $
 *
 * Savefile
 */
struct pcap_sf {
	FILE           *rfile;
	int             swapped;
	int             version_major;
	int             version_minor;
	u_char         *base;
};

struct pcap_md {
	struct pcap_stat stat;
	                /*XXX*/ int use_bpf;
	u_long          TotPkts;	/* can't oflow for 79 hrs on ether 
					 */
	u_long          TotAccepted;	/* count accepted by filter */
	u_long          TotDrops;	/* count of dropped packets */
	long            TotMissed;	/* missed by i/f during this run */
	long            OrigMissed;	/* missed by i/f before this run */
#ifdef linux
	int             pad;
	int             skip;
	char           *device;
#endif
};

struct pcap {
	int             fd;
	int             snapshot;
	int             linktype;
	int             tzoff;	/* timezone offset */
	int             offset;	/* offset for proper alignment */
	struct pcap_sf  sf;
	struct pcap_md  md;
	int             bufsize;	/* read buffer */
	u_char         *buffer;
	u_char         *bp;
	int             cc;
	u_char         *pkt;	/* place holder for pcap_next() */
	struct bpf_program fcode;	/* place holder for filter code if 
					 * bpf not in kernel */
	char            errbuf[PCAP_ERRBUF_SIZE];
};

#ifndef min
#define min(a, b) ((a) > (b) ? (b) : (a))
#endif
