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
	u_long          TotPkts;
	u_long          TotAccepted;	/* accepted by filter */
	u_long          TotDrops;
	long            TotMissed;	/* missed by iface during this run */
	long            OrigMissed;	/* missed by iface before this run */
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
