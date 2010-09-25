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
#ifndef _PROTOCOLS_H_
#define _PROTOCOLS_H_

/////////////////////////////////////////////////////////////////////

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_PSH|TCP_ACK|TCP_URG)

/* normal TCP states */
#define LISTEN       1
#define SYN_RCVD     2
#define SYN_SENT     3
#define ESTB         4
#define FIN_RCVD     5
#define FIN_SENT     6
#define CLOSED       7

/////////////////////////////////////////////////////////////////////

/* 4 bytes IP address */
typedef struct ip_addr
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_addr;

////////////////////////////////////////////////////////////////////

// Ethernet header
typedef struct ether_header
{
	u_char  ether_dhost[6]; //Destination host address
	u_char  ether_shost[6]; //Source host address
	u_short ether_type;     //IP? ARP? RARP? etc
} ether_header;

////////////////////////////////////////////////////////////////////

// IPv4 header
typedef struct ip_header
{
	u_char  ver_ihl;         //Version (4 bits) + IP header length (4 bits)
	u_char  tos;             //Type of service
	u_short tlen;            //Total length
	u_short id;              //Identification
	u_short off;             //Flags (3 bits) + Fragment offset (13 bits)
#define DF off & 0x4000
#define MF off & 0x2000
#define FRAG_OFF off & 0x1fff
	u_char  ttl;             //Time to live
	u_char  ptcl;            //Protocol
	u_short sum;             //Header checksum
	ip_addr saddr;           //Source address
	ip_addr daddr;           //Destination address
} ip_header;

////////////////////////////////////////////////////////////////////

// TCPv4 header
typedef struct tcp_header
{
	u_short sport;           //source port
	u_short dport;           //destination port

	u_int seq;               //sequence number
	u_int ack;               //acknowledgement number

	u_char x2:4, off:4;      //data offset

	u_char flags;		  //flags
	u_short win;          //window
	u_short crc;          //checksum
	u_short urp;          //urgent pointer
} tcp_header;

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

#endif //_PROTOCOLS_H_

