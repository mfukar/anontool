#include <stdio.h>
#include "anonymization.h"
#define CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#define IP2_HLEN(iph)	((iph)->ip_verhl & 0x0f)

//thanks to libnet code
unsigned int in_cksum(u_int16_t * addr, int len)
{
	unsigned int    sum;

	sum = 0;

	while (len > 1) {
		sum += *addr++;
		len -= 2;
	}
	if (len == 1) {
		sum += *(u_int16_t *) addr;
	}

	return (sum);
}

#include <assert.h>

unsigned short calculate_tcp_sum(anonpacket * p)
{
	unsigned int    sum;
	unsigned char   backup = 0;
	short           padding = 0;

	int             len;

	len = ntohs(p->iph->ip_len) - sizeof(IPHdr) - p->ip_options_len;

	if (len % 2 == 1) {
		backup = ((unsigned char *)p->tcph)[len];
		((unsigned char *)p->tcph)[len] = 0;
		padding = 1;
	}

	p->tcph->th_sum = 0;
	sum = in_cksum((u_int16_t *) & p->iph->ip_src, 8);
	sum += ntohs(IPPROTO_TCP + len);
	sum += in_cksum((u_int16_t *) p->tcph, len);

	if (padding) {
		((unsigned char *)p->tcph)[len] = backup;
	}
	return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_ip_sum(anonpacket * p)
{
	unsigned int    sum;
	int             ip_hl;

	p->iph->ip_csum = 0;

	ip_hl = IP2_HLEN(p->iph) << 2;

	sum = in_cksum((u_int16_t *) p->iph, ip_hl);
	return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_icmp_sum(anonpacket * p)
{
	unsigned int    sum;
	int             icmp_hl;

	p->icmph->csum = 0;

	icmp_hl = ntohs(p->iph->ip_len) - sizeof(IPHdr) - p->ip_options_len;
	sum = in_cksum((u_int16_t *) p->icmph, icmp_hl);
	return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_udp_sum(anonpacket * p)
{
	unsigned long   sum;
	u_int16_t      *s;
	int             size;
	u_int32_t       addr;
	sum = 0;

	p->udph->uh_chk = 0;

	addr = p->iph->ip_src.s_addr;
	sum += addr >> 16;
	sum += addr & 0xffff;
	addr = p->iph->ip_dst.s_addr;
	sum += addr >> 16;
	sum += addr & 0xffff;
	sum += p->iph->ip_proto << 8;	/* endian swap */
	size = p->udph->uh_len;
	sum += size;

	size = ntohs(size);
	s = (u_int16_t *) p->udph;
	while (size > 1) {
		sum += *s;
		s++;
		size -= 2;
	}
	if (size)
		sum += *(u_int8_t *) s;

	sum = (sum & 0xffff) + (sum >> 16);	/* add overflow counts */
	sum = (sum & 0xffff) + (sum >> 16);	/* once again */

	return ~sum;
}
