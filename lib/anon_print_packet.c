#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>

#include "anonymization.h"

#define TIMEBUF_SIZE 26
#define C_OFFSET          49
#define FRAME_SIZE        66

void            PrintEthHeader(FILE * fp, anonpacket * p);
void            PrintIPPkt(FILE * fp, int type, anonpacket * p);
void            PrintTcpOptions(FILE * fp, anonpacket * p);
void            PrintIpOptions(FILE * fp, anonpacket * p);
void            PrintTCPHeader(FILE * fp, anonpacket * p);
void            PrintIPHeader(FILE * fp, anonpacket * p);
void            PrintEmbeddedTCPHeader(FILE * fp, anonpacket * p, int size);
void            CreateTCPFlagString(anonpacket * p, char *flagBuffer);
void            PrintNetData(FILE * fp, u_char * start, const int len);
void            PrintICMPHeader(FILE * fp, anonpacket * p);
void            PrintUDPHeader(FILE * fp, anonpacket * p);
void            ts_print(register const struct timeval *tvp, char *timebuf);
void            Print2ndHeader(FILE * fp, anonpacket * p, int datalink);
void            PrintPacket(FILE * fp, anonpacket * p, int datalink);

char           *protocol_names[256];
char           *data_dump_buffer;
int             dump_size;

void PrintTcpOptions(FILE * fp, anonpacket * p)
{
	int             i;
	int             j;
	union {
		u_char          tmp_char[5];
		uint16_t	tmp_short;
		uint32_t	tmp_long;
	} tmp;
	u_long          init_offset;
	u_long          print_offset;

	init_offset = ftell(fp);

	fprintf(fp, "TCP Options (%d) => ", p->tcp_option_count);

	if (p->tcp_option_count > 40 || !p->tcp_option_count)
		return;

	for (i = 0; i < (int)p->tcp_option_count; i++) {
		print_offset = ftell(fp);

		if ((print_offset - init_offset) > 60) {
			fwrite("\nTCP Options => ", 16, 1, fp);
			init_offset = ftell(fp);
		}

		switch (p->tcp_options[i].code) {
		case TCPOPT_MAXSEG:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			fwrite("MSS: ", 5, 1, fp);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 2);
			fprintf(fp, "%u ", EXTRACT_16BITS(&tmp.tmp_short));
			break;

		case TCPOPT_EOL:
			fwrite("EOL ", 4, 1, fp);
			break;

		case TCPOPT_NOP:
			fwrite("NOP ", 4, 1, fp);
			break;

		case TCPOPT_WSCALE:
			fprintf(fp, "WS: %u ", p->tcp_options[i].data[0]);
			break;

		case TCPOPT_SACK:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 2);
			fprintf(fp, "Sack: %u@", EXTRACT_16BITS(&tmp.tmp_short));
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, (p->tcp_options[i].data) + 2, 2);
			fprintf(fp, "%u ", EXTRACT_16BITS(&tmp.tmp_short));
			break;

		case TCPOPT_SACKOK:
			fwrite("SackOK ", 7, 1, fp);
			break;

		case TCPOPT_ECHO:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "Echo: %u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		case TCPOPT_ECHOREPLY:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "Echo Rep: %u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		case TCPOPT_TIMESTAMP:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "TS: %u ", EXTRACT_32BITS(&tmp.tmp_long));

			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, (p->tcp_options[i].data) + 4, 4);
			fprintf(fp, "%u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		case TCPOPT_CC:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "CC %u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		case TCPOPT_CCNEW:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "CCNEW: %u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		case TCPOPT_CCECHO:
			memset(tmp.tmp_char, 0, sizeof tmp.tmp_char);
			memcpy(tmp.tmp_char, p->tcp_options[i].data, 4);
			fprintf(fp, "CCECHO: %u ", EXTRACT_32BITS(&tmp.tmp_long));
			break;

		default:
			if (p->tcp_options[i].len) {
				fprintf(fp, "Opt %d (%d): ", p->tcp_options[i].code,
					(int)p->tcp_options[i].len);

				for (j = 0; j < p->tcp_options[i].len; j++) {
					fprintf(fp, "%02X", p->tcp_options[i].data[j]);

					if ((j % 2) == 0)
						fprintf(fp, " ");
				}
			} else {
				fprintf(fp, "Opt %d ", p->tcp_options[i].code);
			}
			break;
		}
	}

	fwrite("\n", 1, 1, fp);
}

void InitProtoNames()
{
	int             i;
	struct protoent *pt;
	unsigned char  *tmp;
	u_char          protoname[11];

	for (i = 0; i < 256; i++) {
		pt = getprotobynumber(i);

		if (pt) {
			protocol_names[i] = strdup(pt->p_name);

			tmp = (unsigned char *)protocol_names[i];

			for (tmp = (unsigned char *)protocol_names[i]; *tmp != 0; tmp++)
				*tmp = (unsigned char)toupper(*tmp);
		} else {
			snprintf((char *)protoname, 10, "PROTO%03d", i);
			protocol_names[i] = strdup((char *)protoname);
		}
	}
}

int             protosInitiated = 0;

void PrintIPPkt(FILE * fp, int type, anonpacket * p)
{
	char            timestamp[TIMEBUF_SIZE];

	if (!protosInitiated) {
		InitProtoNames();
		protosInitiated = 1;
	}

	if (!p) {
		return;
	}

	memset(timestamp, 0, sizeof(timestamp));
	ts_print((struct timeval *)&p->pkth->ts, timestamp);

	/* dump the timestamp */
	fwrite(timestamp, strlen(timestamp), 1, fp);

	/* dump the ethernet header if we're doing that sort of thing */
	PrintEthHeader(fp, p);

	/* etc */
	PrintIPHeader(fp, p);

	/* if this isn't a fragment, print the other header info */
	if (p->iph && !p->frag_flag) {
		switch (p->iph->ip_proto) {
		case IPPROTO_TCP:
			if (p->tcph != NULL) {
				PrintTCPHeader(fp, p);
			} else {
				PrintNetData(fp, (u_char *)
					     ((u_char *) p->iph + (IP_HLEN(p->iph) << 2)),
					     (ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)));
			}

			break;

		case IPPROTO_UDP:
			if (p->udph != NULL) {
				PrintUDPHeader(fp, p);
			} else {
				PrintNetData(fp, (u_char *)
					     ((u_char *) p->iph + (IP_HLEN(p->iph) << 2)),
					     (ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)));
			}

			break;

		case IPPROTO_ICMP:
			if (p->icmph != NULL) {
				PrintICMPHeader(fp, p);
			} else {
				PrintNetData(fp, (u_char *)
					     ((u_char *) p->iph + (IP_HLEN(p->iph) << 2)),
					     (ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)));
			}

			break;

		default:
			break;
		}
	}

	PrintNetData(fp, p->pkt, p->pkth->caplen);

	fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"
		"=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}

void PrintUDPHeader(FILE * fp, anonpacket * p)
{

	if (p->udph == NULL) {
		fprintf(fp, "UDP header truncated\n");
		return;
	}
	/* not much to do here... */
	fprintf(fp, "Len: %d\n", ntohs(p->udph->uh_len) - UDP_HEADER_LEN);
}

void PrintICMPHeader(FILE * fp, anonpacket * p)
{
	if (p->icmph == NULL) {
		fprintf(fp, "ICMP header truncated\n");
		return;
	}

	fprintf(fp, "Type:%d  Code:%d  ", p->icmph->type, p->icmph->code);

	switch (p->icmph->type) {
	case ICMP_ECHOREPLY:
		fprintf(fp, "ID:%d  Seq:%d  ", ntohs(p->icmph->s_icmp_id),
			ntohs(p->icmph->s_icmp_seq));
		fwrite("ECHO REPLY\n", 10, 1, fp);
		break;

	case ICMP_DEST_UNREACH:
		fwrite("DESTINATION UNREACHABLE: ", 25, 1, fp);
		switch (p->icmph->code) {
		case ICMP_NET_UNREACH:
			fwrite("NET UNREACHABLE", 15, 1, fp);
			break;

		case ICMP_HOST_UNREACH:
			fwrite("HOST UNREACHABLE", 16, 1, fp);
			break;

		case ICMP_PROT_UNREACH:
			fwrite("PROTOCOL UNREACHABLE", 20, 1, fp);
			break;

		case ICMP_PORT_UNREACH:
			fwrite("PORT UNREACHABLE", 16, 1, fp);
			break;

		case ICMP_FRAG_NEEDED:
			fprintf(fp, "FRAGMENTATION NEEDED, DF SET\n"
				"NEXT LINK MTU: %u", ntohs(p->icmph->s_icmp_nextmtu));
			break;

		case ICMP_SR_FAILED:
			fwrite("SOURCE ROUTE FAILED", 19, 1, fp);
			break;

		case ICMP_NET_UNKNOWN:
			fwrite("NET UNKNOWN", 11, 1, fp);
			break;

		case ICMP_HOST_UNKNOWN:
			fwrite("HOST UNKNOWN", 12, 1, fp);
			break;

		case ICMP_HOST_ISOLATED:
			fwrite("HOST ISOLATED", 13, 1, fp);
			break;

		case ICMP_PKT_FILTERED_NET:
			fwrite("ADMINISTRATIVELY PROHIBITED NETWORK FILTERED", 44, 1, fp);
			break;

		case ICMP_PKT_FILTERED_HOST:
			fwrite("ADMINISTRATIVELY PROHIBITED HOST FILTERED", 41, 1, fp);
			break;

		case ICMP_NET_UNR_TOS:
			fwrite("NET UNREACHABLE FOR TOS", 23, 1, fp);
			break;

		case ICMP_HOST_UNR_TOS:
			fwrite("HOST UNREACHABLE FOR TOS", 24, 1, fp);
			break;

		case ICMP_PKT_FILTERED:
			fwrite("ADMINISTRATIVELY PROHIBITED,\nPACKET FILTERED", 44, 1, fp);
			break;

		case ICMP_PREC_VIOLATION:
			fwrite("PREC VIOLATION", 14, 1, fp);
			break;

		case ICMP_PREC_CUTOFF:
			fwrite("PREC CUTOFF", 12, 1, fp);
			break;

		default:
			fwrite("UNKNOWN", 7, 1, fp);
			break;

		}
		{
			anonpacket      op;
			anonpacket     *orig_p;
			int             orig_iph_size;

			memset(&op, 0, sizeof(op));
			orig_p = &op;
			orig_p->iph = p->orig_iph;
			orig_p->tcph = p->orig_tcph;
			orig_p->udph = p->orig_udph;
			orig_p->sp = p->orig_sp;
			orig_p->dp = p->orig_dp;

			if (orig_p->iph != NULL) {
				orig_iph_size = IP_HLEN(orig_p->iph) << 2;

				fprintf(fp, "\n** ORIGINAL DATAGRAM DUMP:\n");
				PrintIPHeader(fp, orig_p);

				switch (orig_p->iph->ip_proto) {
				case IPPROTO_TCP:
					/* 
					 * we can only guarantee the first 8 bytes of the
					 * tcp header are encapsulated, so lets just print 
					 * them instead of freaking people out all the time
					 *   --MFR
					 */
					if (orig_p->tcph != NULL)
						PrintEmbeddedTCPHeader(fp, orig_p,
								       p->dsize - orig_iph_size);
					break;

				case IPPROTO_UDP:
					if (orig_p->udph != NULL)
						PrintUDPHeader(fp, orig_p);
					break;

				case IPPROTO_ICMP:
					if (orig_p->icmph != NULL)
						fprintf(fp, "orig type: %d  code: %d\n",
							orig_p->icmph->type, orig_p->icmph->code);
					break;

				default:
					fprintf(fp, "Protocol: 0x%X (unknown or "
						"header truncated)", orig_p->iph->ip_proto);
					break;
				}	/* switch */

				fprintf(fp, "** END OF DUMP");
			} else {
				fprintf(fp, "\nORIGINAL DATAGRAM TRUNCATED");
			}
		}
		break;

	case ICMP_SOURCE_QUENCH:
		fwrite("SOURCE QUENCH", 13, 1, fp);
		break;

	case ICMP_REDIRECT:
		fwrite("REDIRECT", 8, 1, fp);
		switch (p->icmph->code) {
		case ICMP_REDIR_NET:
			fwrite(" NET", 4, 1, fp);
			break;

		case ICMP_REDIR_HOST:
			fwrite(" HOST", 5, 1, fp);
			break;

		case ICMP_REDIR_TOS_NET:
			fwrite(" TOS NET", 8, 1, fp);
			break;

		case ICMP_REDIR_TOS_HOST:
			fwrite(" TOS HOST", 9, 1, fp);
			break;
		}

		fprintf(fp, " NEW GW: %s", inet_ntoa(p->icmph->s_icmp_gwaddr));

		{
			anonpacket      op;
			anonpacket     *orig_p;
			int             orig_iph_size;

			memset(&op, 0, sizeof(op));
			orig_p = &op;

			orig_p->iph = p->orig_iph;
			orig_p->tcph = p->orig_tcph;
			orig_p->udph = p->orig_udph;
			orig_p->sp = p->orig_sp;
			orig_p->dp = p->orig_dp;

			if (orig_p->iph != NULL) {
				orig_iph_size = IP_HLEN(orig_p->iph) << 2;

				fprintf(fp, "\n** ORIGINAL DATAGRAM DUMP:\n");
				PrintIPHeader(fp, orig_p);

				switch (orig_p->iph->ip_proto) {
				case IPPROTO_TCP:
					/* 
					 * we can only guarantee the first 8 bytes of the
					 * tcp header are encapsulated, so lets just print 
					 * them instead of freaking people out all the time
					 *   --MFR
					 */
					if (orig_p->tcph != NULL)
						PrintEmbeddedTCPHeader(fp, orig_p,
								       p->dsize - orig_iph_size);
					break;

				case IPPROTO_UDP:
					if (orig_p->udph != NULL)
						PrintUDPHeader(fp, orig_p);
					break;

				case IPPROTO_ICMP:
					if (orig_p->icmph != NULL)
						fprintf(fp, "orig type: %d  code: %d\n",
							orig_p->icmph->type, orig_p->icmph->code);
					break;

				default:
					fprintf(fp, "Protocol: 0x%X (unknown or "
						"header truncated)", orig_p->iph->ip_proto);
					break;
				}	/* switch */

				fprintf(fp, "** END OF DUMP");
			} else {
				fprintf(fp, "\nORIGINAL DATAGRAM TRUNCATED");
			}
		}

		break;

	case ICMP_ECHO:
		fprintf(fp, "ID:%d   Seq:%d  ", ntohs(p->icmph->s_icmp_id),
			ntohs(p->icmph->s_icmp_seq));
		fwrite("ECHO", 4, 1, fp);
		break;

	case ICMP_ROUTER_ADVERTISE:
		fprintf(fp, "ROUTER ADVERTISMENT: "
			"Num addrs: %d Addr entry size: %d Lifetime: %u",
			p->icmph->s_icmp_num_addrs, p->icmph->s_icmp_wpa,
			p->icmph->s_icmp_lifetime);
		break;

	case ICMP_ROUTER_SOLICIT:
		fwrite("ROUTER SOLICITATION", 19, 1, fp);
		break;

	case ICMP_TIME_EXCEEDED:
		fwrite("TTL EXCEEDED", 12, 1, fp);
		switch (p->icmph->code) {
		case ICMP_TIMEOUT_TRANSIT:
			fwrite(" IN TRANSIT", 11, 1, fp);
			break;

		case ICMP_TIMEOUT_REASSY:
			fwrite(" TIME EXCEEDED IN FRAG REASSEMBLY", 33, 1, fp);
			break;
		}
		break;

	case ICMP_PARAMETERPROB:
		fwrite("PARAMETER PROBLEM", 17, 1, fp);
		switch (p->icmph->code) {
		case ICMP_PARAM_BADIPHDR:
			fprintf(fp, ": BAD IP HEADER BYTE %u", p->icmph->s_icmp_pptr);
			break;

		case ICMP_PARAM_OPTMISSING:
			fwrite(": OPTION MISSING", 16, 1, fp);
			break;

		case ICMP_PARAM_BAD_LENGTH:
			fwrite(": BAD LENGTH", 12, 1, fp);
			break;
		}
		break;

	case ICMP_TIMESTAMP:
		fprintf(fp, "ID: %u  Seq: %u  TIMESTAMP REQUEST",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
		break;

	case ICMP_TIMESTAMPREPLY:
		fprintf(fp, "ID: %u  Seq: %u  TIMESTAMP REPLY:\n"
			"Orig: %u Rtime: %u  Ttime: %u",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
			p->icmph->s_icmp_otime, p->icmph->s_icmp_rtime, p->icmph->s_icmp_ttime);
		break;

	case ICMP_INFO_REQUEST:
		fprintf(fp, "ID: %u  Seq: %u  INFO REQUEST",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
		break;

	case ICMP_INFO_REPLY:
		fprintf(fp, "ID: %u  Seq: %u  INFO REPLY",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
		break;

	case ICMP_ADDRESS:
		fprintf(fp, "ID: %u  Seq: %u  ADDRESS REQUEST",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq));
		break;

	case ICMP_ADDRESSREPLY:
		fprintf(fp, "ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X",
			ntohs(p->icmph->s_icmp_id), ntohs(p->icmph->s_icmp_seq),
			(u_int) ntohl(p->icmph->s_icmp_mask));
		break;

	default:
		fwrite("UNKNOWN", 7, 1, fp);

		break;
	}

	putc('\n', fp);

}

void PrintIpOptions(FILE * fp, anonpacket * p)
{
	int             i;
	int             j;
	u_long          init_offset;
	u_long          print_offset;

	init_offset = ftell(fp);

	if (!p->ip_option_count || p->ip_option_count > 40)
		return;

	fprintf(fp, "IP Options (%d) => ", p->ip_option_count);

	for (i = 0; i < (int)p->ip_option_count; i++) {
		print_offset = ftell(fp);

		if ((print_offset - init_offset) > 60) {
			fwrite("\nIP Options => ", 15, 1, fp);
			init_offset = ftell(fp);
		}

		switch (p->ip_options[i].code) {
		case IPOPT_RR:
			fwrite("RR ", 3, 1, fp);
			break;

		case IPOPT_EOL:
			fwrite("EOL ", 4, 1, fp);
			break;

		case IPOPT_NOP:
			fwrite("NOP ", 4, 1, fp);
			break;

		case IPOPT_TS:
			fwrite("TS ", 3, 1, fp);
			break;

		case IPOPT_SECURITY:
			fwrite("SEC ", 4, 1, fp);
			break;

		case IPOPT_LSRR:
		case IPOPT_LSRR_E:
			fwrite("LSRR ", 5, 1, fp);
			break;

		case IPOPT_SATID:
			fwrite("SID ", 4, 1, fp);
			break;

		case IPOPT_SSRR:
			fwrite("SSRR ", 5, 1, fp);
			break;

		case IPOPT_RTRALT:
			fwrite("RTRALT ", 7, 1, fp);
			break;

		default:
			fprintf(fp, "Opt %d: ", p->ip_options[i].code);

			if (p->ip_options[i].len) {
				for (j = 0; j < p->ip_options[i].len; j++) {
					fprintf(fp, "%02X", p->ip_options[i].data[j]);

					if ((j % 2) == 0)
						fprintf(fp, " ");
				}
			}
			break;
		}
	}

	fwrite("\n", 1, 1, fp);
}

void PrintNetData(FILE * fp, u_char * start, const int len)
{
	char           *end;	/* ptr to buffer end */
	int             i;	/* counter */
	int             j;	/* counter */
	int             dbuf_size;	/* data buffer size */
	int             done;	/* flag */
	char           *data;	/* index pointer */
	char           *frame_ptr;	/* we use 66 byte frames for a printed line */
	char           *d_ptr;	/* data pointer into the frame */
	char           *c_ptr;	/* char pointer into the frame */
	char            conv[] = "0123456789ABCDEF";	/* xlation lookup table */

	/* initialization */
	done = 0;

	/* zero, print a <CR> and get out */
	if (!len) {
		fputc('\n', fp);
		return;
	}

	if (start == NULL) {
		printf("Got NULL ptr in PrintNetData()\n");
		return;
	}

	end = (char *)(start + (len - 1));	/* set the end of buffer ptr */

	if (len > 65535) {
		printf("Got bogus buffer length (%d) for PrintNetData, defaulting to 16 bytes!\n",
		       len);
		dbuf_size = (FRAME_SIZE + 8) + (FRAME_SIZE + 8) + 1;

		/* dbuf_size = 66 + 67; */
		end = (char *)(start + 15);
	} else {
		dbuf_size = ((len / 16) * (FRAME_SIZE + 8)) + (FRAME_SIZE + 8) + 1;

	}

	/* generate the buffer */
	data_dump_buffer = (char *)malloc(dbuf_size);

	/* make sure it got allocated properly */
	if (data_dump_buffer == NULL) {
		return;
	}
	/* clean it out */
	memset(data_dump_buffer, 0x20, dbuf_size);

	/* set the byte buffer pointer to step thru the data buffer */
	data = (char *)start;

	/* set the frame pointer to the start of the printout buffer */
	frame_ptr = data_dump_buffer;

	/* initialize counters and frame index pointers */
	i = 0;
	j = 0;

	/* loop thru the whole buffer */
	while (!done) {
		d_ptr = frame_ptr + 8;
		c_ptr = (frame_ptr + 8 + C_OFFSET);
		sprintf(frame_ptr, "0x%04X: ", j);
		j += 16;

		/* process 16 bytes per frame */
		for (i = 0; i < 16; i++) {
			/*
			 * look up the ASCII value of the first nybble of the current
			 * data buffer
			 */
			*d_ptr = conv[((*data & 0xFF) >> 4)];
			d_ptr++;

			/* look up the second nybble */
			*d_ptr = conv[((*data & 0xFF) & 0x0F)];
			d_ptr++;

			/* put a space in between */
			*d_ptr = 0x20;
			d_ptr++;

			/* print out the char equivalent */
			if (*data > 0x1F && *data < 0x7F)
				*c_ptr = (char)(*data & 0xFF);
			else
				*c_ptr = 0x2E;

			c_ptr++;

			/* increment the pointer or finish up */
			if (data < end)
				data++;
			else {
				*c_ptr = '\n';
				c_ptr++;
				*c_ptr = '\n';
				c_ptr++;
				*c_ptr = 0;

				dump_size = (int)(c_ptr - data_dump_buffer);
				fwrite(data_dump_buffer, dump_size, 1, fp);

				return;
			}
		}

		*c_ptr = '\n';
		frame_ptr += (FRAME_SIZE + 8);
	}
}

void PrintIPHeader(FILE * fp, anonpacket * p)
{
	if (p->iph == NULL) {
		fprintf(fp, "IP header truncated\n");
		return;
	}
	if (p->frag_flag) {
		/* just print the straight IP header */
		fputs(inet_ntoa(p->iph->ip_src), fp);
		fwrite(" -> ", 4, 1, fp);
		fputs(inet_ntoa(p->iph->ip_dst), fp);
	} else {
		if (p->iph->ip_proto != IPPROTO_TCP && p->iph->ip_proto != IPPROTO_UDP) {
			/* just print the straight IP header */
			fputs(inet_ntoa(p->iph->ip_src), fp);
			fwrite(" -> ", 4, 1, fp);
			fputs(inet_ntoa(p->iph->ip_dst), fp);
		} else {
			/* print the header complete with port information */
			fputs(inet_ntoa(p->iph->ip_src), fp);
			fprintf(fp, ":%d -> ", p->sp);
			fputs(inet_ntoa(p->iph->ip_dst), fp);
			fprintf(fp, ":%d", p->dp);
		}
	}

	fputc(' ', fp);

	fprintf(fp, "%s TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d",
		protocol_names[p->iph->ip_proto],
		p->iph->ip_ttl,
		p->iph->ip_tos, ntohs(p->iph->ip_id), IP_HLEN(p->iph) << 2, ntohs(p->iph->ip_len));

	/* print the reserved bit if it's set */
	if ((u_int8_t) ((ntohs(p->iph->ip_off) & 0x8000) >> 15) == 1)
		fprintf(fp, " RB");

	/* printf more frags/don't frag bits */
	if ((u_int8_t) ((ntohs(p->iph->ip_off) & 0x4000) >> 14) == 1)
		fprintf(fp, " DF");

	if ((u_int8_t) ((ntohs(p->iph->ip_off) & 0x2000) >> 13) == 1)
		fprintf(fp, " MF");

	fputc('\n', fp);

	/* print IP options */
	if (p->ip_option_count != 0) {
		PrintIpOptions(fp, p);
	}

	/* print fragment info if necessary */
	if (p->frag_flag) {
		fprintf(fp, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
			(p->frag_offset & 0x1FFF),
			(ntohs(p->iph->ip_len) - (ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2))));
	}
}

void PrintTCPHeader(FILE * fp, anonpacket * p)
{
	char            tcpFlags[9];

	if (p->tcph == NULL) {
		fprintf(fp, "TCP header truncated\n");
		return;
	}
	/* print TCP flags */
	CreateTCPFlagString(p, tcpFlags);
	fwrite(tcpFlags, 8, 1, fp);	/* We don't care about the NULL */

	/* print other TCP info */
	fprintf(fp, " Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d",
		(u_long) ntohl(p->tcph->th_seq),
		(u_long) ntohl(p->tcph->th_ack), ntohs(p->tcph->th_win), TCP_OFFSET(p->tcph) << 2);

	if ((p->tcph->th_flags & TH_URG) != 0) {
		fprintf(fp, "  UrgPtr: 0x%X\n", (u_int16_t) ntohs(p->tcph->th_urp));
	} else {
		fputc((int)'\n', fp);
	}

	/* dump the TCP options */
	if (p->tcp_option_count != 0) {
		PrintTcpOptions(fp, p);
	}
}

void PrintEmbeddedTCPHeader(FILE * fp, anonpacket * p, int size)
{
	char            tcpFlags[9];

	if (size >= 16) {
		CreateTCPFlagString(p, tcpFlags);
		fwrite(tcpFlags, 8, 1, fp);
		fprintf(fp, " Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d\n",
			(u_long) ntohl(p->tcph->th_seq),
			(u_long) ntohl(p->tcph->th_ack),
			ntohs(p->tcph->th_win), TCP_OFFSET(p->tcph) << 2);
	} else if (size >= 14) {
		CreateTCPFlagString(p, tcpFlags);
		fwrite(tcpFlags, 8, 1, fp);
		fprintf(fp, " Seq: 0x%lX  Ack: 0x%lX  TcpLen: %d\n",
			(u_long) ntohl(p->tcph->th_seq),
			(u_long) ntohl(p->tcph->th_ack), TCP_OFFSET(p->tcph) << 2);
	} else if (size >= 13) {
		fprintf(fp, "Seq: 0x%lX  Ack: 0x%lX  TcpLen: %d\n",
			(u_long) ntohl(p->tcph->th_seq),
			(u_long) ntohl(p->tcph->th_ack), TCP_OFFSET(p->tcph) << 2);
	} else if (size >= 12) {
		fprintf(fp, "Seq: 0x%lX  Ack: 0x%lX\n",
			(u_long) ntohl(p->tcph->th_seq), (u_long) ntohl(p->tcph->th_ack));
	} else if (size >= 8) {

		fprintf(fp, "Seq: 0x%lX\n", (u_long) ntohl(p->tcph->th_seq));
	}
}

int gmt2local(time_t t)
{
	register int    dt, dir;
	register struct tm *gmt, *loc;
	struct tm       sgmt;

	if (t == 0)
		t = time(NULL);

	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);

	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + (loc->tm_min - gmt->tm_min) * 60;

	dir = loc->tm_year - gmt->tm_year;

	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;

	dt += dir * 24 * 60 * 60;

	return (dt);
}

void PrintEthHeader(FILE * fp, anonpacket * p)
{
	/* src addr */
	fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", p->eh->ether_src[0],
		p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
		p->eh->ether_src[4], p->eh->ether_src[5]);

	/* dest addr */
	fprintf(fp, "%X:%X:%X:%X:%X:%X ", p->eh->ether_dst[0],
		p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
		p->eh->ether_dst[4], p->eh->ether_dst[5]);

	/* protocol and pkt size */
	fprintf(fp, "type:0x%X len:0x%X\n", ntohs(p->eh->ether_type), p->pkth->len);
}

void CreateTCPFlagString(anonpacket * p, char *flagBuffer)
{
	/* parse TCP flags */
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_RES1) ? '1' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_RES2) ? '2' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_URG) ? 'U' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_ACK) ? 'A' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_PUSH) ? 'P' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_RST) ? 'R' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_SYN) ? 'S' : '*');
	*flagBuffer++ = (char)((p->tcph->th_flags & TH_FIN) ? 'F' : '*');
	*flagBuffer = '\0';

}

void ts_print(register const struct timeval *tvp, char *timebuf)
{
	register int    s;
	struct timeval  tv;
	struct tm      *lt;	/* place to stick the adjusted clock data */
	int             thiszone;

	thiszone = gmt2local(0);

	/* if null was passed, we use current time */
	if (!tvp) {
		gettimeofday(&tv, NULL);
		tvp = &tv;
	}
	lt = gmtime((time_t *) & tvp->tv_sec);

	s = (tvp->tv_sec + thiszone) % 86400;

	(void)snprintf(timebuf, TIMEBUF_SIZE,
		       "%02d/%02d/%02d-%02d:%02d:%02d.%06u ",
		       lt->tm_mon + 1, lt->tm_mday, lt->tm_year - 100,
		       s / 3600, (s % 3600) / 60, s % 60, (u_int) tvp->tv_usec);
}

static unsigned char ezero[6];
void PrintArpHeader(FILE * fp, anonpacket * p)
{
	struct in_addr  ip_addr;
	char            timestamp[TIMEBUF_SIZE];
	u_int8_t       *mac_src = NULL;
	u_int8_t       *mac_dst = NULL;

	memset(&ip_addr, 0, sizeof(ip_addr));
	memset(timestamp, 0, sizeof(timestamp));
	ts_print((struct timeval *)&p->pkth->ts, timestamp);

	/* determine what to use as MAC src and dst */
	if (p->eh != NULL) {
		mac_src = p->eh->ether_src;
		mac_dst = p->eh->ether_dst;
	} /* per table 4, 802.11 section 7.2.2 */
	else if (p->wifih != NULL && (p->wifih->frame_control & WLAN_FLAG_FROMDS)) {
		mac_src = p->wifih->addr3;
		mac_dst = p->wifih->addr2;
	} else if (p->wifih != NULL && (p->wifih->frame_control & WLAN_FLAG_TODS)) {
		mac_src = p->wifih->addr2;
		mac_dst = p->wifih->addr3;
	} else if (p->wifih != NULL) {
		mac_src = p->wifih->addr2;
		mac_dst = p->wifih->addr1;
	}

	/* 
	 * if these are null this function will break, exit until 
	 * someone writes a function for it...
	 */
	if (mac_src == NULL || mac_dst == NULL) {
		return;
	}

	/* dump the timestamp */
	fwrite(timestamp, strlen(timestamp), 1, fp);

	if (ntohs(p->ah->ea_hdr.ar_pro) != ETHERNET_TYPE_IP) {
		fprintf(fp, "ARP #%d for protocol #%.4X (%d) hardware #%d (%d)\n",
			ntohs(p->ah->ea_hdr.ar_op), ntohs(p->ah->ea_hdr.ar_pro),
			p->ah->ea_hdr.ar_pln, ntohs(p->ah->ea_hdr.ar_hrd), p->ah->ea_hdr.ar_hln);

		return;
	}

	switch (ntohs(p->ah->ea_hdr.ar_op)) {
	case ARPOP_REQUEST:
		bcopy((void *)p->ah->arp_tpa, (void *)&ip_addr, sizeof(ip_addr));
		fprintf(fp, "ARP who-has %s", inet_ntoa(ip_addr));

		if (memcmp((char *)ezero, (char *)p->ah->arp_tha, 6) != 0) {
			fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_tha[0],
				p->ah->arp_tha[1], p->ah->arp_tha[2], p->ah->arp_tha[3],
				p->ah->arp_tha[4], p->ah->arp_tha[5]);
		}
		bcopy((void *)p->ah->arp_spa, (void *)&ip_addr, sizeof(ip_addr));

		fprintf(fp, " tell %s", inet_ntoa(ip_addr));

		if (memcmp((char *)mac_src, (char *)p->ah->arp_sha, 6) != 0) {
			fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_sha[0],
				p->ah->arp_sha[1], p->ah->arp_sha[2], p->ah->arp_sha[3],
				p->ah->arp_sha[4], p->ah->arp_sha[5]);
		}
		break;

	case ARPOP_REPLY:
		bcopy((void *)p->ah->arp_spa, (void *)&ip_addr, sizeof(ip_addr));
		fprintf(fp, "ARP reply %s", inet_ntoa(ip_addr));

		/* print out the originating request if we're on a weirder
		 * wireless protocol */
		if (memcmp((char *)mac_src, (char *)p->ah->arp_sha, 6) != 0) {
			fprintf(fp, " (%X:%X:%X:%X:%X:%X)", mac_src[0],
				mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
		}
		fprintf(fp, " is-at %X:%X:%X:%X:%X:%X", p->ah->arp_sha[0],
			p->ah->arp_sha[1], p->ah->arp_sha[2], p->ah->arp_sha[3],
			p->ah->arp_sha[4], p->ah->arp_sha[5]);

		if (memcmp((char *)mac_dst, (char *)p->ah->arp_tha, 6) != 0) {
			fprintf(fp, " (%X:%X:%X:%X:%X:%X)", p->ah->arp_tha[0],
				p->ah->arp_tha[1], p->ah->arp_tha[2], p->ah->arp_tha[3],
				p->ah->arp_tha[4], p->ah->arp_tha[5]);
		}
		break;

	case ARPOP_RREQUEST:
		fprintf(fp, "RARP who-is %X:%X:%X:%X:%X:%X tell %X:%X:%X:%X:%X:%X",
			p->ah->arp_tha[0], p->ah->arp_tha[1], p->ah->arp_tha[2],
			p->ah->arp_tha[3], p->ah->arp_tha[4], p->ah->arp_tha[5],
			p->ah->arp_sha[0], p->ah->arp_sha[1], p->ah->arp_sha[2],
			p->ah->arp_sha[3], p->ah->arp_sha[4], p->ah->arp_sha[5]);

		break;

	case ARPOP_RREPLY:
		bcopy((void *)p->ah->arp_tpa, (void *)&ip_addr, sizeof(ip_addr));
		fprintf(fp, "RARP reply %X:%X:%X:%X:%X:%X at %s",
			p->ah->arp_tha[0], p->ah->arp_tha[1], p->ah->arp_tha[2],
			p->ah->arp_tha[3], p->ah->arp_tha[4], p->ah->arp_tha[5],
			inet_ntoa(ip_addr));

		break;

	default:
		fprintf(fp, "Unknown operation: %d", ntohs(p->ah->ea_hdr.ar_op));
		break;
	}

	fprintf(fp, "\n\n");

}

void PrintTrHeader(FILE * fp, anonpacket * p)
{

	fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", p->trh->saddr[0],
		p->trh->saddr[1], p->trh->saddr[2], p->trh->saddr[3],
		p->trh->saddr[4], p->trh->saddr[5]);
	fprintf(fp, "%X:%X:%X:%X:%X:%X\n", p->trh->daddr[0],
		p->trh->daddr[1], p->trh->daddr[2], p->trh->daddr[3],
		p->trh->daddr[4], p->trh->daddr[5]);

	fprintf(fp, "access control:0x%X frame control:0x%X\n", p->trh->ac, p->trh->fc);
	if (!p->trhllc)
		return;
	fprintf(fp, "DSAP: 0x%X SSAP 0x%X protoID: %X%X%X Ethertype: %X\n",
		p->trhllc->dsap, p->trhllc->ssap, p->trhllc->protid[0],
		p->trhllc->protid[1], p->trhllc->protid[2], p->trhllc->ethertype);
	if (p->trhmr) {
		fprintf(fp, "RIF structure is present:\n");
		fprintf(fp, "bcast: 0x%X length: 0x%X direction: 0x%X largest"
			"fr. size: 0x%X res: 0x%X\n",
			TRH_MR_BCAST(p->trhmr), TRH_MR_LEN(p->trhmr),
			TRH_MR_DIR(p->trhmr), TRH_MR_LF(p->trhmr), TRH_MR_RES(p->trhmr));
		fprintf(fp, "rseg -> %X:%X:%X:%X:%X:%X:%X:%X\n",
			p->trhmr->rseg[0], p->trhmr->rseg[1], p->trhmr->rseg[2],
			p->trhmr->rseg[3], p->trhmr->rseg[4], p->trhmr->rseg[5],
			p->trhmr->rseg[6], p->trhmr->rseg[7]);
	}
}

void PrintWifiPkt(FILE * fp, anonpacket * p, int datalink)
{
	char            timestamp[TIMEBUF_SIZE];

	memset(timestamp, 0, sizeof(timestamp));
	ts_print((struct timeval *)&p->pkth->ts, timestamp);

	/* dump the timestamp */
	fwrite(timestamp, strlen(timestamp), 1, fp);

	/* dump the ethernet header if we're doing that sort of thing */
	Print2ndHeader(fp, p, datalink);

	/* dump the application layer data */
	PrintNetData(fp, p->data, p->dsize);

	fprintf(fp, "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+"
		"=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}

void PrintWifiHeader(FILE * fp, anonpacket * p)
{
	/* This assumes we are printing a data packet, could be changed
	   to print other types as well */
	u_char         *da = NULL, *sa = NULL, *bssid = NULL, *ra = NULL, *ta = NULL;
	/* per table 4, IEEE802.11 section 7.2.2 */
	if ((p->wifih->frame_control & WLAN_FLAG_TODS) &&
	    (p->wifih->frame_control & WLAN_FLAG_FROMDS)) {
		ra = p->wifih->addr1;
		ta = p->wifih->addr2;
		da = p->wifih->addr3;
		sa = p->wifih->addr4;
	} else if (p->wifih->frame_control & WLAN_FLAG_TODS) {
		bssid = p->wifih->addr1;
		sa = p->wifih->addr2;
		da = p->wifih->addr3;
	} else if (p->wifih->frame_control & WLAN_FLAG_FROMDS) {
		da = p->wifih->addr1;
		bssid = p->wifih->addr2;
		sa = p->wifih->addr3;
	} else {
		da = p->wifih->addr1;
		sa = p->wifih->addr2;
		bssid = p->wifih->addr3;
	}

	/* DO this switch to provide additional info on the type */
	switch (p->wifih->frame_control & 0x00ff) {
	case WLAN_TYPE_MGMT_BEACON:
		fprintf(fp, "Beacon ");
		break;
		/* management frames */
	case WLAN_TYPE_MGMT_ASREQ:
		fprintf(fp, "Assoc. Req. ");
		break;
	case WLAN_TYPE_MGMT_ASRES:
		fprintf(fp, "Assoc. Resp. ");
		break;
	case WLAN_TYPE_MGMT_REREQ:
		fprintf(fp, "Reassoc. Req. ");
		break;
	case WLAN_TYPE_MGMT_RERES:
		fprintf(fp, "Reassoc. Resp. ");
		break;
	case WLAN_TYPE_MGMT_PRREQ:
		fprintf(fp, "Probe Req. ");
		break;
	case WLAN_TYPE_MGMT_PRRES:
		fprintf(fp, "Probe Resp. ");
		break;
	case WLAN_TYPE_MGMT_ATIM:
		fprintf(fp, "ATIM ");
		break;
	case WLAN_TYPE_MGMT_DIS:
		fprintf(fp, "Dissassoc. ");
		break;
	case WLAN_TYPE_MGMT_AUTH:
		fprintf(fp, "Authent. ");
		break;
	case WLAN_TYPE_MGMT_DEAUTH:
		fprintf(fp, "Deauthent. ");
		break;

		/* Control frames */
	case WLAN_TYPE_CONT_PS:
	case WLAN_TYPE_CONT_RTS:
	case WLAN_TYPE_CONT_CTS:
	case WLAN_TYPE_CONT_ACK:
	case WLAN_TYPE_CONT_CFE:
	case WLAN_TYPE_CONT_CFACK:
		fprintf(fp, "Control ");
		break;
	}

	if (sa != NULL) {
		fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
	} else {
		fprintf(fp, "ta: %X:%X:%X:%X:%X:%X da: ", ta[0], ta[1], ta[2], ta[3], ta[4], ta[5]);
	}

	fprintf(fp, "%X:%X:%X:%X:%X:%X\n", da[0], da[1], da[2], da[3], da[4], da[5]);

	if (bssid) {
		fprintf(fp, "bssid: %X:%X:%X:%X:%X:%X", bssid[0],
			bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	}

	if (ra != NULL) {
		fprintf(fp, " ra: %X:%X:%X:%X:%X:%X", ra[0], ra[1], ra[2], ra[3], ra[4], ra[5]);
	}
	fprintf(fp, " Flags:");
	if (p->wifih->frame_control & WLAN_FLAG_TODS)
		fprintf(fp, " ToDs");
	if (p->wifih->frame_control & WLAN_FLAG_TODS)
		fprintf(fp, " FrDs");
	if (p->wifih->frame_control & WLAN_FLAG_FRAG)
		fprintf(fp, " Frag");
	if (p->wifih->frame_control & WLAN_FLAG_RETRY)
		fprintf(fp, " Re");
	if (p->wifih->frame_control & WLAN_FLAG_PWRMGMT)
		fprintf(fp, " Pwr");
	if (p->wifih->frame_control & WLAN_FLAG_MOREDAT)
		fprintf(fp, " MD");
	if (p->wifih->frame_control & WLAN_FLAG_WEP)
		fprintf(fp, " Wep");
	if (p->wifih->frame_control & WLAN_FLAG_ORDER)
		fprintf(fp, " Ord");
	fprintf(fp, "\n");
}

void PrintSLLHeader(FILE * fp, anonpacket * p)
{

	switch (ntohs(p->sllh->sll_pkttype)) {
	case LINUX_SLL_HOST:
		(void)fprintf(fp, "< ");
		break;
	case LINUX_SLL_BROADCAST:
		(void)fprintf(fp, "B ");
		break;
	case LINUX_SLL_MULTICAST:
		(void)fprintf(fp, "M ");
		break;
	case LINUX_SLL_OTHERHOST:
		(void)fprintf(fp, "P ");
		break;
	case LINUX_SLL_OUTGOING:
		(void)fprintf(fp, "> ");
		break;
	default:
		(void)fprintf(fp, "? ");
		break;
	}

	/* mac addr */
	fprintf(fp, "l/l len: %i l/l type: 0x%X %X:%X:%X:%X:%X:%X\n",
		htons(p->sllh->sll_halen), ntohs(p->sllh->sll_hatype),
		p->sllh->sll_addr[0], p->sllh->sll_addr[1], p->sllh->sll_addr[2],
		p->sllh->sll_addr[3], p->sllh->sll_addr[4], p->sllh->sll_addr[5]);

	/* protocol and pkt size */
	fprintf(fp, "pkt type:0x%X proto: 0x%X len:0x%X\n",
		ntohs(p->sllh->sll_pkttype), ntohs(p->sllh->sll_protocol), p->pkth->len);
}

void Print2ndHeader(FILE * fp, anonpacket * p, int datalink)
{

	switch (datalink) {
	case DLT_EN10MB:	/* Ethernet */
		if (p && p->eh)
			PrintEthHeader(fp, p);
		break;
#ifdef DLT_IEEE802_11
	case DLT_IEEE802_11:
		if (p && p->wifih)
			PrintWifiHeader(fp, p);
		break;
#endif
	case DLT_IEEE802:	/* Token Ring */
		if (p && p->trh)
			PrintTrHeader(fp, p);
		break;
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		if (p && p->sllh)
			PrintSLLHeader(fp, p);	/* Linux cooked sockets */
		break;
#endif
	default:
		break;
	}
}

void PrintEapolHeader(FILE * fp, anonpacket * p)
{
	fprintf(fp, "EAPOL type: ");
	switch (p->eplh->eaptype) {
	case EAPOL_TYPE_EAP:
		fprintf(fp, "EAP");
		break;
	case EAPOL_TYPE_START:
		fprintf(fp, "Start");
		break;
	case EAPOL_TYPE_LOGOFF:
		fprintf(fp, "Logoff");
		break;
	case EAPOL_TYPE_KEY:
		fprintf(fp, "Key");
		break;
	case EAPOL_TYPE_ASF:
		fprintf(fp, "ASF Alert");
		break;
	default:
		fprintf(fp, "Unknown");
	}
	fprintf(fp, " Len: %d\n", ntohs(p->eplh->len));
}

void PrintEAPHeader(FILE * fp, anonpacket * p)
{

	if (p->eaph == NULL) {
		fprintf(fp, "EAP header truncated\n");
		return;
	}
	fprintf(fp, "code: ");
	switch (p->eaph->code) {
	case EAP_CODE_REQUEST:
		fprintf(fp, "Req ");
		break;
	case EAP_CODE_RESPONSE:
		fprintf(fp, "Resp");
		break;
	case EAP_CODE_SUCCESS:
		fprintf(fp, "Succ");
		break;
	case EAP_CODE_FAILURE:
		fprintf(fp, "Fail");
		break;
	}
	fprintf(fp, " id: 0x%x len: %d", p->eaph->id, ntohs(p->eaph->len));
	if (p->eaptype != NULL) {
		fprintf(fp, " type: ");
		switch (*(p->eaptype)) {
		case EAP_TYPE_IDENTITY:
			fprintf(fp, "id");
			break;
		case EAP_TYPE_NOTIFY:
			fprintf(fp, "notify");
			break;
		case EAP_TYPE_NAK:
			fprintf(fp, "nak");
			break;
		case EAP_TYPE_MD5:
			fprintf(fp, "md5");
			break;
		case EAP_TYPE_OTP:
			fprintf(fp, "otp");
			break;
		case EAP_TYPE_GTC:
			fprintf(fp, "token");
			break;
		case EAP_TYPE_TLS:
			fprintf(fp, "tls");
			break;
		default:
			fprintf(fp, "undef");
			break;
		}
	}
	fprintf(fp, "\n");
}

void PrintEapolKey(FILE * fp, anonpacket * p)
{
	u_int16_t       length;

	if (p->eapolk == NULL) {
		fprintf(fp, "Eapol Key truncated\n");
		return;
	}
	fprintf(fp, "KEY type: ");
	if (p->eapolk->type == 1) {
		fprintf(fp, "RC4");
	}

	memcpy(&length, &p->eapolk->length, 2);
	length = ntohs(length);
	fprintf(fp, " len: %d", length);
	fprintf(fp, " index: %d ", p->eapolk->index & 0x7F);
	fprintf(fp, p->eapolk->index & 0x80 ? " unicast\n" : " broadcast\n");

}

void PrintEapolPkt(FILE * fp, anonpacket * p, int datalink)
{
	char            timestamp[TIMEBUF_SIZE];

	memset(timestamp, 0, sizeof(timestamp));
	ts_print((struct timeval *)&p->pkth->ts, timestamp);

	/* dump the timestamp */
	fwrite(timestamp, strlen(timestamp), 1, fp);

	/* dump the ethernet header if we're doing that sort of thing */
	Print2ndHeader(fp, p, datalink);
	PrintEapolHeader(fp, p);

	if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
		PrintEAPHeader(fp, p);
	} else if (p->eplh->eaptype == EAPOL_TYPE_KEY) {
		PrintEapolKey(fp, p);
	}

	/* dump the application layer data */
	PrintNetData(fp, p->data, p->dsize);

	fprintf(fp,
		"=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}

void PrintPacket(FILE * fp, anonpacket * p, int datalink)
{
	if (p->iph != NULL)
		PrintIPPkt(stdout, p->iph->ip_proto, p);
	else if (p->ah != NULL)
		PrintArpHeader(stdout, p);
	else if (p->eplh != NULL) {
		PrintEapolPkt(stdout, p, datalink);
	} else if (p->wifih) {
		PrintWifiPkt(stdout, p, datalink);
	}
}
