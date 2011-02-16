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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include <assert.h>
#include "anonymization.h"
#include "internal.h"
#include "prefix_preserving_map.h"

/* Prefix-preserving map table initialization */
extern nodehdr_t                addr_propagate;

int             can_field_be_applied_to_protocol(int protocol, int field);
int             can_field_be_applied_to_function(int anonymization_function, int field);
void            anonymize_field(int protocol, int field, int function,
                                anonpacket * packet, struct anonymize_data *params,
                                struct anonflow *flow);
void            init_mapping_tables();
void            swap(unsigned char *a, unsigned char *b);
void            checkSwap(unsigned char *field_pointer, int field);

/* mapping table for fields */

mapNode        *srcIpMappingTable[MAPPING_ENTRIES];
unsigned int    src_ip_count = 16777217;
mapNode        *dstIpMappingTable[MAPPING_ENTRIES];
unsigned int    dst_ip_count = 1107296257;

mapNode        *ipMappingTable[MAPPING_ENTRIES];
unsigned int    ip_count = 16777217;
mapNode        *portsMappingTable[MAPPING_ENTRIES];
int             ports_count = 1;
mapNode        *generalMapping32Table[MAPPING_ENTRIES];
int             general32_count = 1;
mapNode        *generalMapping16Table[MAPPING_ENTRIES];
int             general16_count = 1;
mapNode        *generalMapping8Table[MAPPING_ENTRIES];
int             general8_count = 1;

/* delta value for value shifting */
uint32_t        delta = 0;

/******FUNCTION STUFF*******/

struct httpheader default_http_header;
struct ftpheader default_ftp_header;

int anonymize_unmarshal(va_list vl, struct anonymize_data *data)
{
        int             pattern_type, i, tmp;
        char           *tmps;
        char          **repvec;

        tmp = va_arg(vl, int);  //protocol
        data->protocol = tmp;

        tmp = va_arg(vl, int);  //field
        data->field = tmp;

        tmp = va_arg(vl, int);  //function
        data->function = tmp;

        switch (data->function) {
        case UNCHANGED:
        case MAP:
        case ZERO:
        case PREFIX_PRESERVING:
        case PREFIX_PRESERVING_MAP:
        case FILENAME_RANDOM:
        case RANDOM:
        case CHECKSUM_ADJUST:
                break;
        case STRIP:
                tmp = va_arg(vl, int);  //seed
                data->seed = tmp;
                break;
        case REPLACE:
                tmps = va_arg(vl, char *);
                data->pattern = strdup(tmps);
                break;
        case HASHED:
                tmp = va_arg(vl, int);  //hashing algorithm
                data->hash_algorithm = tmp;

                tmp = va_arg(vl, int);  //padding behavior
                data->padding_behavior = tmp;

                break;
        case MAP_DISTRIBUTION:
                tmp = va_arg(vl, int);  //distribution type
                data->distribution_type = tmp;

                tmp = va_arg(vl, int);  //median
                data->median = tmp;

                tmp = va_arg(vl, int);  //standard deviation
                data->standard_deviation = tmp;

                break;
        case PATTERN_FILL:
                pattern_type = va_arg(vl, int); //pattern type
                data->pattern_type = pattern_type;

                switch (pattern_type) {
                case INTEGER:
                        tmp = va_arg(vl, int);  //integer to fill in
                        data->seed = tmp;

                        break;
                case STR:
                        tmps = va_arg(vl, char *);
                        data->pattern = (char *)strdup(tmps);
                        break;
                default:
                        fprintf(stderr, "UNKNOWN PATTERN TYPE\n");
                        return -1;
                }
                break;
        case REGEXP:
                tmps = va_arg(vl, char *);
                data->regexp = (char *)strdup(tmps);

                repvec = va_arg(vl, char **);

                tmp = va_arg(vl, int);
                data->num_of_matches = tmp;

                if (tmp == 0) {
                        return -1;
                }

                data->replaceVector = (char **)malloc(data->num_of_matches * sizeof(char *));

                for (i = 0; i < tmp; i++) {
                        if (repvec[i] != NULL) {
                                data->replaceVector[i] = (char *)strdup(repvec[i]);
                        } else {
                                data->replaceVector[i] = NULL;
                        }
                }
                break;
        case VALUE_SHIFT:
                tmp = va_arg(vl, int);
                delta = tmp;
                break;
        }

        return 0;
}

int can_field_be_applied_to_protocol(int protocol, int field)
{
        if (field == PAYLOAD && protocol != NETFLOW_V9 && protocol != NETFLOW_V5 && protocol != IPFIX)  //common to all protocols..except NETFLOW & IPFIX
                return 1;

        switch (protocol) {
        case ETHERNET:
                if (field != SRC_IP && field != DST_IP && field != ETHER_TYPE)
                        return 0;
                break;
        case IP:
                if (field < PAYLOAD || field > FRAGMENT_OFFSET)
                        return 0;
                break;
        case TCP:
                if (field < PAYLOAD || field > TCP_OPTIONS)
                        return 0;
                break;
        case UDP:
                if ((field < PAYLOAD || field > DST_PORT)
                    && field != UDP_DATAGRAM_LENGTH)
                        return 0;
                break;
        case ICMP:
                if (field < PAYLOAD || (field > FRAGMENT_OFFSET && field != TYPE && field != CODE))
                        return 0;
                break;
        case HTTP:
                if (field < PAYLOAD
                    || (field > TCP_OPTIONS && (field <= BASE_HTTP_DEFS || field >= END_HTTP_DEFS)))
                        return 0;
                break;
        case FTP:
                if (field < PAYLOAD
                    || (field > TCP_OPTIONS && (field <= BASE_FTP_DEFS || field >= END_FTP_DEFS)))
                        return 0;
                break;
        case NETFLOW_V9:
                if (((field < PAYLOAD || (field > DST_PORT && field <= BASE_NETFLOW_V9_DEFS))
                     || field >= END_NETFLOW_V9_SCOPES) && field != UDP_DATAGRAM_LENGTH)
                        return 0;
                break;
        case NETFLOW_V5:
                if (((field < PAYLOAD || (field > DST_PORT && field < NF5_VERSION))
                     || field > NF5_DST_MASK) && field != UDP_DATAGRAM_LENGTH)
                        return 0;
                break;
        case IPFIX:
                if (field < PAYLOAD || (field > DST_PORT && field < IPFIX_VERSION)
                    || field > IPFIX_mplsVpnRouteDistinguisher)
                        return 0;
                break;
        default:
                return 0;
        }

        return 1;
}

int can_field_be_applied_to_function(int anonymization_function, int field)
{
        if (anonymization_function == PREFIX_PRESERVING
        && field != SRC_IP && field != DST_IP
        && field != NF9_IPV4_SRC_ADDR && field != NF9_IPV4_DST_ADDR
        && field != NF5_SRCADDR && field != NF5_DSTADDR
        && field != NF5_NEXTHOP
        && field != NF9_IPV4_NEXT_HOP && field != NF9_IPV6_NEXT_HOP
        && field != NF9_BGP_IPV4_NEXT_HOP && field != NF9_BGP_IPV6_NEXT_HOP) {
                fprintf(stderr, "PREFIX_PRESERVING can only be applied to IP addresses\n");
                return 0;
        }

        if (anonymization_function == PREFIX_PRESERVING_MAP
        && field != SRC_IP && field != DST_IP
        && field != NF9_IPV4_SRC_ADDR && field != NF9_IPV4_DST_ADDR
        && field != NF5_SRCADDR && field != NF5_DSTADDR
        && field != NF5_NEXTHOP && field != NF9_IPV4_NEXT_HOP && field != NF9_IPV6_NEXT_HOP
        && field != NF9_BGP_IPV4_NEXT_HOP && field != NF9_BGP_IPV6_NEXT_HOP) {
                fprintf(stderr, "PREFIX_PRESERVING_MAP can only be applied to IP addresses\n");
                return 0;
        }

        if ((anonymization_function == MAP || anonymization_function == MAP_DISTRIBUTION)
            && (field < CHECKSUM || field > CODE || field == OPTIONS || field == TCP_OPTIONS)
            && field != NF9_IPV4_SRC_ADDR && field != NF9_IPV4_DST_ADDR
            && field != NF9_L4_SRC_PORT && field != NF9_L4_DST_PORT
            && field != NF5_SRCADDR && field != NF5_DSTADDR
            && field != NF5_NEXTHOP && field != NF9_IPV4_NEXT_HOP && field != NF9_IPV6_NEXT_HOP
            && field != NF9_BGP_IPV4_NEXT_HOP && field != NF9_BGP_IPV6_NEXT_HOP) {
                fprintf(stderr, "MAP/MAP_DISTRIBUTION can only be applied to IP,TCP,UDP and ICMP headers (except IP and TCP options) & Netflows\n");
                return 0;
        }

        if (anonymization_function == STRIP && (field != PAYLOAD)
            && (field != OPTIONS) && (field != TCP_OPTIONS)
            && (field <= BASE_HTTP_DEFS) && (field >= END_HTTP_DEFS)
            && (field <= BASE_FTP_DEFS) && (field <= END_FTP_DEFS)) {
                fprintf(stderr, "STRIP can only be applied to IP and TCP options, PAYLOAD and all HTTP, FTP headers\n");
                return 0;
        }

        /*if(anonymization_function==HASHED && (field>=CHECKSUM &&  field<=CODE)) {
           printf("HASHING cannot be performed on headers\n");
           return 0;
           } */

        if (anonymization_function == REPLACE && (field >= CHECKSUM && field <= CODE)) {
                fprintf(stderr, "REPLACE cannot be performed on headers\n");
                return 0;
        }

        if (anonymization_function == CHECKSUM_ADJUST && field != CHECKSUM) {
                fprintf(stderr, "CHECKSUM_ADJUST can only be applied to CHECKSUM field\n");
                return 0;
        }

        if (field == VERSION || field == IHL) {
                fprintf(stderr, "Anonymization of IP fields Version & Internet Header Length is not supported to maintain usability of anonymized data.\n");
                return 0;
        }

        return 1;

}

static int sanity_checks(int protocol, int field_description, int anonymization_function)
{
        if (protocol < IP || protocol > BINARY_PAYLOAD) {
                return MFUNCT_INVALID_ARGUMENT_1;
        }
        //field shouldn't be special enumeration like BASE_FTP_DEFS
        if ((field_description <= BASE_FIELD_DEFS || field_description >= END_FIELD_DEFS)
            || field_description == BASE_FTP_DEFS
            || field_description == END_FTP_DEFS
            || field_description == BASE_HTTP_DEFS
            || field_description == END_HTTP_DEFS
            || field_description == BASE_NETFLOW_V5_DEFS
            || field_description == END_NETFLOW_V5_DEFS
            || field_description == BASE_NETFLOW_V9_DEFS
            || field_description == END_NETFLOW_V9_DEFS
            || field_description == BASE_IPFIX_DEFS || field_description == END_IPFIX_DEFS) {

                return MFUNCT_INVALID_ARGUMENT_2;
        }

        if (anonymization_function < UNCHANGED || anonymization_function > REGEXP) {
                fprintf(stderr, "UNKNOWN FUNCTION\n");
                return MFUNCT_INVALID_ARGUMENT_3;
        }

        if (!can_field_be_applied_to_protocol(protocol, field_description)) {
                fprintf(stderr, "FIELD CANNOT BE APPLIED TO SPECIFIC PROTOCOL\n");
                return MFUNCT_INVALID_ARGUMENT_2;
        }

        if (!can_field_be_applied_to_function(anonymization_function, field_description)) {
                fprintf(stderr, "FIELD CANNOT BE APPLIED TO SPECIFIC FUNCTION\n");
                return MFUNCT_INVALID_ARGUMENT_2;
        }

        return 0;
};

/* Initialisation functions */

void init_mapping_tables()
{
        memset(ipMappingTable, 0, MAPPING_ENTRIES * sizeof(mapNode *));
        memset(portsMappingTable, 0, MAPPING_ENTRIES * sizeof(mapNode *));
        memset(generalMapping32Table, 0, MAPPING_ENTRIES * sizeof(mapNode *));
        memset(generalMapping16Table, 0, MAPPING_ENTRIES * sizeof(mapNode *));
        memset(generalMapping8Table, 0, MAPPING_ENTRIES * sizeof(mapNode *));
}

static int                      components_initialized = 0;

static int anonymize_init(va_list vl, void *fu, struct anonflow *fl)
{
        struct anonymize_data *data;
        struct function *f;

        f = (struct function *)fu;

        data = (struct anonymize_data *)
            malloc(sizeof(struct anonymize_data));
        if (anonymize_unmarshal(vl, data) == -1) {
                fprintf(stderr, "[-] Unmarshaling failed\n");
                return -1;
        }

        if (sanity_checks(data->protocol, data->field, data->function) != 0) {
                fprintf(stderr, "[-] Sanity checks failed\n");
        }

        f->internal_data = (void *)data;

        if (!components_initialized) {
                init_mapping_tables();
                gen_table();
                srandom(time(NULL));
                srand48((long int)time(NULL));
                lookup_init(&addr_propagate);
                components_initialized = 1;
        }

        return 1;
}

/*
 * Overflow & conversion safe byte-swapping function.
 */
void swap(unsigned char *a, unsigned char *b)
{
        *a ^= *b;
        *b ^= *a;
        *a ^= *b;
}

void checkSwap(unsigned char *field_pointer, int field)
{
        if (field == SRC_IP || field == DST_IP || field == SEQUENCE_NUMBER || field == ACK_NUMBER) {
                swap(&field_pointer[0], &field_pointer[3]);
                swap(&field_pointer[1], &field_pointer[1]);
        } else if (field == SRC_PORT || field == DST_PORT || field == PACKET_LENGTH || field == ID) {
                swap(&field_pointer[0], &field_pointer[1]);
        }
}

void
apply_function_to_field(int function, int protocol, int field,
                        unsigned char *field_pointer, int len,
                        unsigned char *header_pointer, int header_len,
                        anonpacket * packet, struct anonymize_data *params)
{
        mapNode       **mapTable;
        int            *counter;
        unsigned char  *packet_end;
        unsigned int    total_len;
        /* XXX this is major fail XXX */
        unsigned char   DES3_keys[24] =
            { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45,
                0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23
        };
        unsigned char   AES_keys[32] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45,
                0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x01, 0x23, 0x45, 0x67, 0x23, 0x45, 0x67, 0x89
        };
        int             helper;

        if (!field_pointer)     //a HTTP reply for example doesn't have URI
                return;

        switch (function) {
        case MAP:
                if (field == SRC_IP || field == DST_IP) {
                        mapTable = ipMappingTable;
                        counter = (int *)&ip_count;
                } else if (field == SRC_PORT || field == DST_PORT) {
                        mapTable = portsMappingTable;
                        counter = &ports_count;
                } else {
                        if (len == 4) {
                                mapTable = generalMapping32Table;
                                counter = &general32_count;
                        } else if (len == 2) {
                                mapTable = generalMapping16Table;
                                counter = &general16_count;
                        } else {
                                mapTable = generalMapping8Table;
                                counter = &general8_count;
                        }
                }
                map_field(field_pointer, len, mapTable, counter);
                //checkSwap(field_pointer,field);

                break;
        case BD_MAP:
                if (field == SRC_IP) { // || field == SRC_PORT
                        mapTable = srcIpMappingTable;
                        counter = (int *)&src_ip_count;
                } else if (field == DST_IP) { // || field == DST_PORT
                        mapTable = dstIpMappingTable;
                        counter = (int *)&dst_ip_count;
                } else {
                        fprintf(stderr,
                                "Bidirectional mapping doesn't work on fields other than SRC/DST IP.\n");
                        return;
                }

                map_field(field_pointer, len, mapTable, counter);
                break;
        case MAP_DISTRIBUTION:
                map_distribution(field_pointer, len,
                                 params->distribution_type, params->median,
                                 params->standard_deviation);
                //checkSwap(field_pointer,field);
                break;
        case PREFIX_PRESERVING:
                prefix_preserving_anonymize_field(field_pointer);
                break;
        case PREFIX_PRESERVING_MAP:
                hide_addr(field_pointer);
                break;
        case STRIP:
                //printf("++I will call STRIP and I will keep %d bytes\n",params->seed);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                strip(packet, header_pointer, header_len, params->seed, total_len, packet_end);
                break;
        case HASHED:
                //printf("I will call HASH for algorithm %d and padding %d\n",params->hash_algorithm,params->padding_behavior);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                int             donotreplace = 0;
                if (field >= CHECKSUM && field <= CODE)
                        donotreplace = 1;
                switch (params->hash_algorithm) {
                case SHA:
                        sha1_hash(field_pointer, len,
                                  params->padding_behavior, packet,
                                  total_len, packet_end, donotreplace);
                        break;
                case MD5:
                        md5_hash(field_pointer, len,
                                 params->padding_behavior, packet, total_len,
                                 packet_end, donotreplace);
                        break;
                case CRC32:
                        crc32_hash(field_pointer, len,
                                   params->padding_behavior, packet,
                                   total_len, packet_end, donotreplace);
                        break;
                case SHA_2:
                        sha256_hash(field_pointer, len,
                                    params->padding_behavior, packet,
                                    total_len, packet_end, donotreplace);
                        break;
                case DES:
                case TRIPLEDES:
                        des_hash(field_pointer, len,
                                 (unsigned char *)DES3_keys, params->padding_behavior, packet);
                        break;
                case AES:
                        aes_hash(field_pointer, len,
                                 (unsigned char *)AES_keys, 8 * sizeof(AES_keys), params->padding_behavior, packet);
                        break;
                default:
                        fprintf(stderr, "[-] Fatal Error, unknown hash algorithm\n");
                        exit(0);
                }
                break;
        case PATTERN_FILL:
                //printf("I will call PATTERN_FILL with type %d and pattern: %s\n",params->pattern_type,params->pattern);
                switch (params->pattern_type) {
                case 0: //integers
                        helper = atoi(params->pattern);
                        pattern_fill_field(field_pointer, len,
                                           params->pattern_type, (void *)&helper);
                        break;
                case 1:
                        pattern_fill_field(field_pointer, len,
                                           params->pattern_type, (void *)params->pattern);
                        break;
                }
                checkSwap(field_pointer, field);
                break;
        case FILENAME_RANDOM:
                //printf("++I will call FILENAME_RANDOM (%p,%d)\n",field_pointer,len);
                filename_random_field(field_pointer, len);
                break;
        case RANDOM:
                //printf("++I will call RANDOM %u.%u.%u.%u\n",field_pointer[0],field_pointer[1],field_pointer[2],field_pointer[3]);
                random_field(field_pointer, len);
                break;
        case ZERO:
                memset(field_pointer, 0, len);
                break;
        case REPLACE:
                //printf("++I will call REPLACE with pattern: %s\n",params->pattern);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                replace_field(field_pointer, len,
                              (unsigned char *)params->pattern,
                              strlen(params->pattern), packet, total_len, packet_end);
                break;
        case CHECKSUM_ADJUST:
                switch (protocol) {
                case IP:
                        packet->iph->ip_csum = calculate_ip_sum(packet);

                        /* pseudoheader uses some info from IP */
                        if (packet->tcph) {
                                packet->tcph->th_sum = calculate_tcp_sum(packet);
                        } else if (packet->udph) {
                                packet->udph->uh_chk = calculate_udp_sum(packet);
                        }
                        break;
                case TCP:
                        packet->tcph->th_sum = calculate_tcp_sum(packet);
                        break;
                case UDP:
                        packet->udph->uh_chk = calculate_udp_sum(packet);
                        break;
                case ICMP:
                        packet->icmph->csum = calculate_icmp_sum(packet);
                        break;
                case HTTP:
                case FTP:
                        /* pseudoheader uses some info from IP */
                        if (packet->tcph) {
                                packet->tcph->th_sum = calculate_tcp_sum(packet);
                        }
                        break;
                }
                break;
        case REGEXP:
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                reg_exp_substitute(field_pointer, len, params->regexp,
                                   params->replaceVector,
                                   params->num_of_matches, packet, total_len, packet_end);
                break;
        case VALUE_SHIFT:
                value_shift(field_pointer, len);
                break;
        default:
                break;
        }
}

void
anonymize_field(int protocol, int field, int function, anonpacket * packet,
                struct anonymize_data *params, struct anonflow *flow)
{
        unsigned char  *field_pointer = NULL;
        unsigned char  *header_pointer = NULL;
        unsigned int    len = 0, header_len = 0;

        int             i;
        unsigned char   DES3_keys[24] =
            { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45,
                0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23
        };
        unsigned char   AES_keys[32] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45,
                0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0x01, 0x23, 0x01, 0x23, 0x45, 0x67, 0x23, 0x45, 0x67, 0x89
        };
        unsigned char  *packet_end;
        unsigned int    total_len;

        if (!packet) {
                fprintf(stderr, "WARNING: NULL packet\n");
                return;
        }

        if (function == UNCHANGED)
                return;

        switch (protocol) {
        case ETHERNET:
                if (!packet->eh) {
                        return;
                }
                switch (field) {
                case SRC_IP:
                        field_pointer = (unsigned char *)(packet->eh->ether_src);
                        len = 6;
                        break;
                case DST_IP:
                        field_pointer = (unsigned char *)(packet->eh->ether_dst);
                        len = 6;
                        break;
                case ETHER_TYPE:
                        field_pointer = (unsigned char *)(&(packet->eh->ether_type));
                        len = 2;
                        break;
                default:
                        break;
                }
                break;
        case IP:
                if (!packet->iph) {
                        return;
                }
                switch (field) {
                case PAYLOAD:
                        field_pointer =
                            (unsigned char *)(packet->iph) + sizeof(IPHdr) + packet->ip_options_len;
                        header_pointer = field_pointer;
                        len = header_len =
                            ntohs(packet->iph->ip_len) - sizeof(IPHdr) - packet->ip_options_len;
                        break;
                case CHECKSUM:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_csum));
                        len = 2;
                        break;
                case TTL:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_ttl));
                        len = 1;
                        break;
                case SRC_IP:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_src));
                        len = 4;
                        break;
                case DST_IP:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_dst));
                        len = 4;
                        break;
                case TOS:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_tos));
                        len = 1;
                        break;
                case ID:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_id));
                        len = 2;
                        break;
                case FRAGMENT_OFFSET:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_off));
                        len = 2;
                        break;
                case VERSION:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_verhl));
                        len = 1;
                        break;
                case IHL:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_verhl));
                        len = 1;
                        break;
                case PACKET_LENGTH:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_len));
                        len = 2;
                        break;
                case IP_PROTO:
                        field_pointer = (unsigned char *)(&(packet->iph->ip_proto));
                        len = 1;
                        break;
                case OPTIONS:
                        field_pointer = (unsigned char *)(packet->ip_options_data);
                        header_pointer = (unsigned char *)(packet->ip_options_data);
                        len = header_len = packet->ip_options_len;
                        break;
                default:
                        break;
                }
                break;
        case TCP:
                if (!packet->tcph)
                        return;

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {      //hierarchical
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }
                switch (field) {
                case PAYLOAD:
                        field_pointer = (unsigned char *)(packet->data);
                        header_pointer = (unsigned char *)(packet->data);
                        len = header_len = packet->dsize;
                        break;
                case CHECKSUM:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_sum));
                        len = 2;
                        break;
                case SRC_PORT:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_sport));
                        len = 2;
                        break;
                case DST_PORT:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_dport));
                        len = 2;
                        break;
                case SEQUENCE_NUMBER:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_seq));
                        len = 4;
                        break;
                case ACK_NUMBER:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_ack));
                        len = 4;
                        break;
                case WINDOW:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_win));
                        len = 2;
                        break;
                case FLAGS:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_flags));
                        len = 1;
                        break;
                case OFFSET_AND_RESERVED:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_offx2));
                        len = 1;
                        break;
                case URGENT_POINTER:
                        field_pointer = (unsigned char *)(&(packet->tcph->th_urp));
                        len = 2;
                        break;
                case TCP_OPTIONS:
                        field_pointer = packet->tcp_options_data;
                        header_pointer = packet->tcp_options_data;
                        len = packet->tcp_options_len;
                        break;
                default:
                        break;
                }
                break;
        case UDP:
                if (!packet->udph)
                        return;

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {      //hierarchical
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }
                switch (field) {
                case PAYLOAD:
                        field_pointer = (unsigned char *)(packet->udph) + sizeof(UDPHdr);       //maybe packet->data should be better
                        header_pointer = (unsigned char *)(packet->udph) + sizeof(UDPHdr);      //maybe packet->data should be better
                        len = header_len = packet->dsize;
                        break;
                case CHECKSUM:
                        field_pointer = (unsigned char *)(&(packet->udph->uh_chk));
                        len = 2;
                        break;
                case SRC_PORT:
                        field_pointer = (unsigned char *)(&(packet->udph->uh_sport));
                        len = 2;
                        break;
                case DST_PORT:
                        field_pointer = (unsigned char *)(&(packet->udph->uh_dport));
                        len = 2;
                        break;
                case UDP_DATAGRAM_LENGTH:
                        field_pointer = (unsigned char *)(&(packet->udph->uh_len));
                        len = 2;
                        break;
                default:
                        break;
                }
                break;
        case ICMP:
                if (!packet->icmph)
                        return;

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {      //hierarchical
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }
                switch (field) {
                case PAYLOAD:
                        field_pointer = (unsigned char *)(packet->icmph) + sizeof(ICMPHdr);
                        header_pointer = (unsigned char *)(packet->icmph) + sizeof(ICMPHdr);
                        len = header_len = packet->dsize;
                        break;
                case CHECKSUM:
                        field_pointer = (unsigned char *)(&(packet->icmph->csum));
                        len = 2;
                        break;
                case TYPE:
                        field_pointer = (unsigned char *)(&(packet->icmph->type));
                        len = 1;
                        break;
                case CODE:
                        field_pointer = (unsigned char *)(&(packet->icmph->code));
                        len = 1;
                        break;
                default:
                        break;
                }
                break;
        case HTTP:
        {
                struct httpheader *h;

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {      //hierarchical
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }

                if (field >= SRC_PORT && field <= TCP_OPTIONS) {
                        return anonymize_field(TCP, field, function, packet, params, flow);
                        break;
                }
                //decode the http if we haven't done so
                if (packet->num_of_upper_layer_protocols == 0) {
                        //packet->upper_layer_protocol_headers[0]=(void *)malloc(sizeof(struct httpheader));
                        packet->upper_layer_protocol_headers[0] = &default_http_header;
                        if (http_decode
                            (packet,
                             (struct httpheader *)packet->upper_layer_protocol_headers[0]) == -1) {
                                //printf("Cannot parse HTTP protocol\n");
                                //free(packet->upper_layer_protocol_headers[0]);
                                return;
                        } else {
                                packet->upper_layer_names[0] = HTTP;
                                packet->num_of_upper_layer_protocols++;
                                h = (struct httpheader *)packet->upper_layer_protocol_headers[0];
                        }
                } else {        //try to find the HTTP header
                        int             j;
                        for (j = 0; j < packet->num_of_upper_layer_protocols; j++) {
                                if (packet->upper_layer_names[j] == HTTP)
                                        break;
                        }

                        if (j == packet->num_of_upper_layer_protocols)
                                return;
                        h = (struct httpheader *)packet->upper_layer_protocol_headers[j];

                }

                for (i = 0; i < h->pipeline_depth; i++) {
                        switch (field) {
                        case PAYLOAD:
                                field_pointer = h->pointers_to_value[i]
                                    [HTTP_PAYLOAD - BASE_HTTP_DEFS - 1];
                                header_pointer = h->pointers_to_value[i]
                                    [HTTP_PAYLOAD - BASE_HTTP_DEFS - 1];
                                len = header_len =
                                    h->value_length[i][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1];
                                break;
                        default:
                                field_pointer = h->pointers_to_value[i][field - BASE_HTTP_DEFS - 1];
                                len = h->value_length[i][field - BASE_HTTP_DEFS - 1];

                                header_pointer =
                                    h->pointers_to_header[i][field - BASE_HTTP_DEFS - 1];
                                header_len = h->header_length[i][field - BASE_HTTP_DEFS - 1];
                                break;
                        }
                        apply_function_to_field(function, protocol,
                                                field, field_pointer,
                                                len, header_pointer, header_len, packet, params);
                }
                return;
                break;
        }
        case FTP:
        {
                struct ftpheader *h;
                //decode the ftp if we haven't done so
                if (packet->num_of_upper_layer_protocols == 0) {
                        packet->upper_layer_protocol_headers[0] = &default_ftp_header;
                        if (ftp_decode
                            (packet,
                             (struct ftpheader *)packet->upper_layer_protocol_headers[0]) == -1) {
                                //printf("Cannot parse FTP protocol\n");
                                //free(packet->upper_layer_protocol_headers[0]);
                                return;
                        } else {
                                packet->upper_layer_names[0] = FTP;
                                packet->num_of_upper_layer_protocols++;
                                h = (struct ftpheader *)packet->upper_layer_protocol_headers[0];
                        }
                } else {        //try to find the HTTP header
                        int             j;
                        for (j = 0; j < packet->num_of_upper_layer_protocols; j++) {
                                if (packet->upper_layer_names[j] == FTP)
                                        break;
                        }

                        if (j == packet->num_of_upper_layer_protocols)
                                return;
                        h = (struct ftpheader *)packet->upper_layer_protocol_headers[j];

                }

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {      //hierarchical
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }

                if (field >= SRC_PORT && field <= TCP_OPTIONS) {
                        return anonymize_field(TCP, field, function, packet, params, flow);
                        break;
                }

                switch (field) {
                case PAYLOAD:
                        return;
                default:
                        field_pointer = h->pointers_to_value[field - BASE_FTP_DEFS - 1];
                        len = h->value_length[field - BASE_HTTP_DEFS - 1];

                        header_pointer = h->pointers_to_header[field - BASE_FTP_DEFS - 1];
                        header_len = h->header_length[field - BASE_FTP_DEFS - 1];
                        break;
                }
                break;
        }
        case NETFLOW_V5:
        {
                int             i = 0;
                uint32_t        offset = sizeof(struct NF5_RECORD);
                struct NETFLOW_V5 *netflow;
                if ((netflow = malloc(sizeof(struct NETFLOW_V5))) == NULL) {
                        fprintf(stderr, "Allocation of struct NETFLOW_V5 failed.\n");
                        return;
                }

                memset(netflow, 0, sizeof(struct NETFLOW_V5));

                if (netflow_v5_decode(packet, netflow) == -1) {
                        free(netflow);
                        return;
                }

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {
                        anonymize_field(IP, field, function, packet, params, flow);
                        if (netflow->r)
                                free(netflow->r);
                        free(netflow);
                        return;
                        break;
                }
                if (field == SRC_PORT || field == DST_PORT
                    || field == PAYLOAD || field == CHECKSUM || field == UDP_DATAGRAM_LENGTH) {
                        anonymize_field(UDP, field, function, packet, params, flow);
                        if (netflow->r)
                                free(netflow->r);
                        free(netflow);
                        break;
                }

                switch (field) {
                case NF5_VERSION:
                        field_pointer = (unsigned char *)&(netflow->h->version);
                        len = sizeof(netflow->h->version);
                        break;
                case NF5_FLOWCOUNT:
                        field_pointer = (unsigned char *)&(netflow->h->flowcount);
                        len = sizeof(netflow->h->flowcount);
                        break;
                case NF5_UPTIME:
                        field_pointer = (unsigned char *)&(netflow->h->uptime);
                        len = sizeof(netflow->h->uptime);
                        break;
                case NF5_UNIX_SECS:
                        field_pointer = (unsigned char *)&(netflow->h->unix_secs);
                        len = sizeof(netflow->h->unix_secs);
                        break;
                case NF5_UNIX_NSECS:
                        field_pointer = (unsigned char *)&(netflow->h->unix_nsecs);
                        len = sizeof(netflow->h->unix_nsecs);
                        break;
                case NF5_SEQUENCE:
                        field_pointer = (unsigned char *)&(netflow->h->sequence);
                        len = sizeof(netflow->h->sequence);
                        break;
                case NF5_ENGINE_TYPE:
                        field_pointer = (unsigned char *)&(netflow->h->engine_type);
                        len = sizeof(netflow->h->engine_type);
                        break;
                case NF5_ENGINE_ID:
                        field_pointer = (unsigned char *)&(netflow->h->engine_id);
                        len = sizeof(netflow->h->engine_id);
                        break;
                case NF5_SRCADDR:
                        offset = 0;
                        netflow->field_lengths[NF5_SRCADDR -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->srcaddr);
                        break;
                case NF5_DSTADDR:
                        offset = 4;
                        netflow->field_lengths[NF5_DSTADDR -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->dstaddr);
                        break;
                case NF5_NEXTHOP:
                        offset = 8;
                        netflow->field_lengths[NF5_NEXTHOP -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->nexthop);
                        break;
                case NF5_INPUT:
                        offset = 12;
                        netflow->field_lengths[NF5_INPUT -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->input);
                        break;
                case NF5_OUTPUT:
                        offset = 14;
                        netflow->field_lengths[NF5_OUTPUT -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->output);
                        break;
                case NF5_DPKTS:
                        offset = 16;
                        netflow->field_lengths[NF5_DPKTS -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->dPkts);
                        break;
                case NF5_DOCTETS:
                        offset = 20;
                        netflow->field_lengths[NF5_DOCTETS -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->dOctets);
                        break;
                case NF5_FIRST:
                        offset = 24;
                        netflow->field_lengths[NF5_FIRST -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->First);
                        break;
                case NF5_LAST:
                        offset = 28;
                        netflow->field_lengths[NF5_LAST -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->Last);
                        break;
                case NF5_SRCPORT:
                        offset = 32;
                        netflow->field_lengths[NF5_SRCPORT -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->srcport);
                        break;
                case NF5_DSTPORT:
                        offset = 34;
                        netflow->field_lengths[NF5_DSTPORT -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->dstport);
                        break;
                case NF5_TCP_FLAGS:
                        offset = 37;
                        netflow->field_lengths[NF5_TCP_FLAGS -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->tcp_flags);
                        break;
                case NF5_PROT:
                        offset = 38;
                        netflow->field_lengths[NF5_PROT -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->prot);
                        break;
                case NF5_TOS:
                        offset = 39;
                        netflow->field_lengths[NF5_TOS -
                                               BASE_NETFLOW_V5_DEFS] = sizeof(netflow->r[0]->tos);
                        break;
                case NF5_SRC_AS:
                        offset = 40;
                        netflow->field_lengths[NF5_SRC_AS -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->src_as);
                        break;
                case NF5_DST_AS:
                        offset = 42;
                        netflow->field_lengths[NF5_DST_AS -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->dst_as);
                        break;
                case NF5_SRC_MASK:
                        offset = 44;
                        netflow->field_lengths[NF5_SRC_MASK -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->src_mask);
                        break;
                case NF5_DST_MASK:
                        offset = 45;
                        netflow->field_lengths[NF5_DST_MASK -
                                               BASE_NETFLOW_V5_DEFS] =
                            sizeof(netflow->r[0]->dst_mask);
                        break;
                default:
                        // Strange shit has happened.
                        break;
                }

                if (offset != sizeof(struct NF5_RECORD)) {
                        int             nrec = ntohs(netflow->h->flowcount);

                        for (i = 0; i < nrec; i++) {
                                field_pointer = (unsigned char *)netflow->r[i] + offset;

                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        netflow->field_lengths
                                                        [field -
                                                         BASE_NETFLOW_V5_DEFS],
                                                        header_pointer, header_len, packet, params);
                        }
                        free(netflow->r);
                        free(netflow);
                        return;
                }

                if (netflow->r)
                        free(netflow->r);
                free(netflow);
                break;
        }
        case NETFLOW_V9:
        {
                struct NETFLOW_V9 *netflow;
                if ((netflow = malloc(sizeof(struct NETFLOW_V9))) == NULL) {
                        fprintf(stderr, "Allocation of struct NETFLOW_V9 failed\n");
                        return;
                }
                // Decode NetFlow header. Keeps template records in a list.
                if (netflow_v9_decode(packet, netflow, flow) == -1) {
                        /*
                         * Nothing (correct) to anonymize.
                         */
                        return;
                }
                /*
                 * From this point on, netflow can be anonymized.
                 * Still we need access to the template lists to do so.
                 */

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }
                if (field == SRC_PORT || field == DST_PORT
                    || field == PAYLOAD || field == CHECKSUM || field == UDP_DATAGRAM_LENGTH) {
                        return anonymize_field(UDP, field, function, packet, params, flow);
                        break;
                }

                switch (field) {
                        // Header fields.
                case NF9_VERSION:
                        field_pointer = (unsigned char *)&(netflow->header->version);
                        len = sizeof(uint16_t);
                        break;
                case NF9_COUNT:
                        field_pointer = (unsigned char *)&(netflow->header->count);
                        len = sizeof(uint16_t);
                        break;
                case NF9_UPTIME:
                        field_pointer = (unsigned char *)&(netflow->header->uptime);
                        len = sizeof(uint32_t);
                        break;
                case NF9_UNIXSECS:
                        field_pointer = (unsigned char *)&(netflow->header->seconds);
                        len = sizeof(uint32_t);
                        break;
                case NF9_PACKAGESEQ:
                        field_pointer = (unsigned char *)&(netflow->header->sequence);
                        len = sizeof(uint32_t);
                        break;
                case NF9_SOURCEID:
                        field_pointer = (unsigned char *)&(netflow->header->source_id);
                        len = sizeof(uint32_t);
                        break;
                        // Fields common to all flowsets.
                case NF9_FLOWSET_ID:
                {
                        int             i = 0;
                        len = sizeof(uint16_t);
                        for (i = 0; i < netflow->ntemplates; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->template_flowsets[i]->c->flowset_id);

                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < netflow->ndata; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->data_flowsets[i]->c->flowset_id);
                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < netflow->noptions; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->option_templates[i]->c->flowset_id);
                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                }
                        break;
                case NF9_LENGTH:
                {
                        int             i = 0;
                        len = sizeof(uint16_t);
                        for (i = 0; i < netflow->ntemplates; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->template_flowsets[i]->c->length);

                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < netflow->ndata; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->data_flowsets[i]->c->length);
                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < netflow->noptions; i++) {
                                field_pointer = (unsigned char *)
                                    &(netflow->option_templates[i]->c->length);
                                apply_function_to_field
                                    (function, protocol,
                                     field, field_pointer,
                                     len, header_pointer, header_len, packet, params);
                        }
                }
                        break;
                        /*
                         * All other cases go here.
                         * Like hell I'm going to write 88 different cases.
                         */
                default:
                {
                        assert((field > BASE_NETFLOW_V9_FIELDS && field < END_NETFLOW_V9_FIELDS)
                               || (field >
                                   BASE_NETFLOW_V9_SCOPES && field < END_NETFLOW_V9_SCOPES));
                        /*
                         * For every data flowset,
                         *      search for its ID amongst the stored templates.
                         *      If found ,
                         *              If the template contains the specified field,
                         *                      Anonymize the data flowset.
                         */
                        struct NF9_TEMPLATE *template = NULL;
                        struct NF9_OPTIONS_TEMPLATE *opts = NULL;
                        int             d = 0, t = 0;
                        for (d = 0; d < netflow->ndata; d++) {
                                if ((template =
                                     flist_get(flow->nf9_templates,
                                               ntohs(netflow->data_flowsets[d]->c->flowset_id)))
                                    != NULL) {  // Found a corresponding template.
                                        for (t = 0; t < template->inf->field_count; t++) {
                                                if (template->records[t]->field_type == field - BASE_NETFLOW_V9_FIELDS) {       // Found field in template.
                                                        uint16_t        i = 0, template_len =
                                                            0, offset = 0;

                                                        uint16_t        data_length =
                                                            ntohs(netflow->data_flowsets[d]->c->
                                                                  length) - 2 * sizeof(uint16_t);
                                                        unsigned char  *target =
                                                            netflow->data_flowsets[d]->field_values;
                                                        uint16_t        target_len =
                                                            template->records[t]->field_length;

                                                        // Find the field's offset in the template.
                                                        for (i = 0; i < t; i++) {
                                                                offset +=
                                                                    template->records[i]->
                                                                    field_length;
                                                        }
                                                        // Set the target to point on the field.
                                                        target += offset;
                                                        // Find the template's length.
                                                        for (i
                                                             =
                                                             0;
                                                             i < template->inf->field_count; i++) {
                                                                template_len
                                                                    +=
                                                                    template->records
                                                                    [i]->field_length;
                                                        }
                                                        // Now anonymize the field in all records.
                                                        do {
                                                                apply_function_to_field
                                                                    (function,
                                                                     protocol,
                                                                     field,
                                                                     target,
                                                                     target_len,
                                                                     header_pointer,
                                                                     header_len, packet, params);
                                                                target += template_len;
                                                        }
                                                        while (target -
                                                               netflow->data_flowsets[d]->
                                                               field_values < data_length);
                                                        break;
                                                }
                                        }
                                } else if ((opts =
                                            flist_get(flow->nf9_option_templates,
                                                      ntohs
                                                      (netflow->data_flowsets[d]->c->flowset_id)))
                                           != NULL) {   // Found a corresponding options template.
                                        if (field >
                                            BASE_NETFLOW_V9_SCOPES
                                            && field < END_NETFLOW_V9_SCOPES) {
                                                for (t = 0; t < opts->nscopes; t++) {
                                                        if (opts->scope_fields[t]->field_type == field - BASE_NETFLOW_V9_SCOPES) {      // Gotcha.
                                                                uint16_t        i =
                                                                    0, template_len = 0, offset = 0;
                                                                uint16_t        data_length =
                                                                    ntohs(netflow->
                                                                          data_flowsets[d]->c->
                                                                          length) -
                                                                    2 * sizeof(uint16_t);
                                                                unsigned char  *target =
                                                                    netflow->data_flowsets[d]->
                                                                    field_values;
                                                                uint16_t        target_len =
                                                                    opts->scope_fields[t]->
                                                                    field_length;

                                                                for (i = 0; i < t; i++) {
                                                                        offset +=
                                                                            opts->scope_fields[i]->
                                                                            field_length;
                                                                }
                                                                target += offset;
                                                                template_len
                                                                    =
                                                                    opts->inf->option_scope_len
                                                                    + opts->inf->option_len;
                                                                do {
                                                                        apply_function_to_field
                                                                            (function,
                                                                             protocol,
                                                                             field,
                                                                             target,
                                                                             target_len,
                                                                             header_pointer,
                                                                             header_len,
                                                                             packet, params);
                                                                        target += template_len;
                                                                }
                                                                while (target -
                                                                       netflow->data_flowsets[d]->
                                                                       field_values < data_length);
                                                        }
                                                }
                                        } else {
                                                for (t = 0; t < opts->nopts; t++) {
                                                        if (opts->option_fields[t]->field_type ==
                                                            field - BASE_NETFLOW_V9_FIELDS) {
                                                                uint16_t        i =
                                                                    0, template_len = 0, offset = 0;
                                                                uint16_t        data_len =
                                                                    ntohs(netflow->
                                                                          data_flowsets[d]->c->
                                                                          length -
                                                                          2 * sizeof(uint16_t));
                                                                unsigned char  *target =
                                                                    netflow->data_flowsets[d]->
                                                                    field_values;
                                                                uint16_t        target_len =
                                                                    opts->scope_fields[t]->
                                                                    field_length;

                                                                offset +=
                                                                    opts->inf->option_scope_len;
                                                                for (i = 0; i < t; i++) {
                                                                        offset +=
                                                                            opts->option_fields[i]->
                                                                            field_length;
                                                                }
                                                                target += offset;
                                                                template_len
                                                                    =
                                                                    opts->inf->option_scope_len
                                                                    + opts->inf->option_len;
                                                                do {
                                                                        apply_function_to_field
                                                                            (function,
                                                                             protocol,
                                                                             field,
                                                                             target,
                                                                             target_len,
                                                                             header_pointer,
                                                                             header_len,
                                                                             packet, params);
                                                                        target += template_len;
                                                                }
                                                                while (target -
                                                                       netflow->data_flowsets[d]->
                                                                       field_values < data_len);
                                                        }
                                                }
                                        }
                                }
                        }
                }
                        break;
                }

                /*
                 * Free the netflow.
                 */
                while (netflow->ntemplates--) {
                        uint16_t        templates =
                            netflow->template_flowsets[netflow->ntemplates]->ntemps;

                        while (templates--) {
                                free(netflow->template_flowsets[netflow->ntemplates]->templates
                                     [templates]->records);
                                free(netflow->template_flowsets[netflow->ntemplates]->templates
                                     [templates]);
                        }
                        free(netflow->template_flowsets[netflow->ntemplates]);
                }
                while (netflow->ndata--) {
                        free(netflow->data_flowsets[netflow->ndata]);
                }
                while (netflow->noptions--) {
                        while (netflow->option_templates[netflow->noptions]->nscopes--) {
                                free(netflow->option_templates[netflow->noptions]->scope_fields
                                     [netflow->option_templates[netflow->noptions]->nscopes]);
                        }
                        while (netflow->option_templates[netflow->noptions]->nopts--) {
                                free(netflow->option_templates[netflow->noptions]->option_fields
                                     [netflow->option_templates[netflow->noptions]->nopts]);
                        }
                        free(netflow->option_templates[netflow->noptions]);
                }
                free(netflow);
                // Escape.
                if (field > NF9_SOURCEID && field < END_NETFLOW_V9_FIELDS) {    // Already anonymized. We know where we're going. Out.
                        return;
                }
                break;
        }

        case IPFIX:
        {
                int             i = 0, j = 0;
                struct IPFIX   *ipfix;
                struct ipfix_template_set *templateset;

                if ((ipfix = malloc(sizeof(struct IPFIX))) == NULL
                    || (templateset = malloc(sizeof(struct ipfix_template_set)))
                    == NULL) {
                        fprintf(stderr, "Allocation of struct IPFIX failed\n");
                        return;
                }
                memset(ipfix, 0, sizeof(struct IPFIX));
                if (ipfix_decode(packet, ipfix, flow) == -1) {
                        return;
                }

                if (field >= SRC_IP && field <= FRAGMENT_OFFSET) {
                        return anonymize_field(IP, field, function, packet, params, flow);
                        break;
                }
                // XXX IPFIX over TCP, UDP, SCTP..
                if (field == SRC_PORT || field == DST_PORT
                    || field == PAYLOAD || field == CHECKSUM || field == UDP_DATAGRAM_LENGTH) {
                        return anonymize_field(UDP, field, function, packet, params, flow);
                        break;
                }
                // Anonymize.
                switch (field) {
                        // Header fields
                case IPFIX_VERSION:
                        field_pointer = (unsigned char *)&(ipfix->header->version);
                        len = sizeof(uint16_t);
                        break;
                case IPFIX_MSG_LENGTH:
                        field_pointer = (unsigned char *)&(ipfix->header->length);
                        len = sizeof(uint16_t);
                        break;
                case IPFIX_EXPORT_TIME:
                        field_pointer = (unsigned char *)&(ipfix->header->export_time);
                        len = sizeof(uint16_t);
                        break;
                case IPFIX_SEQUENCE:
                        field_pointer = (unsigned char *)&(ipfix->header->sequence);
                        len = sizeof(uint16_t);
                        break;
                case IPFIX_OBSERV_ID:
                        field_pointer = (unsigned char *)&(ipfix->header->domain);
                        len = sizeof(uint16_t);
                        break;
                        // Common set header fields
                case IPFIX_SET_ID:
                        for (i = 0; i < ipfix->ntemplates; i++) {
                                field_pointer = (unsigned char *)&(ipfix->templates[i]->header->id);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < ipfix->noptions; i++) {
                                field_pointer =
                                    (unsigned char *)&(ipfix->options[i]->setheader->id);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < ipfix->ndata; i++) {
                                field_pointer = (unsigned char *)&(ipfix->data[i]->header->id);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        break;
                case IPFIX_SET_LENGTH:
                        for (i = 0; i < ipfix->ntemplates; i++) {
                                field_pointer =
                                    (unsigned char *)&(ipfix->templates[i]->header->length);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < ipfix->noptions; i++) {
                                field_pointer =
                                    (unsigned char *)&(ipfix->options[i]->setheader->length);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        for (i = 0; i < ipfix->ndata; i++) {
                                field_pointer = (unsigned char *)&(ipfix->data[i]->header->length);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        break;
                        // Template header fields
                case IPFIX_TEMPLATE_ID:
                        for (i = 0; i < ipfix->ntemplates; i++)
                                for (j = 0; j < ipfix->templates[i]->nrecords; j++) {
                                        field_pointer = (unsigned char *)
                                            &(ipfix->templates[i]->records[j]->header->id);
                                        len = sizeof(uint16_t);
                                        apply_function_to_field
                                            (function, protocol,
                                             field, field_pointer,
                                             len, header_pointer, header_len, packet, params);
                                }
                        break;
                case IPFIX_TEMPLATE_COUNT:
                        for (i = 0; i < ipfix->ntemplates; i++)
                                for (j = 0; j < ipfix->templates[i]->nrecords; j++) {
                                        field_pointer = (unsigned char *)
                                            &(ipfix->templates[i]->records[j]->header->count);
                                        len = sizeof(uint16_t);
                                        apply_function_to_field
                                            (function, protocol,
                                             field, field_pointer,
                                             len, header_pointer, header_len, packet, params);
                                }
                        break;
                        // Option header fields
                case IPFIX_OPTION_HDR_ID:
                        for (i = 0; i < ipfix->noptions; i++) {
                                field_pointer = (unsigned char *)&(ipfix->options[i]->header->id);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        break;
                case IPFIX_OPTION_HDR_COUNT:
                        for (i = 0; i < ipfix->noptions; i++) {
                                field_pointer =
                                    (unsigned char *)&(ipfix->options[i]->header->field_count);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        break;
                case IPFIX_OPTION_HDR_SCOPE:
                        for (i = 0; i < ipfix->noptions; i++) {
                                field_pointer =
                                    (unsigned char *)&(ipfix->options[i]->header->scope_count);
                                len = sizeof(uint16_t);
                                apply_function_to_field(function,
                                                        protocol,
                                                        field,
                                                        field_pointer,
                                                        len,
                                                        header_pointer, header_len, packet, params);
                        }
                        break;

                default:
                        /*
                         * Data fields.
                         */
                {
                        assert(field > BASE_IPFIX_FIELD_DEFS && field < END_IPFIX_FIELD_DEFS);
                        /*
                         * For each data set,
                         *      if there exists a corresponding template (option or not),
                         *      and if the specified field exists in the template,
                         *              anonymize it in the data set.
                         */

                        struct ipfix_template_record
                                       *tmp_record = NULL;
                        struct ipfix_option_template_set
                                       *tmp_opts = NULL;
                        uint16_t        d = 0, t = 0, rid = 0, vendor = 0;      // vendor = 0 -> IETF field

                        for (d = 0; d < ipfix->ndata; d++) {
                                if ((tmp_record = flist_get(flow->ipfix_templates, ipfix->data[d]->header->id)) != NULL) {      // Got a corresponding template record.
                                        for (t = 0; t < tmp_record->nfields; t++) {
                                                vendor = ((*
                                                           ((uint16_t *) tmp_record->
                                                            fields[t])) & (1 << 15));
                                                if (vendor)     // Vendor-specified
                                                {
                                                        uint16_t        processed = 0;
                                                        uint16_t        target_len = 0;
                                                        struct ipfix_vendor_field_specifier
                                                            *anonfield =
                                                            (struct ipfix_vendor_field_specifier *)
                                                            tmp_record->fields[t];
                                                        // Clear the first bit of the ID.
                                                        rid = anonfield->id;
                                                        rid &= ~(1 << 15);

                                                        if (rid == field) {
                                                                unsigned char  *target =
                                                                    (unsigned char *)ipfix->
                                                                    data[d]->header;
                                                                uint16_t        offset = 0;
                                                                uint16_t        set_length =
                                                                    ntohs(ipfix->data[d]->header->
                                                                          length);
                                                                uint16_t        record_length = 0;

                                                                for (i = 0; i < t; i++)
                                                                        if (((unsigned
                                                                              char)(*tmp_record->
                                                                                    fields[i] & (1
                                                                                                 <<
                                                                                                 15)))
                                                                            == 0) {
                                                                                offset +=
                                                                                    sizeof(struct
                                                                                           ipfix_vendor_field_specifier);
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_vendor_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i])->
                                                                                          length);
                                                                        } else {
                                                                                offset +=
                                                                                    sizeof(struct
                                                                                           ipfix_ietf_field_specifier);
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_ietf_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i])->
                                                                                          length);
                                                                        }
                                                                while (i < tmp_record->nfields)
                                                                        if (((unsigned
                                                                              char)(*tmp_record->
                                                                                    fields[i] & (1
                                                                                                 <<
                                                                                                 15)))
                                                                            == 0)
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_vendor_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i++])->
                                                                                          length);
                                                                        else
                                                                                record_length
                                                                                    +=
                                                                                    ntohs
                                                                                    (((struct
                                                                                       ipfix_ietf_field_specifier
                                                                                       *)
                                                                                      tmp_record->
                                                                                      fields[i++])->
                                                                                     length);
                                                                // XXX ALIGN RECORD_LENGTH ON 32 BIT BOUNDARY

                                                                target_len
                                                                    = ntohs(anonfield->length);
                                                                processed
                                                                    =
                                                                    sizeof(struct ipfix_set_header);
                                                                target +=
                                                                    sizeof(struct ipfix_set_header);

                                                                while (processed < set_length) {
                                                                        apply_function_to_field
                                                                            (function,
                                                                             protocol,
                                                                             field,
                                                                             target
                                                                             +
                                                                             offset,
                                                                             target_len,
                                                                             header_pointer,
                                                                             header_len,
                                                                             packet, params);
                                                                        target += record_length;
                                                                        processed += record_length;
                                                                }
                                                        }
                                                } else  // IETF-specified
                                                {
                                                        uint16_t        processed = 0;
                                                        uint16_t        target_len = 0;
                                                        struct ipfix_ietf_field_specifier *anonfield
                                                            =
                                                            (struct ipfix_ietf_field_specifier *)
                                                            tmp_record->fields[t];
                                                        // Clear the first bit of the ID.
                                                        rid = anonfield->id;
                                                        rid &= ~(1 << 15);

                                                        if (rid == field) {
                                                                unsigned char  *target =
                                                                    (unsigned char *)ipfix->
                                                                    data[d]->header;
                                                                uint16_t        offset = 0;
                                                                uint16_t        set_length =
                                                                    ntohs(ipfix->data[d]->header->
                                                                          length);
                                                                uint16_t        record_length = 0;

                                                                for (i = 0; i < t; i++)
                                                                        if (((unsigned
                                                                              char)(*tmp_record->
                                                                                    fields[i] & (1
                                                                                                 <<
                                                                                                 15)))
                                                                            == 0) {
                                                                                offset +=
                                                                                    sizeof(struct
                                                                                           ipfix_vendor_field_specifier);
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_vendor_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i])->
                                                                                          length);
                                                                        } else {
                                                                                offset +=
                                                                                    sizeof(struct
                                                                                           ipfix_ietf_field_specifier);
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_ietf_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i])->
                                                                                          length);
                                                                        }
                                                                while (i < tmp_record->nfields)
                                                                        if (((unsigned
                                                                              char)(*tmp_record->
                                                                                    fields[i] & (1
                                                                                                 <<
                                                                                                 15)))
                                                                            == 0)
                                                                                record_length +=
                                                                                    ntohs(((struct
                                                                                            ipfix_vendor_field_specifier
                                                                                            *)
                                                                                           tmp_record->
                                                                                           fields
                                                                                           [i++])->
                                                                                          length);
                                                                        else
                                                                                record_length
                                                                                    +=
                                                                                    ntohs
                                                                                    (((struct
                                                                                       ipfix_ietf_field_specifier
                                                                                       *)
                                                                                      tmp_record->
                                                                                      fields[i++])->
                                                                                     length);
                                                                // XXX ALIGN RECORD_LENGTH ON 32 BIT BOUNDARY

                                                                target_len
                                                                    = ntohs(anonfield->length);
                                                                processed
                                                                    =
                                                                    sizeof(struct ipfix_set_header);
                                                                target +=
                                                                    sizeof(struct ipfix_set_header);

                                                                while (processed < set_length) {
                                                                        apply_function_to_field
                                                                            (function,
                                                                             protocol,
                                                                             field,
                                                                             target
                                                                             +
                                                                             offset,
                                                                             target_len,
                                                                             header_pointer,
                                                                             header_len,
                                                                             packet, params);
                                                                        target += record_length;
                                                                        processed += record_length;
                                                                }
                                                        }
                                                }
                                        }
                                } else if ((tmp_opts = flist_get(flow->ipfix_options, ipfix->data[d]->header->id)) != NULL) {   // Got an options template.
                                } else {        // Leave unchanged. Print some error message?
                                        ;
                                }
                        }
                }
                        break;
                }

                // Free associated structures.
        }
                break;

        case BINARY_PAYLOAD:
        {
                XORPayloadContent *ip = malloc(sizeof(XORPayloadContent));
                struct genericWgetURL *wgetURL = malloc(sizeof(struct genericWgetURL));
                stuttgartLink  *link = malloc(sizeof(stuttgartLink));
                wuerzburgLink  *link2 = malloc(sizeof(wuerzburgLink));
                konstanzLink   *link3 = malloc(sizeof(konstanzLink));

                if (!ip)
                        return;
                if (!wgetURL)
                        return;
                if (!link)
                        return;
                if (!link2)
                        return;
                if (!link3)
                        return;

                if (binaryGenericWgetDecode(packet, flow, wgetURL) == 0) {
                        switch (field) {
                        case URL_PROTOCOL:
                                field_pointer = wgetURL->protocol;
                                len = wgetURL->protocolLen;
                                break;
                        case URL_USER:
                                field_pointer = wgetURL->user;
                                len = wgetURL->userLen;
                                break;
                        case URL_PASS:
                                field_pointer = wgetURL->pass;
                                len = wgetURL->passLen;
                                break;
                        case URL_HOST:
                                field_pointer = wgetURL->host;
                                len = wgetURL->hostLen;
                                break;
                        case URL_PORT:
                                field_pointer = wgetURL->port;
                                len = wgetURL->portLen;
                                break;
                        case URL_PATH:
                                field_pointer = wgetURL->path;
                                len = wgetURL->pathLen;
                                break;
                        case URL_DIR:
                                field_pointer = wgetURL->dir;
                                len = wgetURL->dirLen;
                                break;
                        case URL_FILE:
                                field_pointer = wgetURL->file;
                                len = wgetURL->fileLen;
                                break;
                        default:
                                break;
                        }
                }
                if (binaryGenericXORDecode(packet, flow, ip) == 0) {
                        switch (field) {
                                /*case IP:
                                   break;
                                   case HOST:
                                   break; */
                        default:
                                break;
                        }
                }
                if (binaryStuttgartDecode(packet, flow, link) == 0) {
                        printf("offsets\n");
                }
                if (binaryWuerzburgDecode(packet, flow, link2) == 0) {
                        printf("connect back\n");
                }
                if (binaryKonstanzDecode(packet, flow, link3) == 0) {
                        printf("konstanza!\n");
                }

                if (ip)
                        free(ip);
                if (wgetURL)
                        free(wgetURL);
                if (link)
                        free(link);
                if (link2)
                        free(link2);
                if (link3)
                        free(link3);
        }
                break;

        default:
                break;
        }

        if (!field_pointer)     //a HTTP reply for example doesn't have URI
                return;

        //function-specific argument selection
        mapNode       **mapTable;
        int            *counter;

        switch (function) {
        case MAP:
                if (field == SRC_IP || field == DST_IP) {
                        if (((unsigned char)ip_count) == ((unsigned char)255))
                                ip_count += 2;  //do no use special addresses .0 and .255

                        mapTable = ipMappingTable;
                        counter = (int *)&ip_count;
                } else if (field == SRC_PORT || field == DST_PORT) {
                        mapTable = portsMappingTable;
                        counter = &ports_count;
                } else {
                        if (len == 4) {
                                mapTable = generalMapping32Table;
                                counter = &general32_count;
                        } else if (len == 2) {
                                mapTable = generalMapping16Table;
                                counter = &general16_count;
                        } else {
                                mapTable = generalMapping8Table;
                                counter = &general8_count;
                        }
                }

                map_field(field_pointer, len, mapTable, counter);
                //checkSwap(field_pointer,field);

                break;

        case BD_MAP:
                if (field == SRC_IP)    // || field == SRC_PORT
                {
                        if (((unsigned char)src_ip_count) == ((unsigned char)255))
                                src_ip_count += 2;      //do no use special addresses .0 and .255

                        mapTable = srcIpMappingTable;
                        counter = (int *)&src_ip_count;
                } else if (field == DST_IP)     // || field == DST_PORT
                {
                        if (((unsigned char)dst_ip_count) == ((unsigned char)255))
                                dst_ip_count += 2;      //do no use special addresses .0 and .255

                        mapTable = dstIpMappingTable;
                        counter = (int *)&dst_ip_count;
                } else {
                        fprintf(stderr,
                                "Bidirectional mapping doesn't work on fields other than SRC/DST IP.\n");
                        return;
                }

                map_field(field_pointer, len, mapTable, counter);
                break;
        case MAP_DISTRIBUTION:
                map_distribution(field_pointer, len,
                                 params->distribution_type, params->median,
                                 params->standard_deviation);
                //checkSwap(field_pointer,field);
                break;
        case PREFIX_PRESERVING:
                prefix_preserving_anonymize_field(field_pointer);
                break;
        case PREFIX_PRESERVING_MAP:
                hide_addr(field_pointer);
                break;
        case STRIP:
                //printf("++I will call STRIP and I will keep %d bytes\n",params->seed);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                strip(packet, header_pointer, header_len, params->seed, total_len, packet_end);
                break;
        case HASHED:
                //printf("I will call HASH for algorithm %d and padding %d\n",params->hash_algorithm,params->padding_behavior);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                int             donotreplace = 0;
                if (field >= CHECKSUM && field <= CODE)
                        donotreplace = 1;
                switch (params->hash_algorithm) {
                case SHA:
                        sha1_hash(field_pointer, len,
                                  params->padding_behavior, packet,
                                  total_len, packet_end, donotreplace);
                        break;
                case MD5:
                        md5_hash(field_pointer, len,
                                 params->padding_behavior, packet, total_len,
                                 packet_end, donotreplace);
                        break;
                case CRC32:
                        crc32_hash(field_pointer, len,
                                   params->padding_behavior, packet,
                                   total_len, packet_end, donotreplace);
                        break;
                case SHA_2:
                        sha256_hash(field_pointer, len,
                                    params->padding_behavior, packet,
                                    total_len, packet_end, donotreplace);
                        break;
                case DES:
                case TRIPLEDES:
                        des_hash(field_pointer, len,
                                 (unsigned char *)DES3_keys, params->padding_behavior, packet);
                        break;
                case AES:
                        aes_hash(field_pointer, len,
                                 (unsigned char *)AES_keys, 8 * sizeof(AES_keys), params->padding_behavior, packet);
                        break;
                default:
                        fprintf(stderr, "Fatal Error, unknown hash algorithm\n");
                        exit(0);
                }
                break;
        case PATTERN_FILL:
                //printf("I will call PATTERN_FILL with type %d and pattern: %s\n",params->pattern_type,params->pattern);
                switch (params->pattern_type) {
                case 0: //integers
                        pattern_fill_field(field_pointer, len,
                                           params->pattern_type, (void *)&params->seed);
                        break;
                case 1:
                        pattern_fill_field(field_pointer, len,
                                           params->pattern_type, (void *)params->pattern);
                        break;
                }
                checkSwap(field_pointer, field);
                break;
        case FILENAME_RANDOM:
                //printf("++I will call FILENAME_RANDOM (%p,%d)\n",field_pointer,len);
                filename_random_field(field_pointer, len);
                break;
        case RANDOM:
                //printf("++I will call RANDOM %u.%u.%u.%u\n",field_pointer[0],field_pointer[1],field_pointer[2],field_pointer[3]);
                random_field(field_pointer, len);
                break;
        case ZERO:
                memset(field_pointer, 0, len);
                break;
        case REPLACE:
                //printf("++I will call REPLACE with pattern: %s\n",params->pattern);
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                replace_field(field_pointer, len,
                              (unsigned char *)params->pattern,
                              strlen(params->pattern), packet, total_len, packet_end);
                break;
        case CHECKSUM_ADJUST:
                switch (protocol) {
                case IP:
                        packet->iph->ip_csum = calculate_ip_sum(packet);
                        if (packet->tcph) {     //pseudoheader uses some info from IP
                                packet->tcph->th_sum = calculate_tcp_sum(packet);
                        } else if (packet->udph) {
                                packet->udph->uh_chk = calculate_udp_sum(packet);
                        }
                        break;
                case TCP:
                        packet->tcph->th_sum = calculate_tcp_sum(packet);
                        break;
                case UDP:
                        packet->udph->uh_chk = calculate_udp_sum(packet);
                        break;
                case ICMP:
                        packet->icmph->csum = calculate_icmp_sum(packet);
                        break;
                case HTTP:
                case FTP:
                        if (packet->tcph) {     //pseudoheader uses some info from IP
                                packet->tcph->th_sum = calculate_tcp_sum(packet);
                        }
                        break;
                }
                break;
        case REGEXP:
                total_len = ntohs(packet->iph->ip_len);
                packet_end = ((unsigned char *)(packet->iph)) + total_len;
                reg_exp_substitute(field_pointer, len, params->regexp,
                                   params->replaceVector,
                                   params->num_of_matches, packet, total_len, packet_end);
                break;
        case VALUE_SHIFT:
                value_shift(field_pointer, len);
                break;
        default:
                break;
        }
/*
        for (i = 0; i < packet->num_of_upper_layer_protocols; i++) {
                free(packet->upper_layer_protocol_headers[i]);
        }
*/
}

anon_pkthdr_t  *last_header_seen = NULL;
anonpacket      decoded_packet;
extern int      client_size;

int anonymize_stream(struct anonflow *flow, struct anonymize_data *params, anon_pkthdr_t * pkt_head)
{
        struct pcap_pkthdr pkthdr;
        anon_pkthdr_t  *anon_head;

        anon_head = pkt_head;

        pkthdr.caplen = anon_head->caplen;
        pkthdr.len = anon_head->wlen;
        pkthdr.ts.tv_sec = anon_head->ts.tv_sec;
        pkthdr.ts.tv_usec = anon_head->ts.tv_usec;

        flow->decoded_packet = &decoded_packet;
        decode_packet(flow->link_type, flow->cap_length, &pkthdr,
                      flow->mod_pkt, flow->decoded_packet);
        flow->decoded_packet->dsize = flow->client_size;
        if (flow->decoded_packet->data == NULL) {       //decoder does not work well above 65536
                flow->decoded_packet->data =
                    flow->decoded_packet->pkt + (anon_head->caplen - flow->client_size);
        }

        last_header_seen = anon_head;
        anonymize_field(params->protocol, params->field, params->function,
                        flow->decoded_packet, params, flow);

        return 1;
}

int
anonymize_process(struct anonflow *flow, void *internal_data,
                  unsigned char *dev_pkt, anon_pkthdr_t * pkt_head)
{
        struct anonymize_data *params;
        struct pcap_pkthdr pkthdr;

        params = (struct anonymize_data *)internal_data;

        if (flow->client_headers != NULL) {     //if this is a cooked packet try to anonymize it
                return anonymize_stream(flow, params, pkt_head);
        }

        pkthdr.caplen = pkt_head->caplen;
        pkthdr.len = pkt_head->wlen;
        pkthdr.ts.tv_sec = pkt_head->ts.tv_sec;
        pkthdr.ts.tv_usec = pkt_head->ts.tv_usec;

        last_header_seen = pkt_head;

        if (flow->decoded_packet == NULL) {
                //   printf("WILL DECODE PACKET %d\n",flow->link_type);
                flow->decoded_packet = &decoded_packet;
                decode_packet(flow->link_type, flow->cap_length, &pkthdr,
                              (unsigned char *)dev_pkt, flow->decoded_packet);
        }

        anonymize_field(params->protocol, params->field, params->function,
                        flow->decoded_packet, params, flow);
        return 1;
}

struct finfo    anonymize_info = {
        "ANONYMIZE",
        "Basic anonymization function",
        anonymize_init,
        anonymize_process
};
