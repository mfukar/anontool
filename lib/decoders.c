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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pcap.h>
#include <ctype.h>

#include "anonymization.h"

char           *http_keywords[] = {
    "HTTP Version",
    "Method",
    "URI",
    "User-Agent",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Ranges",
    "Age",
    "Allow",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Content-Type",
    "Content-Length",
    "Content-Location",
    "Content-MD5",
    "Content-Range",
    "Cookie",
    "Etag",
    "Expect",
    "Expires",
    "From",
    "Host",
    "If-match",
    "If-modified-since",
    "If-none-match",
    "If-range",
    "If-unmodified-since",
    "Last-modified",
    "Max-forwards",
    "Pragma",
    "Proxy-authenticate",
    "Proxy-authorization",
    "Range",
    "Referer",
    "Retry-after",
    "Set-Cookie",
    "Server",
    "Te",
    "Trailer",
    "Transfer-encoding",
    "Upgrade",
    "Via",
    "Warning",
    "WWW-authenticate",
    "X-powered-by",
    "Response code",
    "Code description",
    "Vary",
    "Date",
    "Content-Encoding",
    "Keep-Alive",
    "Location",
    "Payload"
};

char           *ftp_keywords[] =
{
    "USER",
    "PASS",
    "ACCT",
    "TYPE",
    "STRU",
    "MODE",
    "CWD",
    "PWD",
    "CDUP",
    "PASV",
    "RETR",
    "REST",
    "PORT",
    "LIST",
    "NLST",
    "QUIT",
    "SYST",
    "STAT",
    "HELP",
    "NOOP",
    "STOR",
    "APPE",
    "STOU",
    "ALLO",
    "MKD",
    "RMD",
    "DELE",
    "RNFR",
    "RNTO",
    "SITE",
    "FTP_RESPONSE_CODE",
    "FTP_RESPONSE_ARG"
};


extern grinder_t SetPktProcessor(int datalink);

int decode_packet(int datalink, int snaplen, struct pcap_pkthdr *pkthdr, unsigned char *raw_bytes,
          anonpacket * pkt)
{
    grinder_t       decoder;

    decoder = SetPktProcessor(datalink);
    (*decoder) (pkt, pkthdr, raw_bytes, snaplen);
    return 1;
}

typedef enum _http_type {
    HTTP_REQUEST,
    HTTP_RESPONSE,
    HTTP_NOTIFICATION,
    HTTP_OTHERS
} http_type_t;

typedef enum {
    PROTO_HTTP,     /* just HTTP */
    PROTO_SSDP,     /* Simple Service Discovery Protocol */
    PROTO_DAAP      /* Digital Audio Access Protocol */
} http_proto_t;

unsigned char  *mystrnstr(unsigned char *s, int len, char *p)
{
    unsigned char   backup;
    char           *result;

    backup = s[len];
    s[len] = '\0';

    result = strstr((char *)s, p);
    s[len] = backup;

    return (unsigned char *)result;

}

unsigned char  *mystrnchr(unsigned char *start, unsigned char *end, char c)
{
    while (start < end) {
        if ((*start) == c)
            return start;
        start++;
    }
    return NULL;
}

void print_substring(unsigned char *start, unsigned char *end)
{
    while (start < end) {
        putchar(*start);
        start++;
    }
}

int match_http_keyword(char *keyword)
{
    int             i;
    //printf("KEYWORD:%s\n",keyword);
    for (i = 0; i < (END_HTTP_DEFS - BASE_HTTP_DEFS - 1); i++) {
        if (strcasecmp(http_keywords[i], keyword) == 0)
            return i;
    }

    return -1;

}

void print_string(unsigned char *s, unsigned int len)
{
    unsigned int    i = 0;
    for (i = 0; i < len; i++) {
        if (isprint(s[i]))
            putchar(s[i]);
        else
            putchar('.');
    }
}

void printHTTPHeader(struct httpheader *h)
{
    int             i = 0, j;
    printf("=================\n");
    printf("HTTP type: %d\n", h->http_type);
    for (j = 0; j < h->pipeline_depth; j++) {
        printf("Header: %d \n", j);
        for (i = 0; i < (END_HTTP_DEFS - BASE_HTTP_DEFS - 1); i++) {
            if (h->pointers_to_value[j][i]) {
                printf("%s: ", http_keywords[i]);
                print_string(h->pointers_to_value[j][i], h->value_length[j][i]);
                printf("<<<\n");
            }
        }
    }
}

// XXX : This is some dangerous fuck.
int myatoi(unsigned char *field, int len)
{
    unsigned char   buffer[100];
    while (*field == ' ') {
        field++;
        len--;
    }
    memcpy(buffer, field, len);
    buffer[len] = '\0';
    return atoi((char *)buffer);
}

int pipeline_http_decode(unsigned char *payload, unsigned int dsize, struct httpheader *h,
             unsigned int offset, int level)
{
    unsigned char  *start_of_headers, *end_of_headers;
    unsigned char  *end_of_first_line, *tmp;
    unsigned char  *data = payload + offset;
    int             noffset;

    if (offset >= dsize) {  //recursion finished
        return 0;
    }

    if ((end_of_headers = mystrnstr(data, dsize - offset, "\r\n\r\n")) == NULL) {
        return -1;
    }

    memset(h->pointers_to_value[level], 0,
           (END_HTTP_DEFS - BASE_HTTP_DEFS + 1) * sizeof(unsigned char *));
    memset(h->pointers_to_header[level], 0,
           (END_HTTP_DEFS - BASE_HTTP_DEFS + 1) * sizeof(unsigned char *));
    memset(h->value_length[level], 0,
           (END_HTTP_DEFS - BASE_HTTP_DEFS + 1) * sizeof(unsigned short));
    memset(h->header_length[level], 0,
           (END_HTTP_DEFS - BASE_HTTP_DEFS + 1) * sizeof(unsigned short));
    h->pipeline_depth = level + 1;

    end_of_first_line = mystrnstr(data, dsize - offset, "\r\n");

    if (strncmp((char *)data, "GET ", 4) == 0 || strncmp((char *)data, "POST ", 5) == 0
        || strncmp((char *)data, "HEAD ", 5) == 0 || strncmp((char *)data, "PUT ", 4) == 0) {
        //printf(">>>>We have an HTTP request\n");
        unsigned char  *space_finder;

        space_finder = data;
        while (*space_finder != ' ' && space_finder < end_of_first_line)
            space_finder++;

        if (space_finder == end_of_first_line) {
            fprintf(stderr, "Invalid first line of HTTP request\n");
            return -1;
        }
        h->http_type = HTTP_REQUEST;

        h->pointers_to_value[level][METHOD - BASE_HTTP_DEFS - 1] = data;
        h->value_length[level][METHOD - BASE_HTTP_DEFS - 1] = (space_finder - data);

        while (*space_finder == ' ')
            space_finder++; //skip whitespaces

        unsigned char  *uri_start = space_finder;

        while (*space_finder != ' ' && space_finder < end_of_first_line)
            space_finder++;

        if (space_finder == end_of_first_line) {
            fprintf(stderr, "Invalid first line of HTTP request. Protocol missing!\n");
            return -1;
        }

        h->pointers_to_value[level][URI - BASE_HTTP_DEFS - 1] =
            h->pointers_to_header[level][URI - BASE_HTTP_DEFS - 1] = uri_start;
        h->value_length[level][URI - BASE_HTTP_DEFS - 1] =
            h->header_length[level][URI - BASE_HTTP_DEFS - 1] = space_finder - uri_start;

        h->pointers_to_value[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
            h->pointers_to_header[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
            space_finder + 1;
        h->value_length[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
            h->header_length[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
            (end_of_first_line - space_finder - 1);

    } else if (strncmp((char *)data, "HTTP/", 5) == 0) {
        tmp = data + 5;
        if (*tmp >= '0' && *tmp <= '9' && *(tmp + 1) == '.' && *(tmp + 2) >= '0'
            && *(tmp + 2) <= '9' && *(tmp + 3) == ' ') {
            //printf(">>> We have a HTTP response\n");
            h->http_type = HTTP_RESPONSE;
            h->pointers_to_value[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
                h->pointers_to_header[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] = data;
            h->value_length[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] =
                h->header_length[level][HTTP_VERSION - BASE_HTTP_DEFS - 1] = 8;
            tmp += 4;   //go after "HTTP/1.1 "

            unsigned char  *space_finder;
            space_finder = tmp;
            //try to find space between response code and response description
            while (*space_finder != ' ' && space_finder < end_of_first_line)
                space_finder++;
            if (space_finder == end_of_first_line) {
                //fprintf(stderr,"Not appropriate HTTP protocol\n");
                return -1;
            }

            h->pointers_to_value[level][RESPONSE_CODE - BASE_HTTP_DEFS - 1] =
                h->pointers_to_header[level][RESPONSE_CODE - BASE_HTTP_DEFS - 1] = tmp;
            h->value_length[level][RESPONSE_CODE - BASE_HTTP_DEFS - 1] =
                h->header_length[level][RESPONSE_CODE - BASE_HTTP_DEFS - 1] =
                (space_finder - tmp);

            //printf("RESPONSE CODE: "); print_substring(tmp,space_finder); printf("\n");

            h->pointers_to_value[level][RESP_CODE_DESCR - BASE_HTTP_DEFS - 1] =
                h->pointers_to_header[level][RESP_CODE_DESCR - BASE_HTTP_DEFS - 1] =
                space_finder + 1;
            h->value_length[level][RESP_CODE_DESCR - BASE_HTTP_DEFS - 1] =
                h->header_length[level][RESP_CODE_DESCR - BASE_HTTP_DEFS - 1] =
                end_of_first_line - space_finder - 1;

            //printf("RESP_CODE_DESCR: "); print_substring(space_finder+1,end_of_first_line); printf("\n");

        } else {
            //fprintf(stderr,"Invalid first line of HTTP response\n");
            return -1;
        }
    } else {
        //fprintf(stderr,">>>> First line does not match to HTTP protocol %d\n",offset);
        return -1;
    }

    start_of_headers = end_of_first_line + 2;
    if (start_of_headers > end_of_headers)
        return 0;

    while (start_of_headers < end_of_headers) {
        unsigned char  *end_of_line;
        end_of_line =
            mystrnstr(start_of_headers, (dsize - (start_of_headers - data)) - offset,
                  "\r\n");
        //printf("+++++++++ "); print_substring(start_of_headers,end_of_line); printf("\n");
        unsigned char  *semicolon_pos;
        semicolon_pos = mystrnchr(start_of_headers, end_of_line, ':');
        if (semicolon_pos == NULL) {
            //fprintf(stderr,"Invalid HTTP protocol. No semicolon\n");
            return -1;
        }

        *semicolon_pos = '\0';  //set the semicolon as \0 so as keyword be a normal string
        int             match = match_http_keyword((char *)start_of_headers);
        *semicolon_pos = ':';   //restore the semicolon
        if (match == -1) {
            //fprintf(stderr,"Unknown header ::: "); print_substring(start_of_headers,semicolon_pos); printf("\n");
        } else {
            h->pointers_to_value[level][match] = semicolon_pos + 2;
            h->value_length[level][match] = end_of_line - semicolon_pos - 2;
        }

        h->pointers_to_header[level][match] = start_of_headers;
        h->header_length[level][match] = end_of_line - start_of_headers + 2;    //+2 for the \r\n

        start_of_headers = end_of_line + 2;

    }

    if (h->pointers_to_header[level][CONTENT_LENGTH - BASE_HTTP_DEFS - 1] != NULL) {
        int             content_length;
        content_length =
            myatoi(h->pointers_to_value[level][CONTENT_LENGTH - BASE_HTTP_DEFS - 1],
               h->value_length[level][CONTENT_LENGTH - BASE_HTTP_DEFS - 1]);
        //set the payload
        h->pointers_to_value[level][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1] = end_of_headers + 4;
        h->value_length[level][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1] = content_length;
        //fprintf(stderr,"Payload size: %d %d %d\n",content_length,dsize,offset);
        if ((end_of_headers + 4 + content_length) > (payload + dsize)) {
            h->value_length[level][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1] =
                (payload + dsize) - end_of_headers - 4;
        }

        noffset = offset + (end_of_headers - data) + 4 + content_length;
        //printf("Response with content length!!\n");
    } else {
        //if we do not have content length in response then the HTTP payload is up to the end of
        //TCP session. In reassembled packets we won't see pipeline.
        if (h->http_type == HTTP_RESPONSE) {
            noffset = dsize;

            if ((unsigned int)((end_of_headers - data) + 4) < dsize) {
                h->pointers_to_value[level][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1] =
                    end_of_headers + 4;
                h->value_length[level][HTTP_PAYLOAD - BASE_HTTP_DEFS - 1] =
                    (payload + dsize) - end_of_headers - 4;
            }

            return 0;
        }

        noffset = offset + (end_of_headers - data) + 4;
    }
    return pipeline_http_decode(payload, dsize, h, noffset, level + 1);
}

int http_decode(anonpacket * p, struct httpheader *h)
{
    unsigned char  *data = p->data;
    unsigned int    dsize = p->dsize;

    if (h == NULL)
        return -1;

    if (p->tcph == NULL) {
        return -1;
    }
    //comment out if we want to parse HTTP on non-standard ports
    if (ntohs(p->tcph->th_dport) != 80 && ntohs(p->tcph->th_sport) != 80) {
        return -1;
    }

    if (p->data == NULL || p->dsize < 10) {
        return -1;
    }

    h->pipeline_depth = 0;
    return pipeline_http_decode(data, dsize, h, 0, 0);
}

int match_ftp_headers(char *keyword)
{
    int             i;
    for (i = 0; i < (END_FTP_DEFS - BASE_FTP_DEFS - 1); i++) {
        if (strcasecmp(ftp_keywords[i], keyword) == 0)
            return i;
    }

    return -1;

}

void printFTPHeader(struct ftpheader *h)
{
    int             i;
    printf("+========================+\n");
    for (i = 0; i < END_FTP_DEFS - BASE_FTP_DEFS - 1; i++) {
        if (h->pointers_to_value[i]) {
            printf("%s: ", ftp_keywords[i]);
            print_string(h->pointers_to_value[i], h->value_length[i]);
            printf("<<<\n");
        } else if (h->pointers_to_header[i]) {
            print_string(h->pointers_to_header[i], h->header_length[i]);
            printf("<<<\n");
        }
    }
}

int ftp_decode(anonpacket * p, struct ftpheader *h)
{
    unsigned char  *end_of_headers, *end_of_command;

    if (h == NULL)
        return -1;

    memset(h->pointers_to_value, 0,
           (END_FTP_DEFS - BASE_FTP_DEFS + 1) * sizeof(unsigned char *));
    memset(h->pointers_to_header, 0,
           (END_FTP_DEFS - BASE_FTP_DEFS + 1) * sizeof(unsigned char *));
    memset(h->value_length, 0, (END_FTP_DEFS - BASE_FTP_DEFS + 1) * sizeof(unsigned short));
    memset(h->header_length, 0, (END_FTP_DEFS - BASE_FTP_DEFS + 1) * sizeof(unsigned short));

    if (p->tcph == NULL) {
        return -1;
    }
    //comment out if we want to parse HTTP on non-standard ports
    if (ntohs(p->tcph->th_dport) != 21 && ntohs(p->tcph->th_sport) != 21) {
        return -1;
    }

    if (p->data == NULL || p->dsize < 3) {
        return -1;
    }

    if ((end_of_headers = mystrnstr(p->data, p->dsize, "\r\n")) == NULL) {
        printf("Not valid FTP protocol\n");
        return -1;
    }

    if (ntohs(p->tcph->th_dport) == 21) {   //ftp request
        char            backup;
        end_of_command = p->data;
        while (*end_of_command != ' ' && end_of_command < end_of_headers)
            end_of_command++;

        backup = *end_of_command;
        *end_of_command = '\0';
        int             match = match_ftp_headers((char *)p->data);
        *end_of_command = backup;
        if (match == -1) {
            printf("Unknown header ::: %s\n", p->data);
            return -1;
        } else {
            //printf("FOund keyword::: %s\n",ftp_keywords[match]);
            h->pointers_to_header[match] = p->data;
            h->header_length[match] = (end_of_headers - (p->data)) + 2; //+2 for the \r\n

            switch (match + BASE_FTP_DEFS + 1) {
            case USER:
            case PASS:
            case ACCT:
            case FTP_TYPE:
            case CWD:
            case RETR:
            case MKD:
            case RMD:
            case DELE:
            case SITE:
                if (*end_of_command != ' ') {
                    printf("Missing argument on FTP request!!!!\n");
                    return -1;
                }
                //printf("Request argument:: "); print_substring(end_of_command+1,end_of_headers); printf("\n");
                h->pointers_to_value[match] = end_of_command + 1;
                h->value_length[match] = end_of_headers - end_of_command - 1;
                break;
            case NLST:
            case LIST:
                if (*end_of_command == ' ') {
                    //printf("Request argument:: "); print_substring(end_of_command+1,end_of_headers); printf("\n");
                    h->pointers_to_value[match] = end_of_command + 1;
                    h->value_length[match] =
                        end_of_headers - end_of_command - 1;
                }
                break;
            default:
                break;
            }
        }
        printFTPHeader(h);

    } else {
        end_of_command = p->data;
        while (*end_of_command != ' ' && end_of_command < end_of_headers) {
            end_of_command++;
        }
        if (*end_of_command != ' ') {
            printf("Invalid FTP response\n");
            return -1;
        }

        h->pointers_to_header[FTP_RESPONSE_CODE - BASE_FTP_DEFS - 1] = p->data;
        h->header_length[FTP_RESPONSE_CODE - BASE_FTP_DEFS - 1] = end_of_headers - p->data;

        h->pointers_to_value[FTP_RESPONSE_CODE - BASE_FTP_DEFS - 1] = p->data;
        h->value_length[FTP_RESPONSE_CODE - BASE_FTP_DEFS - 1] = end_of_command - p->data;

        h->pointers_to_value[FTP_RESPONSE_ARG - BASE_FTP_DEFS - 1] = end_of_command + 1;
        h->value_length[FTP_RESPONSE_ARG - BASE_FTP_DEFS - 1] =
            end_of_headers - end_of_command - 1;

        //printFTPHeader(h);
    }
    return (1);
}

/*
 * Netflow v5 decoder.
 * Mar 9 2006
 * mfukar
 */
int netflow_v5_decode(anonpacket * p, struct NETFLOW_V5 *netflow)
{
    unsigned char  *payload = NULL;
    uint16_t        nrec = 0;
    int             i = 0;

    if (!netflow)
        return (-1);
    if (!(p->udph))
        return (-1);
    if (p->data == NULL || p->dsize < sizeof(struct NF5_HEADER))
        return (-1);

    payload = p->data;

    // Header
    netflow->h = (struct NF5_HEADER *)payload;
    payload += sizeof(struct NF5_HEADER);

    nrec = ntohs(netflow->h->flowcount);
    netflow->r = malloc(nrec * sizeof(struct NF5_RECORD));
    // Records
    for (i = 0; i < nrec; i++) {
        netflow->r[i] = (struct NF5_RECORD *)payload;

        payload += sizeof(struct NF5_RECORD);
        if (((uint16_t) (payload - (unsigned char *)netflow->h)) > p->dsize) {
            free(netflow->r);
            return (-1);
        }
    }

    return (1);
}

/*
 * Decodes a NetFlow v9 packet.
 * mfukar
 * Jan 12 2006
 */
int netflow_v9_decode(anonpacket * p, struct NETFLOW_V9 *netflow, struct anonflow *flow)
{
    int             i = 0;
    unsigned char  *payload = NULL;
    int             flowsets = 0;

    uint16_t        flowset_length = 0;

    uint16_t        int16 = 0;

    struct NF9_TEMPLATE_FLOWSET *tmp_template_flowset = NULL;

    struct NF9_OPTIONS_TEMPLATE *tmp_options_template = NULL;

    if (!netflow)
        return (-1);

    // Expecting a UDP datagram.
    if (!(p->udph))
        return (-1);
    // We are at least expecting a header.
    if (p->data == NULL || p->dsize < 20)
        return (-1);

    // Initialisations.
    memset(netflow, 0, sizeof(struct NETFLOW_V9));

    payload = p->data;

    netflow->header = (struct NF9_HEADER *)payload;
    payload += sizeof(struct NF9_HEADER);

    // Now get the flowsets.
    for (flowsets = ntohs(netflow->header->count); flowsets >= 0; flowsets--) {
        /*
         * In most cases (ie. all), the header count field doesn't report
         * the correct number of flowsets.
         * This ugly piece of code will make sure we don't see any
         * "additional" flowsets that in fact don't exist.
         */
        if (((uint16_t) (payload - p->data)) >= p->dsize)
            return (1);

        //Switch on flowset's ID.
        int16 = ntohs(*((unsigned short *)payload));

        if (int16 == 0) { // Template flowset
            struct NF9_TEMPLATE *template_cache = NULL;
            // Allocate memory for the new flowset.
            netflow->template_flowsets =
                realloc(netflow->template_flowsets,
                    (++netflow->ntemplates) *
                    sizeof(struct NF9_TEMPLATE_FLOWSET *));
            netflow->template_flowsets[netflow->ntemplates - 1] =
                malloc(sizeof(struct NF9_TEMPLATE_FLOWSET));
            netflow->template_flowsets[netflow->ntemplates - 1]->c =
                (struct NF9_FLOWSET_COMMON *)payload;

            tmp_template_flowset = netflow->template_flowsets[netflow->ntemplates - 1];
            tmp_template_flowset->ntemps = 0;
            tmp_template_flowset->templates = 0;

            payload += sizeof(struct NF9_FLOWSET_COMMON);

            flowset_length = ntohs(tmp_template_flowset->c->length);
            int16 = sizeof(struct NF9_FLOWSET_COMMON);

            while (int16 + sizeof(uint16_t) < flowset_length) {
                template_cache = malloc(sizeof(struct NF9_TEMPLATE));
                tmp_template_flowset->templates =
                    realloc(tmp_template_flowset->templates,
                        (++tmp_template_flowset->ntemps) *
                        sizeof(struct NF9_TEMPLATE *));
                tmp_template_flowset->templates[tmp_template_flowset->ntemps - 1] =
                    malloc(sizeof(struct NF9_TEMPLATE));
                tmp_template_flowset->templates[tmp_template_flowset->ntemps -
                                1]->inf =
                    (struct NF9_TEMPLATE_INFO *)payload;
                payload += 2 * sizeof(uint16_t);
                int16 += 2 * sizeof(uint16_t);

                tmp_template_flowset->templates[tmp_template_flowset->ntemps -
                                1]->records =
                    malloc(ntohs
                       (tmp_template_flowset->
                        templates[tmp_template_flowset->ntemps -
                              1]->inf->field_count) *
                       sizeof(struct NF9_TEMPLATE_RECORD *));

                for (i = 0;
                     i <
                     ntohs(tmp_template_flowset->
                       templates[tmp_template_flowset->ntemps -
                             1]->inf->field_count); i++) {
                    tmp_template_flowset->templates[tmp_template_flowset->
                                    ntemps - 1]->records[i] =
                        (struct NF9_TEMPLATE_RECORD *)payload;
                    payload += sizeof(struct NF9_TEMPLATE_RECORD);
                }

                int16 +=
                    ntohs(tmp_template_flowset->
                      templates[tmp_template_flowset->ntemps -
                            1]->inf->field_count) *
                    sizeof(struct NF9_TEMPLATE_RECORD);

                template_cache->inf = malloc(sizeof(struct NF9_TEMPLATE_INFO));
                template_cache->inf->template_id =
                    ntohs(tmp_template_flowset->
                      templates[tmp_template_flowset->ntemps -
                            1]->inf->template_id);
                template_cache->inf->field_count =
                    ntohs(tmp_template_flowset->
                      templates[tmp_template_flowset->ntemps -
                            1]->inf->field_count);
                template_cache->records =
                    malloc(template_cache->inf->field_count *
                       sizeof(struct NF9_TEMPLATE_RECORD *));

                for (i = 0; i < template_cache->inf->field_count; i++) {
                    template_cache->records[i] =
                        malloc(sizeof(struct NF9_TEMPLATE_RECORD));
                    template_cache->records[i]->field_type =
                        ntohs(tmp_template_flowset->
                          templates[tmp_template_flowset->ntemps -
                                1]->records[i]->field_type);
                    template_cache->records[i]->field_length =
                        ntohs(tmp_template_flowset->
                          templates[tmp_template_flowset->ntemps -
                                1]->records[i]->field_length);
                }
                /*
                 * If a template with the same ID already exists,
                 * replace it with this one.
                 */
                struct NF9_TEMPLATE *tmp =
                    flist_remove(flow->nf9_templates,
                         template_cache->inf->template_id,
                         FLIST_LEAVE_DATA);
                if (tmp != NULL) {
                    for (i = 0; i < tmp->inf->field_count; i++) {
                        free(tmp->records[i]);
                    }
                    free(tmp->records);
                    free(tmp->inf);
                    free(tmp);
                }

                flist_append(flow->nf9_templates, template_cache->inf->template_id,
                         template_cache);
            }

            if (int16 != flowset_length)
                payload += sizeof(uint16_t);
        } else if (int16 == 1) { // This is an option template flowset.
            struct NF9_OPTIONS_TEMPLATE *options = NULL;
            // Allocate memory for the new flowset.
            netflow->option_templates = realloc(netflow->option_templates,
                                ++(netflow->noptions) *
                                sizeof(struct NF9_OPTIONS_TEMPLATE *));

            netflow->option_templates[netflow->noptions - 1] =
                malloc(sizeof(struct NF9_OPTIONS_TEMPLATE));
            netflow->option_templates[netflow->noptions - 1]->c =
                (struct NF9_FLOWSET_COMMON *)payload;
            payload += sizeof(struct NF9_FLOWSET_COMMON);

            tmp_options_template = netflow->option_templates[netflow->noptions - 1];
            tmp_options_template->inf = malloc(sizeof(struct NF9_OPTIONS_INFO));
            tmp_options_template->inf = (struct NF9_OPTIONS_INFO *)payload;
            payload += 3 * sizeof(uint16_t);

            tmp_options_template->nscopes =
                tmp_options_template->inf->option_scope_len /
                sizeof(struct NF9_TEMPLATE_RECORD);
            tmp_options_template->nopts =
                tmp_options_template->inf->option_len /
                sizeof(struct NF9_TEMPLATE_RECORD);

            // Grab the scope fields.
            tmp_options_template->scope_fields =
                malloc(tmp_options_template->nscopes *
                   sizeof(struct NF9_TEMPLATE_RECORD *));
            for (i = 0; i < tmp_options_template->nscopes; i++) {
                tmp_options_template->scope_fields[i] =
                    (struct NF9_TEMPLATE_RECORD *)payload;
                payload += sizeof(struct NF9_TEMPLATE_RECORD);
            }

            // ..and the option fields.
            tmp_options_template->option_fields =
                malloc(tmp_options_template->nopts *
                   sizeof(struct NF9_TEMPLATE_RECORD *));
            for (i = 0; i < tmp_options_template->nopts; i++) {
                tmp_options_template->option_fields[i] =
                    (struct NF9_TEMPLATE_RECORD *)payload;
                payload += sizeof(struct NF9_TEMPLATE_RECORD);
            }

            int16 = sizeof(struct NF9_FLOWSET_COMMON)
                + 3 * sizeof(uint16_t)
                + tmp_options_template->inf->option_scope_len
                + tmp_options_template->inf->option_len;
            if (int16 != flowset_length)
                payload += sizeof(uint16_t);

            //  Insert the options template flowset in the list.
            options->c = malloc(sizeof(struct NF9_FLOWSET_COMMON));
            options->c->flowset_id = ntohs(tmp_options_template->c->flowset_id);
            options->c->length = ntohs(tmp_options_template->c->length);

            options->inf = malloc(sizeof(struct NF9_OPTIONS_INFO));
            options->inf->template_id = tmp_options_template->inf->template_id;
            options->inf->option_scope_len =
                tmp_options_template->inf->option_scope_len;
            options->inf->option_len = tmp_options_template->inf->option_len;

            options->scope_fields = malloc(tmp_options_template->inf->option_scope_len);
            for (i = 0; i < tmp_options_template->nscopes; i++) {
                options->scope_fields[i]->field_type =
                    ntohs(tmp_options_template->scope_fields[i]->field_type);
                options->scope_fields[i]->field_length =
                    ntohs(tmp_options_template->scope_fields[i]->field_length);
            }
            options->option_fields = malloc(tmp_options_template->inf->option_len);
            for (i = 0; i < tmp_options_template->nopts; i++) {
                options->option_fields[i]->field_type =
                    ntohs(tmp_options_template->option_fields[i]->field_type);
                options->option_fields[i]->field_length =
                    ntohs(tmp_options_template->option_fields[i]->field_length);
            }
            flist_append(flow->nf9_option_templates, options->inf->template_id,
                     options);
        } else { // This is a data flowset.
            netflow->data_flowsets = realloc(netflow->data_flowsets,
                             ++(netflow->ndata) *
                             sizeof(struct NF9_DATA_FLOWSET *));
            netflow->data_flowsets[netflow->ndata - 1] =
                malloc(sizeof(struct NF9_DATA_FLOWSET));
            netflow->data_flowsets[netflow->ndata - 1]->c =
                (struct NF9_FLOWSET_COMMON *)payload;

            netflow->data_flowsets[netflow->ndata - 1]->field_values =
                payload + sizeof(struct NF9_FLOWSET_COMMON);
            payload += ntohs(netflow->data_flowsets[netflow->ndata - 1]->c->length);
        }
    }
    return (1);
}

int ipfix_decode(anonpacket * p, struct IPFIX *ipfix, struct anonflow *flow)
{
    uint16_t        i = 0, j = 0, set_length = 0;
    unsigned char  *payload = NULL;

    struct ipfix_template_set *tmp_template = NULL;
    struct ipfix_template_record *tmp_record = NULL;

    if (!ipfix)
        return (-1);
    if (!(p->iph))
        return (-1);
    if (p->data == NULL || p->dsize < sizeof(struct ipfix_header))
        return (-1);

    if (!(p->udph) && !(p->tcph))
        return (-1);

    memset(ipfix, 0, sizeof(struct IPFIX));
    payload = (unsigned char *)p->data;

    ipfix->header = (struct ipfix_header *)payload;
    payload += sizeof(struct ipfix_header);

    if (ntohs(ipfix->header->length) > p->dsize)
        return (-1);    // XXX could IPFIX span multiple datagrams?

    while ((uint16_t) (payload - p->data) < p->dsize) {
        i = ntohs(*(uint16_t *) payload);

        if (i == 2) {
                /* template set */
            ipfix->templates =
                realloc(ipfix->templates,
                    (++ipfix->ntemplates) * sizeof(struct ipfix_template_set *));
            ipfix->templates[ipfix->ntemplates - 1] =
                malloc(sizeof(struct ipfix_template_set));
            ipfix->templates[ipfix->ntemplates - 1]->header =
                (struct ipfix_set_header *)payload;

            i = sizeof(struct ipfix_set_header);
            payload += i;

            tmp_template = ipfix->templates[ipfix->ntemplates - 1];
            tmp_template->nrecords = 0;
            tmp_template->records = NULL;

            set_length = ntohs(tmp_template->header->length);

            while (i < set_length) {
                if (*(uint16_t *) payload == 0) { // Padding!
                    payload =
                        (unsigned char *)tmp_template->header +
                        ntohs(tmp_template->header->length);
                    break;
                }

                tmp_template->records =
                    realloc(tmp_template->records,
                        (++tmp_template->nrecords) *
                        sizeof(struct ipfix_template_record *));
                tmp_template->records[tmp_template->nrecords - 1] =
                    malloc(sizeof(struct ipfix_template_record));
                tmp_template->records[tmp_template->nrecords - 1]->header =
                    malloc(sizeof(struct ipfix_template_header));
                tmp_template->records[tmp_template->nrecords - 1]->header->id =
                    ntohs(((struct ipfix_template_header *)payload)->id);
                tmp_template->records[tmp_template->nrecords - 1]->header->count =
                    ntohs(((struct ipfix_template_header *)payload)->count);

                i += sizeof(struct ipfix_template_header);
                payload += sizeof(struct ipfix_template_header);

                tmp_record = tmp_template->records[tmp_template->nrecords - 1];
                tmp_record->nvendor = tmp_record->nietf = 0;
                tmp_record->ietf_fields = NULL;
                tmp_record->vendor_fields = NULL;
                tmp_record->nfields = ntohs(tmp_record->header->count);
                tmp_record->fields =
                    malloc(tmp_record->nfields * sizeof(unsigned char *));

                for (j = 0; j < tmp_record->nfields; j++) {
                    tmp_record->fields[j] = payload;
                    if (testBit(*payload, 7)) {
                        tmp_record->nvendor++;
                        tmp_record->vendor_fields =
                            realloc(tmp_record->vendor_fields,
                                tmp_record->nvendor *
                                sizeof(struct
                                   ipfix_vendor_field_specifier));
                        tmp_record->vendor_fields[tmp_record->nvendor -
                                      1].id =
                            ntohs(*(uint16_t *) payload);
                        payload += sizeof(uint16_t);
                        tmp_record->vendor_fields[tmp_record->nvendor -
                                      1].length =
                            ntohs(*(uint16_t *) payload);
                        payload += sizeof(uint16_t);
                        tmp_record->vendor_fields[tmp_record->nvendor -
                                      1].enterprise =
                            ntohl(*(uint32_t *) payload);
                        payload += sizeof(uint32_t);
                        i += sizeof(struct ipfix_vendor_field_specifier);
                    } else {
                        tmp_record->nietf++;
                        tmp_record->ietf_fields =
                            realloc(tmp_record->ietf_fields,
                                tmp_record->nietf *
                                sizeof(struct
                                   ipfix_ietf_field_specifier));
                        tmp_record->ietf_fields[tmp_record->nietf - 1].id =
                            ntohs(*(uint16_t *) payload);
                        payload += sizeof(uint16_t);
                        tmp_record->ietf_fields[tmp_record->nietf -
                                    1].length =
                            ntohs(*(uint16_t *) payload);
                        payload += sizeof(uint16_t);
                        i += sizeof(struct ipfix_ietf_field_specifier);
                    }
                }
            }

            // Check against template records with the same ID and replace/insert.
            struct ipfix_template_record *tmp = NULL;
            for (j = 0; j < tmp_template->nrecords; j++) {
                if ((tmp =
                     flist_remove(flow->ipfix_templates,
                          tmp_template->records[j]->header->id,
                          FLIST_LEAVE_DATA)) != NULL) {
                    // free it.
                }
                // Insert the new template record.
                flist_append(flow->ipfix_templates,
                         tmp_template->records[j]->header->id,
                         tmp_template->records[j]);
            }
        } else if (i == 3) {// Option Template set
        } else if (i >= 4 && i <= 255) { // reserved for future use
            payload += sizeof(uint16_t);
            payload += ntohs(*(uint16_t *) payload);
            continue;
        } else if (i > 256) { // Data set
            ipfix->data =
                realloc(ipfix->data,
                    ++(ipfix->ndata) * sizeof(struct ipfix_data_set *));
            ipfix->data[ipfix->ndata - 1] = malloc(sizeof(struct ipfix_data_set));
            ipfix->data[ipfix->ndata - 1]->header = (struct ipfix_set_header *)payload;
            ipfix->data[ipfix->ndata - 1]->nfields = 0;
            payload += sizeof(struct ipfix_set_header);

            i = sizeof(struct ipfix_set_header);
            // If you try debugging this, good luck.
            while (i < ntohs(ipfix->data[ipfix->ndata - 1]->header->length)) {
                if (*(uint16_t *) payload == 0) { // Padding!
                    payload =
                        (unsigned char *)ipfix->data[ipfix->ndata - 1]->header +
                        ntohs(ipfix->data[ipfix->ndata - 1]->header->length);
                    break;
                }

                ipfix->data[ipfix->ndata - 1]->fields =
                    realloc(ipfix->data[ipfix->ndata - 1]->fields,
                        ++(ipfix->data[ipfix->ndata - 1]->nfields) *
                        sizeof(unsigned char *));
                ipfix->data[ipfix->ndata -
                        1]->fields[ipfix->data[ipfix->ndata - 1]->nfields - 1] =
                    payload;

                payload +=
                    ((unsigned char)(*payload & (1 << 8))) ? sizeof(struct
                                            ipfix_vendor_field_specifier)
                    : sizeof(struct ipfix_ietf_field_specifier);
                i += ((unsigned char)(*payload & (1 << 8))) ? sizeof(struct
                                             ipfix_vendor_field_specifier)
                    : sizeof(struct ipfix_ietf_field_specifier);
            }
        } else
            return (-1);
    }
    return (0);
}

#define IP_HLEN(iph)    ((iph)->ip_verhl & 0x0f)
