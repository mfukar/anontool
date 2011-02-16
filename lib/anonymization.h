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
#ifndef _ANONYMIZATION_H_
#define _ANONYMIZATION_H_

#include <sys/time.h>

#include "flist.h"
#include "anon_snort_decode.h"

#define ON                      1
#define OFF                     0

#define MAX_UPPER_PROTOCOLS     10
#define MAX_CONT                20

#define MAX_NUM_OF_SETS         1024
#define NONE                    0
#define TCPDUMP_TRACE           1
#define ETHERNET_NIC            2

// Bit twiddling stuff
#define setBit(a, n) a |= (1 << (n));
#define clearBit(b, n) b &= ~(1 << (n));
#define toggleBit(c, n) c ^= (1 << (n));
#define testBit(d, n) ((d) & (1 << (n)))

typedef struct {
        unsigned int            caplen;
        unsigned int            wlen;
        struct timeval          ts;
} anon_pkthdr_t;

struct orig_headers {
        void                   *data;
        struct orig_headers    *next;
};

struct headers_data {
        unsigned char          *header;
        int                     header_len;
        unsigned int            caplen;
        unsigned int            wlen;
        struct timeval          ts;
        void                   *decoded_pkt;
};


typedef struct {
        struct pcap_pkthdr         *pkth;           /* BPF data */
        unsigned char              *pkt;            /* base pointer to the raw packet data */

        Fddi_hdr                   *fddihdr;        /* FDDI support headers */
        Fddi_llc_saps              *fddisaps;
        Fddi_llc_sna               *fddisna;
        Fddi_llc_iparp             *fddiiparp;
        Fddi_llc_other             *fddiother;
        Trh_hdr                    *trh;            /* Token Ring support headers */
        Trh_llc                    *trhllc;
        Trh_mr                     *trhmr;
        SLLHdr                     *sllh;           /* Linux cooked sockets header */
        PflogHdr                   *pfh;            /* OpenBSD pflog interface header */
        EtherHdr                   *eh;             /* standard TCP/IP/Ethernet/ARP headers */
        VlanTagHdr                 *vh;
        EthLlc                     *ehllc;
        EthLlcOther                *ehllcother;
        WifiHdr                    *wifih;          /* wireless LAN header */
        EtherARP                   *ah;
        EtherEapol                 *eplh;           /* 802.1x EAPOL header */
        EAPHdr                     *eaph;
        unsigned char              *eaptype;
        EapolKey                   *eapolk;

        IPHdr                      *iph,
                                   *orig_iph;       /* and orig. headers for ICMP_*_UNREACH family */
        unsigned int                ip_options_len;
        unsigned char              *ip_options_data;

        IPv6Hdr                    *ipv6_hdr,
                                   *orig_ipv6_hdr;

        TCPHdr                     *tcph,
                                   *orig_tcph;
        unsigned int                tcp_options_len;
        unsigned char              *tcp_options_data;

        UDPHdr                     *udph,
                                   *orig_udph;
        ICMPHdr                    *icmph,
                                   *orig_icmph;

        echoext                    *ext;            /* ICMP echo extension struct */

        unsigned char              *data;           /* packet payload pointer */
        unsigned int                dsize;          /* packet payload size */

        unsigned char               frag_flag;      /* flag to indicate a fragmented packet */
        unsigned short int          frag_offset;    /* fragment offset number */
        unsigned char               mf,             /* more fragments flag */
                                    df,             /* don't fragment flag */
                                    rf;             /* IP reserved bit */

        unsigned short int          sp,             /* source port (TCP/UDP) */
                                    dp,             /* dest port (TCP/UDP) */
                                    orig_sp,        /* source port (TCP/UDP) of original datagram */
                                    orig_dp;        /* dest port (TCP/UDP) of original datagram */
        unsigned int                caplen;

        unsigned char               uri_count;      /* number of URIs in this packet */

        Options                     ip_options[40]; /* ip options decode structure */
        unsigned int                ip_option_count;/* number of options in this packet */
        unsigned char               ip_lastopt_bad; /* flag to indicate that option decoding was halted due to a bad option */
        Options                     tcp_options[40];/* tcp options decode struct */
        unsigned int                tcp_option_count;
        unsigned char               tcp_lastopt_bad;/* flag to indicate that option decoding was halted due to a bad option */

        unsigned char               csum_flags;     /* checksum flags */
        unsigned int                packet_flags;   /* special flags for the packet */

        void                       *upper_layer_protocol_headers[MAX_UPPER_PROTOCOLS];
        int                         upper_layer_names[MAX_UPPER_PROTOCOLS];
        int                         num_of_upper_layer_protocols;
} anonpacket;


struct anonflow {
        char                    modifies;

        /* Cooking specific fields */
        unsigned char          *mod_pkt,
                               *server_mod_pkt;
        anon_pkthdr_t           mod_pkt_head,
                                server_mod_pkt_head;
        flist_t                *client_headers,
                               *server_headers;
        unsigned int            client_size,
                                server_size;
        flist_t                *ret_client_headers,
                               *ret_server_headers;
        unsigned char          *ret_client_data,
                               *ret_server_data;
        /* end of cooking fields */

        anonpacket             *decoded_packet;
        int                     link_type,
                                cap_length;
        char                    uncook_ready;
        int                     output_type;
        char                   *output_filename;
        void                   *output_handler;
        struct function        *function_list;
        int                     cont_set;               /* continuation set */
        int                     give_output[MAX_CONT];  /* give output to other sets */
        void                   *output_info;

        /* AES / DES keys */
        /*
        unsigned char *AES_key;
        unsigned char *DES_key;
        */

        // For Netflow v9.
        flist_t                *nf9_templates,
                               *nf9_option_templates,
        // For IPFIX
                               *ipfix_templates,
                               *ipfix_options;
};

struct finfo {
        char                   *name;
        char                   *description;
        int     (*init)         (va_list vl,void *f,struct anonflow *flow);
        int     (*process)      (struct anonflow *flow,void *internal_data,unsigned char* dev_pkt,anon_pkthdr_t* pkt_head);
};

struct function {
        int                     fid;
        void                   *internal_data;
        struct finfo           *function_info;
        struct function        *next;
};

typedef enum {
        INTEGER,
        STR
} patternTypes;

typedef enum  {
        //ACCEPTED PROTOCOLS
        IP=1  ,
        TCP  ,
        UDP  ,
        ICMP ,
        HTTP ,
        FTP  ,
        ETHERNET ,
        NETFLOW_V5,
        NETFLOW_V9,
        IPFIX,
        RPC,
        BINARY_PAYLOAD,

        //ANONYMIZATION FUNCTIONS
        UNCHANGED         ,
        MAP               ,
        BD_MAP            ,
        MAP_DISTRIBUTION  ,
        STRIP             ,
        RANDOM            ,
        HASHED            ,
        PATTERN_FILL      ,
        ZERO              ,
        REPLACE           ,
        PREFIX_PRESERVING ,
        PREFIX_PRESERVING_MAP,
        CHECKSUM_ADJUST   ,
        FILENAME_RANDOM   ,
        VALUE_SHIFT       ,
        REGEXP            ,

        PAD_WITH_ZERO     ,
        STRIP_REST        ,

        //ACCEPTABLE HASH FUNCTIONS
        SHA              ,
        MD5              ,
        CRC32            ,
        SHA_2            ,
        TRIPLEDES        ,
        AES              ,
        DES              ,

        BASE_FIELD_DEFS  ,
        PAYLOAD          , //common to all protocols
        CHECKSUM         ,
        ETHER_TYPE       ,
        SRC_IP           ,
        DST_IP           ,
        TTL              ,
        TOS              ,
        ID               ,
        VERSION          ,
        OPTIONS          ,
        PACKET_LENGTH    ,
        IP_PROTO         ,
        IHL              ,
        FRAGMENT_OFFSET  ,
        SRC_PORT         ,
        DST_PORT         ,
        SEQUENCE_NUMBER  ,
        OFFSET_AND_RESERVED,
        ACK_NUMBER       ,
        FLAGS            ,
        URGENT_POINTER   ,
        WINDOW           ,
        TCP_OPTIONS      ,
        UDP_DATAGRAM_LENGTH,
        TYPE             ,
        CODE             ,

        BASE_HTTP_DEFS      , //the number of first definition for HTTP
        HTTP_VERSION        ,
        METHOD              ,
        URI                 ,
        USER_AGENT          ,
        ACCEPT              ,
        ACCEPT_CHARSET      ,
        ACCEPT_ENCODING     ,
        ACCEPT_LANGUAGE     ,
        ACCEPT_RANGES       ,
        AGE                 ,
        ALLOW               ,
        AUTHORIZATION       ,
        CACHE_CONTROL       ,
        CONNECTION_TYPE     ,
        CONTENT_TYPE        ,
        CONTENT_LENGTH      ,
        CONTENT_LOCATION    ,
        CONTENT_MD5         ,
        CONTENT_RANGE       ,
        COOKIE              ,
        ETAG                ,
        EXPECT              ,
        EXPIRES             ,
        FROM                ,
        HOST                ,
        IF_MATCH            ,
        IF_MODIFIED_SINCE   ,
        IF_NONE_MATCH       ,
        IF_RANGE            ,
        IF_UNMODIFIED_SINCE ,
        LAST_MODIFIED       ,
        MAX_FORWRDS         ,
        PRAGMA              ,
        PROXY_AUTHENTICATE  ,
        PROXY_AUTHORIZATION ,
        RANGE               ,
        REFERRER            ,
        RETRY_AFTER         ,
        SET_COOKIE          ,
        SERVER              ,
        TE                  ,
        TRAILER             ,
        TRANSFER_ENCODING   ,
        UPGRADE             ,
        VIA                 ,
        WARNING             ,
        WWW_AUTHENTICATE    ,
        X_POWERED_BY        ,
        RESPONSE_CODE       ,
        RESP_CODE_DESCR     ,
        VARY                ,
        DATE                ,
        CONTENT_ENCODING    ,
        KEEP_ALIVE          ,
        LOCATION            ,
        HTTP_PAYLOAD        ,/* for internal use */
        END_HTTP_DEFS       ,

        //FTP FIELDS
        BASE_FTP_DEFS       ,
        //XXX me must include responses
        //all responses have a code and an argument
        USER     , //has arg
        PASS     , //has arg
        ACCT     , //has arg
        FTP_TYPE , //has arg
        STRU     ,
        MODE     ,
        CWD      , //has arg
        PWD      , //no arg
        CDUP     , //no arg
        PASV     , //no arg
        RETR     , //has arg
        REST     ,
        PORT     ,
        LIST     , //no arg
        NLST     , //yes/no arg
        QUIT     , //no arg
        SYST     , //no arg
        STAT     ,
        HELP     ,
        NOOP     ,
        STOR     ,
        APPE     ,
        STOU     ,
        ALLO     ,
        MKD      , //has arg
        RMD      , //has arg
        DELE     , //has arg
        RNFR     ,
        RNTO     ,
        SITE     , //has arg
        FTP_RESPONSE_CODE,
        FTP_RESPONSE_ARG,
        END_FTP_DEFS,

        // NetFlow fields
        BASE_NETFLOW_V9_DEFS        ,
        NF9_VERSION                 ,
        NF9_COUNT                   ,
        NF9_UPTIME                  ,
        NF9_UNIXSECS                ,
        NF9_PACKAGESEQ              ,
        NF9_SOURCEID                ,

        /*
         * 0 for record that describes flow fields
         * 1 for template options
         * >255 for data records
         */
        NF9_FLOWSET_ID              ,
        NF9_LENGTH                  ,// TLV format

        // Template Flowset fields
        NF9_TEMPLATEID              ,
        NF9_FIELD_COUNT             ,
        // Field Types
        BASE_NETFLOW_V9_FIELDS  ,
        NF9_IN_BYTES                ,
        NF9_IN_PKTS                 ,
        NF9_FLOWS                   ,
        NF9_PROTOCOL                ,
        NF9_SRC_TOS                 ,
        NF9_TCP_FLAGS               ,
        NF9_L4_SRC_PORT             ,
        NF9_IPV4_SRC_ADDR           ,
        NF9_SRC_MASK                ,
        NF9_INPUT_SNMP              ,
        NF9_L4_DST_PORT             ,
        NF9_IPV4_DST_ADDR           ,
        NF9_DST_MASK                ,
        NF9_OUTPUT_SNMP             ,
        NF9_IPV4_NEXT_HOP           ,
        NF9_SRC_AS                  ,
        NF9_DST_AS                  ,
        NF9_BGP_IPV4_NEXT_HOP       ,
        NF9_MUL_DST_PKTS            ,
        NF9_MUL_DST_BYTES           ,
        NF9_LAST_SWITCHED           ,
        NF9_FIRST_SWITCHED          ,
        NF9_OUT_BYTES               ,
        NF9_OUT_PKTS                ,
        NF9_MIN_PKT_LENGTH          ,
        NF9_MAX_PKT_LENGTH          ,
        NF9_IPV6_SRC_ADDR           ,
        NF9_IPV6_DST_ADDR           ,
        NF9_IPV6_SRC_MASK           ,
        NF9_IPV6_DST_MASK           ,
        NF9_IPV6_FLOW_LABEL         ,
        NF9_ICMP_TYPE               ,
        NF9_MUL_IGMP_TYPE           ,
        NF9_SAMPLING_INTERVAL       ,
        NF9_SAMPLING_ALGORITHM      ,
        NF9_FLOW_ACTIVE_TIMEOUT     ,
        NF9_FLOW_INACTIVE_TIMEOUT   ,
        NF9_ENGINE_TYPE             ,
        NF9_ENGINE_ID               ,
        NF9_TOTAL_BYTES_EXP         ,
        NF9_TOTAL_PKTS_EXP          ,
        NF9_TOTAL_FLOWS_EXP         ,
        NF9_VENDOR_43               ,
        NF9_IPV4_SRC_PREFIX         ,
        NF9_IPV4_DST_PREFIX         ,
        NF9_MPLS_TOP_LABEL_TYPE     ,
        NF9_MPLS_TOP_LABEL_IP_ADDR  ,
        NF9_FLOW_SAMPLER_ID         ,
        NF9_FLOW_SAMPLER_MODE       ,
        NF9_FLOW_SAMPLER_RANDOM_INTERVAL,
        NF9_VENDOR_51               ,
        NF9_MIN_TTL                 ,
        NF9_MAX_TTL                 ,
        NF9_IPV4_IDENT              ,
        NF9_DST_TOS                 ,
        NF9_IN_SRC_MAC              ,
        NF9_OUT_DST_MAC             ,
        NF9_SRC_VLAN                ,
        NF9_DST_VLAN                ,
        NF9_IP_PROTOCOL_VERSION     ,
        NF9_DIRECTION               ,
        NF9_IPV6_NEXT_HOP           ,
        NF9_BGP_IPV6_NEXT_HOP       ,
        NF9_IPV6_OPTION_HEADERS     ,
        NF9_VENDOR_65               ,
        NF9_VENDOR_66               ,
        NF9_VENDOR_67               ,
        NF9_VENDOR_68               ,
        NF9_VENDOR_69               ,
        NF9_MPLS_LABEL_1            ,
        NF9_MPLS_LABEL_2            ,
        NF9_MPLS_LABEL_3            ,
        NF9_MPLS_LABEL_4            ,
        NF9_MPLS_LABEL_5            ,
        NF9_MPLS_LABEL_6            ,
        NF9_MPLS_LABEL_7            ,
        NF9_MPLS_LABEL_8            ,
        NF9_MPLS_LABEL_9            ,
        NF9_MPLS_LABEL_10           ,
        NF9_IN_DST_MAC              ,
        NF9_OUT_SRC_MAC             ,
        NF9_IF_NAME                 ,
        NF9_IF_DESC                 ,
        NF9_SAMPLER_NAME            ,
        NF9_IN_PERMANENT_BYTES      ,
        NF9_IN_PERMANENT_PKTS       ,
        NF9_VENDOR_87               ,
        NF9_FRAGMENT_OFFSET         ,
        NF9_FORWARDING_STATUS       ,
        END_NETFLOW_V9_FIELDS       ,
        // End of field types

        // Option Scope fields
        BASE_NETFLOW_V9_SCOPES      ,
        NF9_SCOPE_SYSTEM            ,
        NF9_SCOPE_INTERFACE         ,
        NF9_SCOPE_LINE_CARD         ,
        NF9_SCOPE_NETFLOW_CACHE     ,
        NF9_SCOPE_TEMPLATE          ,
        END_NETFLOW_V9_SCOPES       ,

        END_NETFLOW_V9_DEFS     ,

        BASE_NETFLOW_V5_DEFS    ,
        NF5_VERSION             ,
        NF5_FLOWCOUNT           ,
        NF5_UPTIME              ,
        NF5_UNIX_SECS           ,
        NF5_UNIX_NSECS          ,
        NF5_SEQUENCE            ,
        NF5_ENGINE_TYPE         ,
        NF5_ENGINE_ID           ,
        NF5_SRCADDR             ,
        NF5_DSTADDR             ,
        NF5_NEXTHOP             ,
        NF5_INPUT               ,
        NF5_OUTPUT              ,
        NF5_DPKTS               ,
        NF5_DOCTETS             ,
        NF5_FIRST               ,
        NF5_LAST                ,
        NF5_SRCPORT             ,
        NF5_DSTPORT             ,
        NF5_TCP_FLAGS           ,
        NF5_PROT                ,
        NF5_TOS                 ,
        NF5_SRC_AS              ,
        NF5_DST_AS              ,
        NF5_SRC_MASK            ,
        NF5_DST_MASK            ,
        END_NETFLOW_V5_DEFS     ,

        BASE_IPFIX_DEFS         ,
        // Message Header
        IPFIX_VERSION           ,
        IPFIX_MSG_LENGTH        ,
        IPFIX_EXPORT_TIME       ,
        IPFIX_SEQUENCE          ,
        IPFIX_OBSERV_ID         ,
        // Field
        IPFIX_INFOELEM_ID       ,
        IPFIX_FIELD_LENGTH      ,
        IPFIX_ENTERPRISE_NO     ,
        // Set Header
        IPFIX_SET_ID            ,
        IPFIX_SET_LENGTH        ,
        // Template Record Header
        IPFIX_TEMPLATE_ID       ,
        IPFIX_TEMPLATE_COUNT    ,
        // Option Template Header
        IPFIX_OPTION_HDR_ID     ,
        IPFIX_OPTION_HDR_COUNT  ,
        IPFIX_OPTION_HDR_SCOPE  ,

        BASE_IPFIX_FIELD_DEFS   ,
/* straight from http://www.ietf.org/internet-drafts/draft-ietf-ipfix-info-15.txt */
        IPFIX_octetDeltaCount,
        IPFIX_packetDeltaCount,
        IPFIX_reserved1,
        IPFIX_protocolIdentifier,
        IPFIX_ipClassOfService,
        IPFIX_tcpControlBits,
        IPFIX_sourceTransportPort,
        IPFIX_sourceIPv4Address,
        IPFIX_sourceIPv4PrefixLength,
        IPFIX_ingressInterface,
        IPFIX_destinationTransportPort,
        IPFIX_destinationIPv4Address,
        IPFIX_destinationIPv4PrefixLength,
        IPFIX_egressInterface,
        IPFIX_ipNextHopIPv4Address,
        IPFIX_bgpSourceAsNumber,
        IPFIX_bgpDestinationAsNumber,
        IPFIX_bgpNexthopIPv4Address,
        IPFIX_postMCastPacketDeltaCount,
        IPFIX_postMCastOctetDeltaCount,
        IPFIX_flowEndSysUpTime,
        IPFIX_flowStartSysUpTime,
        IPFIX_postOctetDeltaCount,
        IPFIX_postPacketDeltaCount,
        IPFIX_minimumIpTotalLength,
        IPFIX_maximumIpTotalLength,
        IPFIX_sourceIPv6Address,
        IPFIX_destinationIPv6Address,
        IPFIX_sourceIPv6PrefixLength,
        IPFIX_destinationIPv6PrefixLength,
        IPFIX_flowLabelIPv6,
        IPFIX_icmpTypeCodeIPv4,
        IPFIX_igmpType,
        IPFIX_reserved2,
        IPFIX_reserved3,
        IPFIX_flowActiveTimeout,
        IPFIX_flowIdleTimeout,
        IPFIX_reserved4,
        IPFIX_reserved5,
        IPFIX_exportedOctetTotalCount,
        IPFIX_exportedMessageTotalCount,
        IPFIX_exportedFlowRecordTotalCount,
        IPFIX_reserved6,
        IPFIX_sourceIPv4Prefix,
        IPFIX_destinationIPv4Prefix,
        IPFIX_mplsTopLabelType,
        IPFIX_mplsTopLabelIPv4Address,
        IPFIX_reserved7,
        IPFIX_reserved8,
        IPFIX_reserved9,
        IPFIX_reserved10,
        IPFIX_minimumTTL,
        IPFIX_maximumTTL,
        IPFIX_fragmentIdentification,
        IPFIX_postIpClassOfService,
        IPFIX_sourceMacAddress,
        IPFIX_postDestinationMacAddress,
        IPFIX_vlanId,
        IPFIX_postVlanId,
        IPFIX_ipVersion,
        IPFIX_flowDirection,
        IPFIX_ipNextHopIPv6Address,
        IPFIX_bgpNexthopIPv6Address,
        IPFIX_ipv6ExtensionHeaders,
        IPFIX_reserved11,
        IPFIX_reserved12,
        IPFIX_reserved13,
        IPFIX_reserved14,
        IPFIX_reserved15,
        IPFIX_mplsTopLabelStackSection,
        IPFIX_mplsLabelStackSection2,
        IPFIX_mplsLabelStackSection3,
        IPFIX_mplsLabelStackSection4,
        IPFIX_mplsLabelStackSection5,
        IPFIX_mplsLabelStackSection6,
        IPFIX_mplsLabelStackSection7,
        IPFIX_mplsLabelStackSection8,
        IPFIX_mplsLabelStackSection9,
        IPFIX_mplsLabelStackSection10,
        IPFIX_destinationMacAddress,
        IPFIX_postSourceMacAddress,
        IPFIX_reserved16,
        IPFIX_reserved17,
        IPFIX_reserved18,
        IPFIX_octetTotalCount,
        IPFIX_packetTotalCount,
        IPFIX_reserved19,
        IPFIX_fragmentOffset,
        IPFIX_reserved20,
        IPFIX_mplsVpnRouteDistinguisher,
        /*
         * Vendor-defined field identifiers must be declared in different enumerations
         * with the correct ID #s.
         */
        END_IPFIX_FIELD_DEFS    ,
        END_IPFIX_DEFS          ,

        BASE_URL_DEFS           ,
        URL_PROTOCOL            ,
        URL_USER                ,
        URL_PASS                ,
        URL_HOST                ,
        URL_PORT                ,
        URL_PATH                ,
        URL_DIR                 ,
        URL_FILE                ,
        END_URL_DEFS            ,

        END_FIELD_DEFS,

        GAUSSIAN,
        UNIFORM
} anonymizationDefs;

#define MAX_PIPELINE 50

struct httpheader {
        int http_type;
        unsigned char *pointers_to_value[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
        unsigned char *pointers_to_header[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
        unsigned int value_length[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
        unsigned int header_length[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
        int pipeline_depth;
};

struct ftpheader {
        int ftp_type;
        unsigned char *pointers_to_value[END_FTP_DEFS-BASE_FTP_DEFS+1];
        unsigned char *pointers_to_header[END_FTP_DEFS-BASE_FTP_DEFS+1];
        unsigned int value_length[END_FTP_DEFS-BASE_FTP_DEFS+1];
        unsigned int header_length[END_FTP_DEFS-BASE_FTP_DEFS+1];
};

/*
 * Netflow v5
 */
struct NF5_HEADER
{
        uint16_t version, flowcount;
        uint32_t uptime, unix_secs, unix_nsecs, sequence;
        uint8_t  engine_type, engine_id;
        uint16_t reserved;
};

struct NF5_RECORD
{
        uint32_t srcaddr, dstaddr, nexthop;
        uint16_t input, output;
        uint32_t dPkts, dOctets, First, Last;
        uint16_t srcport, dstport;
        uint8_t  pad1, tcp_flags, prot, tos;
        uint16_t src_as, dst_as;
        uint8_t  src_mask, dst_mask;
        uint16_t pad2;
};

struct NETFLOW_V5
{
        struct NF5_HEADER *h;
        struct NF5_RECORD **r;

        uint8_t field_lengths[END_NETFLOW_V5_DEFS - BASE_NETFLOW_V5_DEFS + 1];
};


/*
 * Below the definition of a v9 NetFlow.
 */
struct NF9_HEADER
{
        uint16_t version, count;
        uint32_t uptime, seconds, sequence, source_id;
};

struct NF9_FLOWSET_COMMON
{
        uint16_t flowset_id, length;
};

struct NF9_TEMPLATE_RECORD
{
        uint16_t field_type, field_length;
};

struct NF9_TEMPLATE_INFO
{
        uint16_t template_id, field_count;
};

struct NF9_TEMPLATE
{
        struct NF9_TEMPLATE_INFO *inf;
        struct NF9_TEMPLATE_RECORD **records;
};

struct NF9_TEMPLATE_FLOWSET
{
        struct NF9_FLOWSET_COMMON *c;

        uint16_t ntemps;
        struct NF9_TEMPLATE **templates;
};

struct NF9_DATA_FLOWSET
{
        struct NF9_FLOWSET_COMMON *c;

        unsigned char *field_values;
};

struct NF9_OPTIONS_INFO
{
        uint16_t template_id, option_scope_len, option_len;
};

struct NF9_OPTIONS_TEMPLATE
{
        struct NF9_FLOWSET_COMMON *c;
        struct NF9_OPTIONS_INFO *inf;

        uint16_t nscopes;
        struct NF9_TEMPLATE_RECORD **scope_fields;
        uint16_t nopts;
        struct NF9_TEMPLATE_RECORD **option_fields;
};

struct NETFLOW_V9
{
        struct NF9_HEADER *header;

        uint16_t ntemplates;
        struct NF9_TEMPLATE_FLOWSET **template_flowsets;

        uint16_t ndata;
        struct NF9_DATA_FLOWSET **data_flowsets;

        uint16_t noptions;
        struct NF9_OPTIONS_TEMPLATE **option_templates;
};

#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256

/* IPFIX message format definition */

struct ipfix_header
{
        uint16_t version, length;               // version 0x000a (NetFlow version + 1), length in octets
        uint32_t export_time, sequence, domain; // seconds since epoch, counter of data records, ID
};

struct ipfix_set_header
{
        uint16_t id, length;                    // 2-Template, 3-Option Template, >255-Data set
};

struct ipfix_template_header
{
        uint16_t id, count;                     // id > 255
};

struct ipfix_ietf_field_specifier
{
        uint16_t id;                            // 1st bit defines type: IETF, 15 bits for ID
        uint16_t length;
};

struct ipfix_vendor_field_specifier
{
        uint16_t id;                            // 1st bit defines type: Vendor
        uint16_t length;
        uint32_t enterprise;                    // Enterprise ID
};

struct ipfix_option_header
{
        uint16_t id, field_count, scope_count;
};

struct ipfix_option_template_set
{
        struct ipfix_set_header *setheader;
        struct ipfix_option_header *header;

        uint16_t nfields;
        void **fields;
};

struct ipfix_template_record
{
        struct ipfix_template_header *header;

        uint16_t nfields;
        unsigned char **fields;

        uint16_t nietf;         // number of IETF fields
        struct ipfix_ietf_field_specifier *ietf_fields;
        uint16_t nvendor;       // number of vendor-spec fields
        struct ipfix_vendor_field_specifier *vendor_fields;
};

struct ipfix_template_set
{
        struct ipfix_set_header *header;

        uint16_t nrecords;
        struct ipfix_template_record **records;
};

struct ipfix_data_set
{
        struct ipfix_set_header *header;

        uint16_t nfields;
        unsigned char **fields;
};

struct IPFIX
{
        struct ipfix_header *header;

        uint16_t ntemplates, ndata, noptions;

        struct ipfix_template_set **templates;
        struct ipfix_option_template_set **options;
        struct ipfix_data_set **data;
};

#include <pcre.h>
/*
 * Generic XOR
 */
typedef struct {
        char           *PCRE;
        char           *Name;
        uint16_t        options;
} XORPcreHelper;

typedef struct {
        pcre           *PCRE;
        char           *Name;
        uint16_t        options;
} XORPcreContext;

#define XF_NONE                 0x00001
#define XF_SIZE_INVERT          0x00002
#define XF_INVERSE_ORDER        0x00004

// The structure returneth for decoded payloads
typedef struct {
        char            keysize;
        char            key;
        uint32_t        longkey;
        unsigned char  *IP;
        uint16_t        IPLen;
        unsigned char  *host;
        uint16_t        hostLen;
} XORPayloadContent;

/*
 * Generic wget
 */
struct genericWgetURL {
        uint32_t        startOffset,
                        endOffset;
        char           *decodedurl;
        unsigned char  *protocol;
        uint16_t        protocolLen;
        unsigned char  *user;
        uint16_t        userLen;
        unsigned char  *pass;
        uint16_t        passLen;
        unsigned char  *host;
        uint16_t        hostLen;
        unsigned char  *port;
        uint16_t        portLen;
        unsigned char  *path;
        uint16_t        pathLen;
        unsigned char  *dir;
        uint16_t        dirLen;
        unsigned char  *file;
        uint16_t        fileLen;
};

/*
 * stuttgart-shellcode link
 */
typedef struct {
        char           *host,          // 32bits
                       *port,          // 16bits
                       *authkey;       // 32bits
} stuttgartLink;

/*
 * wuerzburg-shellcode link
 */
typedef struct {
        char           *ip,
                       *port;
} wuerzburgLink;

/*
 * konstanz-decoder link
 */
typedef struct {
        unsigned char  *IP;
        uint16_t        IPLen;
        unsigned char  *host;
        uint16_t        hostLen;
} konstanzLink;

/* for mapping functions */

typedef struct _mapNode {
        unsigned int    value;
        unsigned int    mapped_value;
        struct _mapNode *next;
} mapNode;

#define MAPPING_ENTRIES         1024

/* ANONYMIZATION PROTOTYPES */
int decode_packet               (int datalink,int snaplen,struct pcap_pkthdr *pkthdr,unsigned char *p,anonpacket *pkt);
int http_decode                 (anonpacket *p, struct httpheader *h);
int ftp_decode                  (anonpacket *p, struct ftpheader *h);
int netflow_v9_decode           (anonpacket *, struct NETFLOW_V9 *, struct anonflow *);
int netflow_v5_decode           (anonpacket *, struct NETFLOW_V5 *);
int ipfix_decode                (anonpacket *, struct IPFIX *, struct anonflow *);
//int rpc_decode                (anonpacket *, struct rpcheader *);

int binaryGenericXORInit        (void);
int binaryGenericWgetInit       (void);
int binaryStuttgartInit         (void);
int binaryWuerzburgInit         (void);
int binaryGenericXORDecode      (anonpacket *, struct anonflow *, XORPayloadContent *);
int binaryGenericWgetDecode     (anonpacket *, struct anonflow *, struct genericWgetURL *);
int binaryStuttgartDecode       (anonpacket *, struct anonflow *, stuttgartLink *);
int binaryWuerzburgDecode       (anonpacket *, struct anonflow *, wuerzburgLink *);
int binaryKonstanzDecode        (anonpacket *, struct anonflow *, konstanzLink *);

typedef void (*grinder_t)       (anonpacket *, struct pcap_pkthdr *, u_char *,int snaplen);

extern void           PrintIPPkt(FILE * fp, int type, anonpacket * p);
extern unsigned short calculate_ip_sum(anonpacket *p);
extern unsigned short calculate_tcp_sum(anonpacket *p);
extern unsigned short calculate_udp_sum(anonpacket *p);
extern unsigned short calculate_icmp_sum(anonpacket *p);

extern void PrintPacket(FILE *fp, anonpacket *p,int datalink);
extern void gen_table();

extern void pattern_fill_field(unsigned char *field, int len, int pattern_type, void *pattern);
extern void prefix_preserving_anonymize_field(unsigned char *raw_addr);
extern void hide_addr(unsigned char *raw_addr);
extern void random_field(unsigned char *field, int len);
extern void filename_random_field(unsigned char *p, int len);
extern void map_distribution(unsigned char *field, short len, int distribution_type, int arg1, int arg2);
extern int  aes_hash(unsigned char *field, int len, unsigned char *key, unsigned int keylen, int padding_behavior, anonpacket *p);
extern int  des_hash(unsigned char *field, int len, unsigned char *key, int padding_behavior, anonpacket *p);
extern void map_field(unsigned char *field, short len, mapNode **map_table,int *count);
extern int  replace_field(unsigned char *field,  int len, unsigned char * pattern, int pattern_len,anonpacket *p, int total_len, unsigned char *packet_end);
extern int  md5_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);

extern void strip (anonpacket *p, unsigned char *field, int len,int keep_bytes, int total_len, unsigned char* packet_end);
extern int  sha1_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
extern int  sha256_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
extern int  crc32_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
extern int  reg_exp_substitute(unsigned char *field, int len, char *regular_expression, char **replacement_vector, int num_of_matches,anonpacket *p,int total_len,unsigned char *packet_end);
extern int  value_shift(unsigned char *, unsigned int);


#define MFUNCT_INVALID_ARGUMENT_1 -2
#define MFUNCT_INVALID_ARGUMENT_2 -3
#define MFUNCT_INVALID_ARGUMENT_3 -4
#define MFUNCT_INVALID_ARGUMENT_4 -5

#define NIC_PKTCAP_LEN 1540

struct sourceinfo {
        int                     type;

        int     (*open_input)   (char *name);
        void    (*init_input)   (struct anonflow *flow);
        void *  (*init_output)  (char *name, int linktype);
        void    (*dump_packet)  (void *handler,unsigned char *packet,anon_pkthdr_t *header);
        void    (*process_packets)();

};


/* API prototypes */
int     create_set      ();
int     set_source      (int type, char *filename);
int     add_function    (int sd, char *funcName, ...);
void    start_processing();
int     set_output      (int sd, int type, char *filename);


#endif
