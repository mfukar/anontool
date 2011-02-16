#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "anonymization.h"

void usage(char *en)
{
	printf("Usage: Anonymize netflows\n");
	printf("%s [-i -f -a -t -d -c -z -p -h] output\n", en);
	printf("\t-i Open interface as input (INTERFACE)\n");
	printf("\t-f Open file as input (FILE)\n");
	printf("\t-a ANONYMIZE IP addresses in Netflows (PREFIX, MAP (IPv4 only), ZERO)\n");
	printf("\t-t ANONYMIZE TCP ports in Netflows (MAP, ZERO)\n");
	printf("\t-v ANONYMIZE Incoming byte count in Netflows (delta)\n");
	printf("\t-c Fix checksums\n");
	printf("\t-z Zero TCP flags\n");
	printf("\t-p Print anonymized packets\n");
	printf
	    ("\t--FIELD FUNCTION This kind of argument allows to anonymized any desired FIELD using any available FUNCTION\n");
	printf("\t Check /docs/API.txt for a detailed list of available fields & functions\n");
	printf("\t-h Print this help message\n");
	printf("\n\tWARNING: -i or -f MUST precede every other argument switch.\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int             sd = 0, opt, print_pkt = 0, fix_cks = 0, status;

	static char    *opstring = "czhpa:v:d:t:i:f:";
	int             opt_index;
	static struct option long_options[] = {
		{"NF9_VERSION", 1, 0, NF9_VERSION,},
		{"NF9_COUNT", 1, 0, NF9_COUNT,},
		{"NF9_UPTIME", 1, 0, NF9_UPTIME,},
		{"NF9_UNIXSECS", 1, 0, NF9_UNIXSECS,},
		{"NF9_PACKAGESEQ", 1, 0, NF9_PACKAGESEQ,},
		{"NF9_SOURCEID", 1, 0, NF9_SOURCEID,},
		{"NF9_FLOWSET_ID", 1, 0, NF9_FLOWSET_ID,},
		{"NF9_LENGTH", 1, 0, NF9_LENGTH,},
		{"NF9_TEMPLATEID", 1, 0, NF9_TEMPLATEID,},
		{"NF9_FIELD_COUNT", 1, 0, NF9_FIELD_COUNT,},
		{"NF9_IN_BYTES", 1, 0, NF9_IN_BYTES,},
		{"NF9_IN_PKTS", 1, 0, NF9_IN_PKTS,},
		{"NF9_FLOWS", 1, 0, NF9_FLOWS,},
		{"NF9_PROTOCOL", 1, 0, NF9_PROTOCOL,},
		{"NF9_SRC_TOS", 1, 0, NF9_SRC_TOS,},
		{"NF9_TCP_FLAGS", 1, 0, NF9_TCP_FLAGS,},
		{"NF9_L4_SRC_PORT", 1, 0, NF9_L4_SRC_PORT,},
		{"NF9_IPV4_SRC_ADDR", 1, 0, NF9_IPV4_SRC_ADDR,},
		{"NF9_SRC_MASK", 1, 0, NF9_SRC_MASK,},
		{"NF9_INPUT_SNMP", 1, 0, NF9_INPUT_SNMP,},
		{"NF9_L4_DST_PORT", 1, 0, NF9_L4_DST_PORT,},
		{"NF9_IPV4_DST_ADDR", 1, 0, NF9_IPV4_DST_ADDR,},
		{"NF9_DST_MASK", 1, 0, NF9_DST_MASK,},
		{"NF9_OUTPUT_SNMP", 1, 0, NF9_OUTPUT_SNMP,},
		{"NF9_IPV4_NEXT_HOP", 1, 0, NF9_IPV4_NEXT_HOP,},
		{"NF9_SRC_AS", 1, 0, NF9_SRC_AS,},
		{"NF9_DST_AS", 1, 0, NF9_DST_AS,},
		{"NF9_BGP_IPV4_NEXT_HOP", 1, 0, NF9_BGP_IPV4_NEXT_HOP,},
		{"NF9_MUL_DST_PKTS", 1, 0, NF9_MUL_DST_PKTS,},
		{"NF9_MUL_DST_BYTES", 1, 0, NF9_MUL_DST_BYTES,},
		{"NF9_LAST_SWITCHED", 1, 0, NF9_LAST_SWITCHED,},
		{"NF9_FIRST_SWITCHED", 1, 0, NF9_FIRST_SWITCHED,},
		{"NF9_OUT_BYTES", 1, 0, NF9_OUT_BYTES,},
		{"NF9_OUT_PKTS", 1, 0, NF9_OUT_PKTS,},
		{"NF9_MIN_PKT_LENGTH", 1, 0, NF9_MIN_PKT_LENGTH,},
		{"NF9_MAX_PKT_LENGTH", 1, 0, NF9_MAX_PKT_LENGTH,},
		{"NF9_IPV6_SRC_ADDR", 1, 0, NF9_IPV6_SRC_ADDR,},
		{"NF9_IPV6_DST_ADDR", 1, 0, NF9_IPV6_DST_ADDR,},
		{"NF9_IPV6_SRC_MASK", 1, 0, NF9_IPV6_SRC_MASK,},
		{"NF9_IPV6_DST_MASK", 1, 0, NF9_IPV6_DST_MASK,},
		{"NF9_IPV6_FLOW_LABEL", 1, 0, NF9_IPV6_FLOW_LABEL,},
		{"NF9_ICMP_TYPE", 1, 0, NF9_ICMP_TYPE,},
		{"NF9_MUL_IGMP_TYPE", 1, 0, NF9_MUL_IGMP_TYPE,},
		{"NF9_SAMPLING_INTERVAL", 1, 0, NF9_SAMPLING_INTERVAL,},
		{"NF9_SAMPLING_ALGORITHM", 1, 0, NF9_SAMPLING_ALGORITHM,},
		{"NF9_FLOW_ACTIVE_TIMEOUT", 1, 0, NF9_FLOW_ACTIVE_TIMEOUT,},
		{"NF9_FLOW_INACTIVE_TIMEOUT", 1, 0, NF9_FLOW_INACTIVE_TIMEOUT,},
		{"NF9_ENGINE_TYPE", 1, 0, NF9_ENGINE_TYPE,},
		{"NF9_ENGINE_ID", 1, 0, NF9_ENGINE_ID,},
		{"NF9_TOTAL_BYTES_EXP", 1, 0, NF9_TOTAL_BYTES_EXP,},
		{"NF9_TOTAL_PKTS_EXP", 1, 0, NF9_TOTAL_PKTS_EXP,},
		{"NF9_TOTAL_FLOWS_EXP", 1, 0, NF9_TOTAL_FLOWS_EXP,},
		{"NF9_VENDOR_43", 1, 0, NF9_VENDOR_43,},
		{"NF9_IPV4_SRC_PREFIX", 1, 0, NF9_IPV4_SRC_PREFIX,},
		{"NF9_IPV4_DST_PREFIX", 1, 0, NF9_IPV4_DST_PREFIX,},
		{"NF9_MPLS_TOP_LABEL_TYPE", 1, 0, NF9_MPLS_TOP_LABEL_TYPE,},
		{"NF9_MPLS_TOP_LABEL_IP_ADDR", 1, 0, NF9_MPLS_TOP_LABEL_IP_ADDR,},
		{"NF9_FLOW_SAMPLER_ID", 1, 0, NF9_FLOW_SAMPLER_ID,},
		{"NF9_FLOW_SAMPLER_MODE", 1, 0, NF9_FLOW_SAMPLER_MODE,},
		{"NF9_FLOW_SAMPLER_RANDOM_INTERVAL", 1, 0, NF9_FLOW_SAMPLER_RANDOM_INTERVAL,},
		{"NF9_VENDOR_51", 1, 0, NF9_VENDOR_51,},
		{"NF9_MIN_TTL", 1, 0, NF9_MIN_TTL,},
		{"NF9_MAX_TTL", 1, 0, NF9_MAX_TTL,},
		{"NF9_IPV4_IDENT", 1, 0, NF9_IPV4_IDENT,},
		{"NF9_DST_TOS", 1, 0, NF9_DST_TOS,},
		{"NF9_IN_SRC_MAC", 1, 0, NF9_IN_SRC_MAC,},
		{"NF9_OUT_DST_MAC", 1, 0, NF9_OUT_DST_MAC,},
		{"NF9_SRC_VLAN", 1, 0, NF9_SRC_VLAN,},
		{"NF9_DST_VLAN", 1, 0, NF9_DST_VLAN,},
		{"NF9_IP_PROTOCOL_VERSION", 1, 0, NF9_IP_PROTOCOL_VERSION,},
		{"NF9_DIRECTION", 1, 0, NF9_DIRECTION,},
		{"NF9_IPV6_NEXT_HOP", 1, 0, NF9_IPV6_NEXT_HOP,},
		{"NF9_BGP_IPV6_NEXT_HOP", 1, 0, NF9_BGP_IPV6_NEXT_HOP,},
		{"NF9_IPV6_OPTION_HEADERS", 1, 0, NF9_IPV6_OPTION_HEADERS,},
		{"NF9_VENDOR_65", 1, 0, NF9_VENDOR_65,},
		{"NF9_VENDOR_66", 1, 0, NF9_VENDOR_66,},
		{"NF9_VENDOR_67", 1, 0, NF9_VENDOR_67,},
		{"NF9_VENDOR_68", 1, 0, NF9_VENDOR_68,},
		{"NF9_VENDOR_69", 1, 0, NF9_VENDOR_69,},
		{"NF9_MPLS_LABEL_1", 1, 0, NF9_MPLS_LABEL_1,},
		{"NF9_MPLS_LABEL_2", 1, 0, NF9_MPLS_LABEL_2,},
		{"NF9_MPLS_LABEL_3", 1, 0, NF9_MPLS_LABEL_3,},
		{"NF9_MPLS_LABEL_4", 1, 0, NF9_MPLS_LABEL_4,},
		{"NF9_MPLS_LABEL_5", 1, 0, NF9_MPLS_LABEL_5,},
		{"NF9_MPLS_LABEL_6", 1, 0, NF9_MPLS_LABEL_6,},
		{"NF9_MPLS_LABEL_7", 1, 0, NF9_MPLS_LABEL_7,},
		{"NF9_MPLS_LABEL_8", 1, 0, NF9_MPLS_LABEL_8,},
		{"NF9_MPLS_LABEL_9", 1, 0, NF9_MPLS_LABEL_9,},
		{"NF9_MPLS_LABEL_10", 1, 0, NF9_MPLS_LABEL_10,},
		{"NF9_IN_DST_MAC", 1, 0, NF9_IN_DST_MAC,},
		{"NF9_OUT_SRC_MAC", 1, 0, NF9_OUT_SRC_MAC,},
		{"NF9_IF_NAME", 1, 0, NF9_IF_NAME,},
		{"NF9_IF_DESC", 1, 0, NF9_IF_DESC,},
		{"NF9_SAMPLER_NAME", 1, 0, NF9_SAMPLER_NAME,},
		{"NF9_IN_PERMANENT_BYTES", 1, 0, NF9_IN_PERMANENT_BYTES,},
		{"NF9_IN_PERMANENT_PKTS", 1, 0, NF9_IN_PERMANENT_PKTS,},
		{"NF9_VENDOR_87", 1, 0, NF9_VENDOR_87,},
		{"NF9_FRAGMENT_OFFSET", 1, 0, NF9_FRAGMENT_OFFSET,},
		{"NF9_FORWARDING_STATUS", 1, 0, NF9_FORWARDING_STATUS,},
		{"NF9_SYSTEM", 1, 0, NF9_SCOPE_SYSTEM,},
		{"NF9_INTERFACE", 1, 0, NF9_SCOPE_INTERFACE,},
		{"NF9_LINE_CARD", 1, 0, NF9_SCOPE_LINE_CARD,},
		{"NF9_NETFLOW_CACHE", 1, 0, NF9_SCOPE_NETFLOW_CACHE,},
		{"NF9_TEMPLATE", 1, 0, NF9_SCOPE_TEMPLATE,},
		{0, 0, 0, 0},
	};

	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	while ((opt = getopt_long(argc, argv, opstring, long_options, &opt_index)) != -1) {
		switch (opt) {
		case ('i'):
			status = set_source(ETHERNET_NIC, optarg);
			printf("Source: live NIC %s\n", optarg);
			if (status != 1) {
				printf("Error setting input\n");
				exit(1);
			}
			sd = create_set();
			break;
		case ('f'):
			status = set_source(TCPDUMP_TRACE, optarg);
			printf("Source: pcap file %s\n", optarg);
			if (status != 1) {
				printf("Error setting input\n");
				exit(1);
			}

			sd = create_set();
			break;
		case ('a'):
			if (strcmp(optarg, "MAP") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_SRC_ADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_DST_ADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_NEXT_HOP, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV6_NEXT_HOP, MAP);
				printf("Map ip addresses\n");
			} else if (strcmp(optarg, "PREFIX") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_SRC_ADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_DST_ADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_NEXT_HOP,
						PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV6_NEXT_HOP,
						PREFIX_PRESERVING);
				printf("Prefix-preserving ip addresses\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_SRC_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_DST_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV6_SRC_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV6_DST_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV4_NEXT_HOP, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IPV6_NEXT_HOP, ZERO);
				printf("Zero ip addresses\n");
			}
			break;
		case ('p'):
			print_pkt = 1;
			break;
		case ('h'):
			usage(argv[0]);
			exit(1);
			break;
		case ('t'):
			if (strcmp(optarg, "MAP") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_L4_SRC_PORT, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_L4_DST_PORT, MAP);
				printf("Map TCP ports\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_L4_SRC_PORT, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_L4_DST_PORT, ZERO);
				printf("ZERO TCP ports\n");
			}
			break;
		case ('v'):
			add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_IN_BYTES, VALUE_SHIFT,
				     strtol(optarg, NULL, 10));
			printf("Shift incoming bytes\n");
			break;
		case ('z'):
			add_function(sd, "ANONYMIZE", NETFLOW_V9, NF9_TCP_FLAGS, ZERO);
			printf("Zero Netflow TCP flags\n");
			break;
		case ('c'):
			fix_cks = 1;
			printf("Fix checksums\n");
			break;
		default:
			if (opt > BASE_NETFLOW_V9_DEFS && opt < END_NETFLOW_V9_SCOPES
			    && opt != BASE_NETFLOW_V9_SCOPES && opt != END_NETFLOW_V9_FIELDS
			    && opt != BASE_NETFLOW_V9_FIELDS) {
				int             function = UNCHANGED;
				if (strcmp("UNCHANGED", optarg) == 0) {
					function = UNCHANGED;
				}
				if (strcmp("MAP", optarg) == 0) {
					function = MAP;
				}
				if (strcmp("MAP_DISTRIBUTION", optarg) == 0) {
					function = MAP_DISTRIBUTION;
				}
				if (strcmp("STRIP", optarg) == 0) {
					function = STRIP;
				}
				if (strcmp("RANDOM", optarg) == 0) {
					function = RANDOM;
				}
				if (strcmp("HASHED", optarg) == 0) {
					function = HASHED;
				}
				if (strcmp("PATTERN_FILL", optarg) == 0) {
					function = PATTERN_FILL;
				}
				if (strcmp("ZERO", optarg) == 0) {
					function = ZERO;
				}
				if (strcmp("REPLACE", optarg) == 0) {
					function = REPLACE;
				}
				if (strcmp("PREFIX_PRESERVING", optarg) == 0) {
					function = PREFIX_PRESERVING;
				}
				if (strcmp("PREFIX_PRESERVING_MAP", optarg) == 0) {
					function = PREFIX_PRESERVING_MAP;
				}
				if (strcmp("CHECKSUM_ADJUST", optarg) == 0) {
					function = CHECKSUM_ADJUST;
				}
				if (strcmp("FILENAME_RANDOM", optarg) == 0) {
					function = FILENAME_RANDOM;
				}
				if (strcmp("REGEXP", optarg) == 0) {
					function = REGEXP;
				}
				if (strcmp("PAD_WITH_ZERO", optarg) == 0) {
					function = PAD_WITH_ZERO;
				}
				if (strcmp("STRIP_REST", optarg) == 0) {
					function = STRIP_REST;
				}
				if (strcmp("SHA", optarg) == 0) {
					function = SHA;
				}
				if (strcmp("MD5", optarg) == 0) {
					function = MD5;
				}
				if (strcmp("CRC32", optarg) == 0) {
					function = CRC32;
				}
				if (strcmp("SHA_2", optarg) == 0) {
					function = SHA_2;
				}
				if (strcmp("TRIPLEDES", optarg) == 0) {
					function = TRIPLEDES;
				}
				if (strcmp("AES", optarg) == 0) {
					function = AES;
				}
				if (strcmp("DES", optarg) == 0) {
					function = DES;
				}
				add_function(sd, "ANONYMIZE", NETFLOW_V9,
					     long_options[opt_index].val, function);
			} else {
				usage(argv[0]);
				exit(1);
			}
			break;
		}
	}

	status = set_output(sd, TCPDUMP_TRACE, argv[argc - 1]);
	printf("Output: File %s\n\n", argv[argc - 1]);
	if (status != 1) {
		printf("Error setting output\n");
		exit(1);
	}

	if (fix_cks)
		add_function(sd, "ANONYMIZE", IP, CHECKSUM, CHECKSUM_ADJUST);
	if (print_pkt)
		add_function(sd, "PRINT_PACKET");

	printf("\nStart anonymize...\n");
	start_processing();
	printf("End anonymize\n");
	return 1;
}
