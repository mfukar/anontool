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
		{"NETFLOW_VERSION", 1, 0, NETFLOW_VERSION,},
		{"COUNT", 1, 0, COUNT,},
		{"UPTIME", 1, 0, UPTIME,},
		{"UNIXSECS", 1, 0, UNIXSECS,},
		{"PACKAGESEQ", 1, 0, PACKAGESEQ,},
		{"SOURCEID", 1, 0, SOURCEID,},
		{"FLOWSET_ID", 1, 0, FLOWSET_ID,},
		{"LENGTH", 1, 0, LENGTH,},
		{"TEMPLATEID", 1, 0, TEMPLATEID,},
		{"FIELD_COUNT", 1, 0, FIELD_COUNT,},
		{"IN_BYTES", 1, 0, IN_BYTES,},
		{"IN_PKTS", 1, 0, IN_PKTS,},
		{"FLOWS", 1, 0, FLOWS,},
		{"PROTOCOL", 1, 0, PROTOCOL,},
		{"SRC_TOS", 1, 0, SRC_TOS,},
		{"NF9_TCP_FLAGS", 1, 0, NF9_TCP_FLAGS,},
		{"L4_SRC_PORT", 1, 0, L4_SRC_PORT,},
		{"IPV4_SRC_ADDR", 1, 0, IPV4_SRC_ADDR,},
		{"SRC_MASK", 1, 0, SRC_MASK,},
		{"INPUT_SNMP", 1, 0, INPUT_SNMP,},
		{"L4_DST_PORT", 1, 0, L4_DST_PORT,},
		{"IPV4_DST_ADDR", 1, 0, IPV4_DST_ADDR,},
		{"DST_MASK", 1, 0, DST_MASK,},
		{"OUTPUT_SNMP", 1, 0, OUTPUT_SNMP,},
		{"IPV4_NEXT_HOP", 1, 0, IPV4_NEXT_HOP,},
		{"SRC_AS", 1, 0, SRC_AS,},
		{"DST_AS", 1, 0, DST_AS,},
		{"BGP_IPV4_NEXT_HOP", 1, 0, BGP_IPV4_NEXT_HOP,},
		{"MUL_DST_PKTS", 1, 0, MUL_DST_PKTS,},
		{"MUL_DST_BYTES", 1, 0, MUL_DST_BYTES,},
		{"LAST_SWITCHED", 1, 0, LAST_SWITCHED,},
		{"FIRST_SWITCHED", 1, 0, FIRST_SWITCHED,},
		{"OUT_BYTES", 1, 0, OUT_BYTES,},
		{"OUT_PKTS", 1, 0, OUT_PKTS,},
		{"MIN_PKT_LENGTH", 1, 0, MIN_PKT_LENGTH,},
		{"MAX_PKT_LENGTH", 1, 0, MAX_PKT_LENGTH,},
		{"IPV6_SRC_ADDR", 1, 0, IPV6_SRC_ADDR,},
		{"IPV6_DST_ADDR", 1, 0, IPV6_DST_ADDR,},
		{"IPV6_SRC_MASK", 1, 0, IPV6_SRC_MASK,},
		{"IPV6_DST_MASK", 1, 0, IPV6_DST_MASK,},
		{"IPV6_FLOW_LABEL", 1, 0, IPV6_FLOW_LABEL,},
		{"ICMP_TYPE", 1, 0, ICMP_TYPE,},
		{"MUL_IGMP_TYPE", 1, 0, MUL_IGMP_TYPE,},
		{"SAMPLING_INTERVAL", 1, 0, SAMPLING_INTERVAL,},
		{"SAMPLING_ALGORITHM", 1, 0, SAMPLING_ALGORITHM,},
		{"FLOW_ACTIVE_TIMEOUT", 1, 0, FLOW_ACTIVE_TIMEOUT,},
		{"FLOW_INACTIVE_TIMEOUT", 1, 0, FLOW_INACTIVE_TIMEOUT,},
		{"ENGINE_TYPE", 1, 0, ENGINE_TYPE,},
		{"ENGINE_ID", 1, 0, ENGINE_ID,},
		{"TOTAL_BYTES_EXP", 1, 0, TOTAL_BYTES_EXP,},
		{"TOTAL_PKTS_EXP", 1, 0, TOTAL_PKTS_EXP,},
		{"TOTAL_FLOWS_EXP", 1, 0, TOTAL_FLOWS_EXP,},
		{"VENDOR_43", 1, 0, VENDOR_43,},
		{"IPV4_SRC_PREFIX", 1, 0, IPV4_SRC_PREFIX,},
		{"IPV4_DST_PREFIX", 1, 0, IPV4_DST_PREFIX,},
		{"MPLS_TOP_LABEL_TYPE", 1, 0, MPLS_TOP_LABEL_TYPE,},
		{"MPLS_TOP_LABEL_IP_ADDR", 1, 0, MPLS_TOP_LABEL_IP_ADDR,},
		{"FLOW_SAMPLER_ID", 1, 0, FLOW_SAMPLER_ID,},
		{"FLOW_SAMPLER_MODE", 1, 0, FLOW_SAMPLER_MODE,},
		{"FLOW_SAMPLER_RANDOM_INTERVAL", 1, 0, FLOW_SAMPLER_RANDOM_INTERVAL,},
		{"VENDOR_51", 1, 0, VENDOR_51,},
		{"MIN_TTL", 1, 0, MIN_TTL,},
		{"MAX_TTL", 1, 0, MAX_TTL,},
		{"IPV4_IDENT", 1, 0, IPV4_IDENT,},
		{"DST_TOS", 1, 0, DST_TOS,},
		{"IN_SRC_MAC", 1, 0, IN_SRC_MAC,},
		{"OUT_DST_MAC", 1, 0, OUT_DST_MAC,},
		{"SRC_VLAN", 1, 0, SRC_VLAN,},
		{"DST_VLAN", 1, 0, DST_VLAN,},
		{"IP_PROTOCOL_VERSION", 1, 0, IP_PROTOCOL_VERSION,},
		{"DIRECTION", 1, 0, DIRECTION,},
		{"IPV6_NEXT_HOP", 1, 0, IPV6_NEXT_HOP,},
		{"BGP_IPV6_NEXT_HOP", 1, 0, BGP_IPV6_NEXT_HOP,},
		{"IPV6_OPTION_HEADERS", 1, 0, IPV6_OPTION_HEADERS,},
		{"VENDOR_65", 1, 0, VENDOR_65,},
		{"VENDOR_66", 1, 0, VENDOR_66,},
		{"VENDOR_67", 1, 0, VENDOR_67,},
		{"VENDOR_68", 1, 0, VENDOR_68,},
		{"VENDOR_69", 1, 0, VENDOR_69,},
		{"MPLS_LABEL_1", 1, 0, MPLS_LABEL_1,},
		{"MPLS_LABEL_2", 1, 0, MPLS_LABEL_2,},
		{"MPLS_LABEL_3", 1, 0, MPLS_LABEL_3,},
		{"MPLS_LABEL_4", 1, 0, MPLS_LABEL_4,},
		{"MPLS_LABEL_5", 1, 0, MPLS_LABEL_5,},
		{"MPLS_LABEL_6", 1, 0, MPLS_LABEL_6,},
		{"MPLS_LABEL_7", 1, 0, MPLS_LABEL_7,},
		{"MPLS_LABEL_8", 1, 0, MPLS_LABEL_8,},
		{"MPLS_LABEL_9", 1, 0, MPLS_LABEL_9,},
		{"MPLS_LABEL_10", 1, 0, MPLS_LABEL_10,},
		{"IN_DST_MAC", 1, 0, IN_DST_MAC,},
		{"OUT_SRC_MAC", 1, 0, OUT_SRC_MAC,},
		{"IF_NAME", 1, 0, IF_NAME,},
		{"IF_DESC", 1, 0, IF_DESC,},
		{"SAMPLER_NAME", 1, 0, SAMPLER_NAME,},
		{"IN_PERMANENT_BYTES", 1, 0, IN_PERMANENT_BYTES,},
		{"IN_PERMANENT_PKTS", 1, 0, IN_PERMANENT_PKTS,},
		{"VENDOR_87", 1, 0, VENDOR_87,},
		{"NF9_FRAGMENT_OFFSET", 1, 0, NF9_FRAGMENT_OFFSET,},
		{"FORWARDING_STATUS", 1, 0, FORWARDING_STATUS,},
		{"SYSTEM", 1, 0, SYSTEM,},
		{"INTERFACE", 1, 0, INTERFACE,},
		{"LINE_CARD", 1, 0, LINE_CARD,},
		{"NETFLOW_CACHE", 1, 0, NETFLOW_CACHE,},
		{"TEMPLATE", 1, 0, TEMPLATE,},
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
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_SRC_ADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_DST_ADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_NEXT_HOP, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV6_NEXT_HOP, MAP);
				printf("Map ip addresses\n");
			} else if (strcmp(optarg, "PREFIX") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_SRC_ADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_DST_ADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_NEXT_HOP,
						PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV6_NEXT_HOP,
						PREFIX_PRESERVING);
				printf("Prefix-preserving ip addresses\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_SRC_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_DST_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV6_SRC_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV6_DST_ADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV4_NEXT_HOP, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, IPV6_NEXT_HOP, ZERO);
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
				add_function(sd, "ANONYMIZE", NETFLOW_V9, L4_SRC_PORT, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, L4_DST_PORT, MAP);
				printf("Map TCP ports\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V9, L4_SRC_PORT, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V9, L4_DST_PORT, ZERO);
				printf("ZERO TCP ports\n");
			}
			break;
		case ('v'):
			add_function(sd, "ANONYMIZE", NETFLOW_V9, IN_BYTES, VALUE_SHIFT,
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
