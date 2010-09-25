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
	printf("\t-a ANONYMIZE IP addresses in Netflows (PREFIX, MAP,(IPv4 only) ZERO)\n");
	printf("\t-t ANONYMIZE TCP ports in Netflows (MAP, ZERO)\n");
	printf("\t-c Fix checksums\n");
	printf("\t-z Zero TCP flags\n");
	printf("\t-p Print anonymized packets\n");
	printf
	    ("\t--FIELD FUNCTION This kind of argument allows to anonymized any desired FIELD using any available FUNCTION\n");
	printf("\t Check /docs/README for a detailed list of available fields & functions\n");
	printf("\t-h Print this help message\n");
	printf("\n\tWARNING: -i or -f MUST precede every other argument switch.\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int             sd = 0, opt, print_pkt = 0, fix_cks = 0, status;

	static char    *opstring = "czhpa:d:t:i:f:";
	int             opt_index = 0;
	static struct option long_options[] = {
		{"NF5_VERSION", 1, 0, NF5_VERSION},
		{"NF5_FLOWCOUNT", 1, 0, NF5_FLOWCOUNT},
		{"NF5_UPTIME", 1, 0, NF5_UPTIME},
		{"NF5_UNIX_SECS", 1, 0, NF5_UNIX_SECS},
		{"NF5_UNIX_NSECS", 1, 0, NF5_UNIX_NSECS},
		{"NF5_SEQUENCE", 1, 0, NF5_SEQUENCE},
		{"NF5_ENGINE_TYPE", 1, 0, NF5_ENGINE_TYPE},
		{"NF5_ENGINE_ID", 1, 0, NF5_ENGINE_ID},
		{"NF5_SRCADDR", 1, 0, NF5_SRCADDR},
		{"NF5_DSTADDR", 1, 0, NF5_DSTADDR},
		{"NF5_NEXTHOP", 1, 0, NF5_NEXTHOP},
		{"NF5_INPUT", 1, 0, NF5_INPUT},
		{"NF5_OUTPUT", 1, 0, NF5_OUTPUT},
		{"NF5_DPKTS", 1, 0, NF5_DPKTS},
		{"NF5_DOCTETS", 1, 0, NF5_DOCTETS},
		{"NF5_FIRST", 1, 0, NF5_FIRST},
		{"NF5_LAST", 1, 0, NF5_LAST},
		{"NF5_SRCPORT", 1, 0, NF5_SRCPORT},
		{"NF5_DSTPORT", 1, 0, NF5_DSTPORT},
		{"NF5_TCP_FLAGS", 1, 0, NF5_TCP_FLAGS},
		{"NF5_PROT", 1, 0, NF5_PROT},
		{"NF5_TOS", 1, 0, NF5_TOS},
		{"NF5_SRC_AS", 1, 0, NF5_SRC_AS},
		{"NF5_DST_AS", 1, 0, NF5_DST_AS},
		{"NF5_SRC_MASK", 1, 0, NF5_SRC_MASK},
		{"NF5_DST_MASK", 1, 0, NF5_DST_MASK},
		{0, 0, 0, 0}
	};

	if (argc == 1) {
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
		case ('d'):
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCADDR, ZERO);
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTADDR, ZERO);
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCPORT, RANDOM);
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTPORT, RANDOM);
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_UPTIME, RANDOM);
			fix_cks = 1;
			printf
			    ("Predefined policy selected.\nRefer to %s -h for more information.\n",
			     argv[0]);
			break;
		case ('a'):
			if (strcmp(optarg, "MAP") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTADDR, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_NEXTHOP, MAP);
				printf("Map ip addresses\n");
			} else if (strcmp(optarg, "PREFIX") == 0) {
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTADDR,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_NEXTHOP,
					     PREFIX_PRESERVING);
				printf("Prefix-preserving ip addresses\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTADDR, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_NEXTHOP, ZERO);
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
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCPORT, MAP);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTPORT, MAP);
				printf("Map TCP ports\n");
			} else {
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_SRCPORT, ZERO);
				add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_DSTPORT, ZERO);
				printf("ZERO TCP ports\n");
			}
			break;
		case ('z'):
			add_function(sd, "ANONYMIZE", NETFLOW_V5, NF5_TCP_FLAGS, ZERO);
			printf("Zero Netflow TCP flags\n");
			break;
		case ('c'):
			fix_cks = 1;
			printf("Fix checksums\n");
			break;
		default:
			if (opt > BASE_NETFLOW_V5_DEFS && opt < END_NETFLOW_V5_DEFS) {
				printf("%s -- %s\n", long_options[opt_index].name, optarg);
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
				add_function(sd, "ANONYMIZE", NETFLOW_V5,
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
