#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include "anonymization.h"

void usage(char *en)
{
	printf("Usage: Anonymize tcp and udp traffic\n");
	printf("%s [-i -f -a -t -d -c -p -h] output\n", en);
	printf("\t-i Open interface as input (INTERFACE)\n");
	printf("\t-f Open file as input (FILE)\n");
	printf("\t-a ANONYMIZE IP addresses in IPFIX (PREFIX, MAP (IPv4 only), ZERO)\n");
	printf("\t-t ANONYMIZE TCP ports in IPFIX (MAP, ZERO)\n");
	printf("\t-c Fix checksums\n");
	printf("\t-p Print anonymized packets\n");
	printf("\t-h Print this help message\n");
	printf("\n");
	printf("\n\tWARNING: -i or -f MUST precede every other argument switch.\n");
}

int main(int argc, char *argv[])
{
	int             sd = 0, opt, print_pkt = 0, fix_cks = 0, status;

	static char    *opstring = "chpa:t:i:f:";
	int             opt_index;
	static struct option long_options[] = {
		{"IPFIX_VERSION", 1, 0, IPFIX_VERSION},
		{"IPFIX_MSG_LENGTH", 1, 0, IPFIX_MSG_LENGTH},
		{"IPFIX_EXPORT_TIME", 1, 0, IPFIX_EXPORT_TIME},
		{"IPFIX_SEQUENCE", 1, 0, IPFIX_SEQUENCE},
		{"IPFIX_OBSERV_ID", 1, 0, IPFIX_OBSERV_ID},
		{"IPFIX_INFOELEM_ID", 1, 0, IPFIX_INFOELEM_ID},
		{"IPFIX_FIELD_LENGTH", 1, 0, IPFIX_FIELD_LENGTH},
		{"IPFIX_ENTERPRISE_NO", 1, 0, IPFIX_ENTERPRISE_NO},
		{"IPFIX_SET_ID", 1, 0, IPFIX_SET_ID},
		{"IPFIX_SET_LENGTH", 1, 0, IPFIX_SET_LENGTH},
		{"IPFIX_TEMPLATE_ID", 1, 0, IPFIX_TEMPLATE_ID},
		{"IPFIX_TEMPLATE_COUNT", 1, 0, IPFIX_TEMPLATE_COUNT},
		{"IPFIX_OPTION_HDR_ID", 1, 0, IPFIX_OPTION_HDR_ID},
		{"IPFIX_OPTION_HDR_COUNT", 1, 0, IPFIX_OPTION_HDR_COUNT},
		{"IPFIX_OPTION_HDR_SCOPE", 1, 0, IPFIX_OPTION_HDR_SCOPE},
		{"IPFIX_octetDeltaCount", 1, 0, IPFIX_octetDeltaCount},
		{"IPFIX_packetDeltaCount", 1, 0, IPFIX_packetDeltaCount},
		{"IPFIX_reserved1", 1, 0, IPFIX_reserved1},
		{"IPFIX_protocolIdentifier", 1, 0, IPFIX_protocolIdentifier},
		{"IPFIX_ipClassOfService", 1, 0, IPFIX_ipClassOfService},
		{"IPFIX_tcpControlBits", 1, 0, IPFIX_tcpControlBits},
		{"IPFIX_sourceTransportPort", 1, 0, IPFIX_sourceTransportPort},
		{"IPFIX_sourceIPv4Address", 1, 0, IPFIX_sourceIPv4Address},
		{"IPFIX_sourceIPv4PrefixLength", 1, 0, IPFIX_sourceIPv4PrefixLength},
		{"IPFIX_ingressInterface", 1, 0, IPFIX_ingressInterface},
		{"IPFIX_destinationTransportPort", 1, 0, IPFIX_destinationTransportPort},
		{"IPFIX_destinationIPv4Address", 1, 0, IPFIX_destinationIPv4Address},
		{"IPFIX_destinationIPv4PrefixLength", 1, 0, IPFIX_destinationIPv4PrefixLength},
		{"IPFIX_egressInterface", 1, 0, IPFIX_egressInterface},
		{"IPFIX_ipNextHopIPv4Address", 1, 0, IPFIX_ipNextHopIPv4Address},
		{"IPFIX_bgpSourceAsNumber", 1, 0, IPFIX_bgpSourceAsNumber},
		{"IPFIX_bgpDestinationAsNumber", 1, 0, IPFIX_bgpDestinationAsNumber},
		{"IPFIX_bgpNexthopIPv4Address", 1, 0, IPFIX_bgpNexthopIPv4Address},
		{"IPFIX_postMCastPacketDeltaCount", 1, 0, IPFIX_postMCastPacketDeltaCount},
		{"IPFIX_postMCastOctetDeltaCount", 1, 0, IPFIX_postMCastOctetDeltaCount},
		{"IPFIX_flowEndSysUpTime", 1, 0, IPFIX_flowEndSysUpTime},
		{"IPFIX_flowStartSysUpTime", 1, 0, IPFIX_flowStartSysUpTime},
		{"IPFIX_postOctetDeltaCount", 1, 0, IPFIX_postOctetDeltaCount},
		{"IPFIX_postPacketDeltaCount", 1, 0, IPFIX_postPacketDeltaCount},
		{"IPFIX_minimumIpTotalLength", 1, 0, IPFIX_minimumIpTotalLength},
		{"IPFIX_maximumIpTotalLength", 1, 0, IPFIX_maximumIpTotalLength},
		{"IPFIX_sourceIPv6Address", 1, 0, IPFIX_sourceIPv6Address},
		{"IPFIX_destinationIPv6Address", 1, 0, IPFIX_destinationIPv6Address},
		{"IPFIX_sourceIPv6PrefixLength", 1, 0, IPFIX_sourceIPv6PrefixLength},
		{"IPFIX_destinationIPv6PrefixLength", 1, 0, IPFIX_destinationIPv6PrefixLength},
		{"IPFIX_flowLabelIPv6", 1, 0, IPFIX_flowLabelIPv6},
		{"IPFIX_icmpTypeCodeIPv4", 1, 0, IPFIX_icmpTypeCodeIPv4},
		{"IPFIX_igmpType", 1, 0, IPFIX_igmpType},
		{"IPFIX_reserved2", 1, 0, IPFIX_reserved2},
		{"IPFIX_reserved3", 1, 0, IPFIX_reserved3},
		{"IPFIX_flowActiveTimeout", 1, 0, IPFIX_flowActiveTimeout},
		{"IPFIX_flowIdleTimeout", 1, 0, IPFIX_flowIdleTimeout},
		{"IPFIX_reserved4", 1, 0, IPFIX_reserved4},
		{"IPFIX_reserved5", 1, 0, IPFIX_reserved5},
		{"IPFIX_exportedOctetTotalCount", 1, 0, IPFIX_exportedOctetTotalCount},
		{"IPFIX_exportedMessageTotalCount", 1, 0, IPFIX_exportedMessageTotalCount},
		{"IPFIX_exportedFlowRecordTotalCount", 1, 0, IPFIX_exportedFlowRecordTotalCount},
		{"IPFIX_reserved6", 1, 0, IPFIX_reserved6},
		{"IPFIX_sourceIPv4Prefix", 1, 0, IPFIX_sourceIPv4Prefix},
		{"IPFIX_destinationIPv4Prefix", 1, 0, IPFIX_destinationIPv4Prefix},
		{"IPFIX_mplsTopLabelType", 1, 0, IPFIX_mplsTopLabelType},
		{"IPFIX_mplsTopLabelIPv4Address", 1, 0, IPFIX_mplsTopLabelIPv4Address},
		{"IPFIX_reserved7", 1, 0, IPFIX_reserved7},
		{"IPFIX_reserved8", 1, 0, IPFIX_reserved8},
		{"IPFIX_reserved9", 1, 0, IPFIX_reserved9},
		{"IPFIX_reserved10", 1, 0, IPFIX_reserved10},
		{"IPFIX_minimumTTL", 1, 0, IPFIX_minimumTTL},
		{"IPFIX_maximumTTL", 1, 0, IPFIX_maximumTTL},
		{"IPFIX_fragmentIdentification", 1, 0, IPFIX_fragmentIdentification},
		{"IPFIX_postIpClassOfService", 1, 0, IPFIX_postIpClassOfService},
		{"IPFIX_sourceMacAddress", 1, 0, IPFIX_sourceMacAddress},
		{"IPFIX_postDestinationMacAddress", 1, 0, IPFIX_postDestinationMacAddress},
		{"IPFIX_vlanId", 1, 0, IPFIX_vlanId},
		{"IPFIX_postVlanId", 1, 0, IPFIX_postVlanId},
		{"IPFIX_ipVersion", 1, 0, IPFIX_ipVersion},
		{"IPFIX_flowDirection", 1, 0, IPFIX_flowDirection},
		{"IPFIX_ipNextHopIPv6Address", 1, 0, IPFIX_ipNextHopIPv6Address},
		{"IPFIX_bgpNexthopIPv6Address", 1, 0, IPFIX_bgpNexthopIPv6Address},
		{"IPFIX_ipv6ExtensionHeaders", 1, 0, IPFIX_ipv6ExtensionHeaders},
		{"IPFIX_reserved11", 1, 0, IPFIX_reserved11},
		{"IPFIX_reserved12", 1, 0, IPFIX_reserved12},
		{"IPFIX_reserved13", 1, 0, IPFIX_reserved13},
		{"IPFIX_reserved14", 1, 0, IPFIX_reserved14},
		{"IPFIX_reserved15", 1, 0, IPFIX_reserved15},
		{"IPFIX_mplsTopLabelStackSection", 1, 0, IPFIX_mplsTopLabelStackSection},
		{"IPFIX_mplsLabelStackSection2", 1, 0, IPFIX_mplsLabelStackSection2},
		{"IPFIX_mplsLabelStackSection3", 1, 0, IPFIX_mplsLabelStackSection3},
		{"IPFIX_mplsLabelStackSection4", 1, 0, IPFIX_mplsLabelStackSection4},
		{"IPFIX_mplsLabelStackSection5", 1, 0, IPFIX_mplsLabelStackSection5},
		{"IPFIX_mplsLabelStackSection6", 1, 0, IPFIX_mplsLabelStackSection6},
		{"IPFIX_mplsLabelStackSection7", 1, 0, IPFIX_mplsLabelStackSection7},
		{"IPFIX_mplsLabelStackSection8", 1, 0, IPFIX_mplsLabelStackSection8},
		{"IPFIX_mplsLabelStackSection9", 1, 0, IPFIX_mplsLabelStackSection9},
		{"IPFIX_mplsLabelStackSection10", 1, 0, IPFIX_mplsLabelStackSection10},
		{"IPFIX_destinationMacAddress", 1, 0, IPFIX_destinationMacAddress},
		{"IPFIX_postSourceMacAddress", 1, 0, IPFIX_postSourceMacAddress},
		{"IPFIX_reserved16", 1, 0, IPFIX_reserved16},
		{"IPFIX_reserved17", 1, 0, IPFIX_reserved17},
		{"IPFIX_reserved18", 1, 0, IPFIX_reserved18},
		{"IPFIX_octetTotalCount", 1, 0, IPFIX_octetTotalCount},
		{"IPFIX_packetTotalCount", 1, 0, IPFIX_packetTotalCount},
		{"IPFIX_reserved19", 1, 0, IPFIX_reserved19},
		{"IPFIX_fragmentOffset", 1, 0, IPFIX_fragmentOffset},
		{"IPFIX_reserved20", 1, 0, IPFIX_reserved20},
		{"IPFIX_mplsVpnRouteDistinguisher", 1, 0, IPFIX_mplsVpnRouteDistinguisher},
		{0, 0, 0, 0},
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
		case ('a'):
			if (strcmp(optarg, "MAP") == 0) {
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceIPv4Address, MAP);
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_destinationIPv4Address,
					     MAP);
				printf("Map ip addresses\n");
			} else if (strcmp(optarg, "PREFIX") == 0) {
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceIPv4Address,
					     PREFIX_PRESERVING);
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_destinationIPv4Address,
					     PREFIX_PRESERVING);
				printf("Prefix-preserving ip addresses\n");
			} else {
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceIPv4Address, ZERO);
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_destinationIPv4Address,
					     ZERO);
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
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceTransportPort,
					     MAP);
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceTransportPort,
					     MAP);
				printf("Map TCP ports\n");
			} else {
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceTransportPort,
					     ZERO);
				add_function(sd, "ANONYMIZE", IPFIX, IPFIX_sourceTransportPort,
					     ZERO);
				printf("ZERO TCP ports\n");
			}
			break;
		case ('c'):
			fix_cks = 1;
			printf("Fix checksums\n");
			break;
		default:
			if (opt > BASE_IPFIX_DEFS && opt < END_IPFIX_FIELD_DEFS
			    && opt != BASE_IPFIX_FIELD_DEFS) {
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
				add_function(sd, "ANONYMIZE", IPFIX, long_options[opt_index].val,
					     function);
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
