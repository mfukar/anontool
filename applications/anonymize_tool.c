/*
 * This application uses AAPI to perform anonymization on packet traces.
 *
 * See './anonymize_tool -h' for usage information.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include "anonymization.h"

void usage(char *en)
{
    printf("Usage: Anonymize tcp and udp traffic\n");
    printf("%s [-i -f -a -t -d -c -z -p -h] output\n", en);
    printf("\t-i Open interface as input (INTERFACE)\n");
    printf("\t-f Open specified file as input (FILE)\n");
    printf("\t-e ANONYMIZE ETHERNET addresses (ZERO)\n");
    printf("\t-a ANONYMIZE IP addresses (PREFIX, MAP (IPv4 only), ZERO)\n");
    printf("\t-t ANONYMIZE TCP ports (MAP, ZERO)\n");
    printf("\t-d ANONYMIZE TCP/UDP payload (STRIP, ZERO, HASH)\n");
    printf("\t-c Fix checksums\n");
    printf("\t-z Zero tcp and ip options\n");
    printf("\t-p Print anonymized packets\n");
    printf("\t-h Print this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("Prefix-preserving anonymization for IP addressses, mapping to intergers for TCP ports, zero TCP/IP options, replace TCP/UDP payload with hash and fix checksums. Read packets from pcap file input_file and dump anonymized packets to pcap file output_file\n");
    printf("\t%s -f input_file -c -z -a PREFIX -t MAP -d HASH output_file\n\n", en);
    printf("Map IP addressses to integers, zero TCP/IP options, remove TCP/UDP payload with hash, fix checksums and print anonymized packets.Read packets from eth0 interface and dump anonymized packets to pcap file output_file\n");
    printf("\t%s -i eth0 -p -c -z -a MAP -d STRIP output_file\n", en);
    printf("\n\tWARNING: -i or -f MUST precede every other argument switch.\n");
}

int main(int argc, char *argv[])
{
    char           *config = NULL;

    int             sd = 0, opt, print_pkt = 0, fix_cks = 0, status;

    static char    *opstring = "czhpa:e:d:t:i:f:o:";

    if (argc == 1) {
        usage(argv[0]);
        exit(-1);
    }

    while ((opt = getopt(argc, argv, opstring)) != -1) {
        switch (opt) {
            case ('i'):
                status = set_source(ETHERNET_NIC, optarg);
                printf("Source: live NIC %s\n", optarg);
                if (status != 1) {
                    printf("Error setting input\n");
                    exit(-2);
                }
                sd = create_set();
                break;
            case ('f'):
                status = set_source(TCPDUMP_TRACE, optarg);
                printf("Source: pcap file %s\n", optarg);
                if (status != 1) {
                    printf("Error setting input\n");
                    exit(-2);
                }

                sd = create_set();
                break;
            case ('e'):
                if (strcmp(optarg, "ZERO") == 0) {
                    add_function(sd, "ANONYMIZE", ETHERNET, SRC_IP, ZERO);
                    add_function(sd, "ANONYMIZE", ETHERNET, DST_IP, ZERO);
                    printf("Zero ethernet addresses\n");
                }
                break;
            case ('a'):
                if (strcmp(optarg, "MAP") == 0) {
                    add_function(sd, "ANONYMIZE", IP, SRC_IP, MAP);
                    add_function(sd, "ANONYMIZE", IP, DST_IP, MAP);
                    printf("Map ip addresses\n");
                } else if (strcmp(optarg, "PREFIX") == 0) {
                    add_function(sd, "ANONYMIZE", IP, SRC_IP, PREFIX_PRESERVING);
                    add_function(sd, "ANONYMIZE", IP, DST_IP, PREFIX_PRESERVING);
                    printf("Prefix-preserving ip addresses\n");
                } else {
                    add_function(sd, "ANONYMIZE", IP, SRC_IP, ZERO);
                    add_function(sd, "ANONYMIZE", IP, DST_IP, ZERO);
                    printf("Zero ip addresses\n");
                }
                break;
            case ('p'):
                print_pkt = 1;
                break;
            case ('d'):
                if (strcmp(optarg, "STRIP") == 0) {
                    add_function(sd, "ANONYMIZE", TCP, PAYLOAD, STRIP, 0);
                    add_function(sd, "ANONYMIZE", UDP, PAYLOAD, STRIP, 0);
                    printf("Removing TCP payload\n");
                } else if (strcmp(optarg, "HASH") == 0) {
                    add_function(sd, "ANONYMIZE", TCP, PAYLOAD, HASHED, MD5,
                            STRIP_REST);
                    add_function(sd, "ANONYMIZE", UDP, PAYLOAD, HASHED, MD5,
                            STRIP_REST);
                    printf("HASH TCP/UDP payload\n");
                } else {
                    add_function(sd, "ANONYMIZE", TCP, PAYLOAD, ZERO);
                    add_function(sd, "ANONYMIZE", UDP, PAYLOAD, ZERO);
                    printf("ZERO TCP payload\n");
                }
                break;
            case ('h'):
                usage(argv[0]);
                exit(0);
                break;
            case ('t'):
                if (strcmp(optarg, "MAP") == 0) {
                    add_function(sd, "ANONYMIZE", TCP, SRC_PORT, MAP);
                    add_function(sd, "ANONYMIZE", TCP, DST_PORT, MAP);
                    printf("Map TCP ports\n");
                } else {
                    add_function(sd, "ANONYMIZE", TCP, SRC_PORT, ZERO);
                    add_function(sd, "ANONYMIZE", TCP, DST_PORT, ZERO);
                    printf("ZERO TCP ports\n");
                }
                break;
            case ('z'):
                add_function(sd, "ANONYMIZE", IP, OPTIONS, ZERO);
                add_function(sd, "ANONYMIZE", TCP, TCP_OPTIONS, RANDOM);
                printf("Zero TCP and IP options\n");
                break;
            case ('c'):
                fix_cks = 1;
                printf("Fix checksums\n");
                break;
            default:
                usage(argv[0]);
                exit(0);
                break;
        }
    }

    status = set_output(sd, TCPDUMP_TRACE, argv[argc - 1]);
    printf("Output: File %s\n\n", argv[argc - 1]);
    if (status != 1) {
        printf("Error setting output\n");
        exit(-2);
    }

    if (fix_cks)
        add_function(sd, "ANONYMIZE", IP, CHECKSUM, CHECKSUM_ADJUST);
    if (print_pkt)
        add_function(sd, "PRINT_PACKET");

    printf("\nStart anonymize...\n");
    start_processing();
    printf("End anonymize\n");
    return (1);
}
