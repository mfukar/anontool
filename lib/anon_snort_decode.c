#include <string.h>
#include <pcap.h>
#include "anonymization.h"

void            DecodeTRPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeFDDIPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeLinuxSLLPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeEthPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeIEEE80211Pkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeVlan(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodePppPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeSlipPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeNullPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeRawPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeI4LRawIPPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeI4LCiscoIPPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodePflog(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
void            DecodeIP(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeIPv6(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeARP(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodeEapol(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodeEapolKey(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodeIPX(unsigned char *, unsigned int, int snaplen);
void            DecodeSCTP(unsigned char *pkt, const unsigned int len, anonpacket *p, int snaplen);
void            DecodeTCP(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeUDP(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeEAP(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeICMP(unsigned char *, const unsigned int, anonpacket *, int snaplen);
void            DecodeIPOptions(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodeTCPOptions(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodeIPOptions(unsigned char *, unsigned int, anonpacket *, int snaplen);
void            DecodePPPoEPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int snaplen);
grinder_t       SetPktProcessor(int datalink);

void DecodeEthPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* suprisingly, the length of the packet */
    unsigned int    cap_len;    /* caplen value */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < ETHERNET_HEADER_LEN) {
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;
    /* grab out the network type */
    switch (ntohs(p->eh->ether_type)) {
    case ETHERNET_TYPE_PPPoE_DISC:
    case ETHERNET_TYPE_PPPoE_SESS:
        DecodePPPoEPkt(p, pkthdr, pkt, snaplen);
        break;

    case ETHERNET_TYPE_IP:
        DecodeIP(p->pkt + ETHERNET_HEADER_LEN, cap_len - ETHERNET_HEADER_LEN, p, snaplen);
        break;

    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
        DecodeARP(p->pkt + ETHERNET_HEADER_LEN, cap_len - ETHERNET_HEADER_LEN, p, snaplen);
        break;

    case ETHERNET_TYPE_IPV6:
        DecodeIPv6(p->pkt + ETHERNET_HEADER_LEN, (cap_len - ETHERNET_HEADER_LEN), p, snaplen);
        break;

    case ETHERNET_TYPE_IPX:
        DecodeIPX(p->pkt + ETHERNET_HEADER_LEN, (cap_len - ETHERNET_HEADER_LEN), snaplen);
        break;

    case ETHERNET_TYPE_8021Q:
        DecodeVlan(p->pkt + ETHERNET_HEADER_LEN, cap_len - ETHERNET_HEADER_LEN, p, snaplen);
        break;

    default:
        break;
    }

    return;
}

/*
 * Function: DecodeIEEE80211Pkt(anonpacket *, char *, struct pcap_pkthdr*,
 *                               unsigned char*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* suprisingly, the length of the packet */
    unsigned int    cap_len;    /* caplen value */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < MINIMAL_IEEE80211_HEADER_LEN) {
        return;
    }
    /* lay the wireless structure over the packet data */
    p->wifih = (WifiHdr *) pkt;

    /* determine frame type */
    switch (p->wifih->frame_control & 0x00ff) {
        /* management frames */
    case WLAN_TYPE_MGMT_ASREQ:
    case WLAN_TYPE_MGMT_ASRES:
    case WLAN_TYPE_MGMT_REREQ:
    case WLAN_TYPE_MGMT_RERES:
    case WLAN_TYPE_MGMT_PRREQ:
    case WLAN_TYPE_MGMT_PRRES:
    case WLAN_TYPE_MGMT_BEACON:
    case WLAN_TYPE_MGMT_ATIM:
    case WLAN_TYPE_MGMT_DIS:
    case WLAN_TYPE_MGMT_AUTH:
    case WLAN_TYPE_MGMT_DEAUTH:
        break;

        /* Control frames */
    case WLAN_TYPE_CONT_PS:
    case WLAN_TYPE_CONT_RTS:
    case WLAN_TYPE_CONT_CTS:
    case WLAN_TYPE_CONT_ACK:
    case WLAN_TYPE_CONT_CFE:
    case WLAN_TYPE_CONT_CFACK:
        break;
        /* Data packets without data */
    case WLAN_TYPE_DATA_NULL:
    case WLAN_TYPE_DATA_CFACK:
    case WLAN_TYPE_DATA_CFPL:
    case WLAN_TYPE_DATA_ACKPL:

        break;
        /* data packets with data */
    case WLAN_TYPE_DATA_DTCFACK:
    case WLAN_TYPE_DATA_DTCFPL:
    case WLAN_TYPE_DATA_DTACKPL:
    case WLAN_TYPE_DATA_DATA:
        p->ehllc = (EthLlc *) (pkt + IEEE802_11_DATA_HDR_LEN);

        if (p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP) {
            p->ehllcother =
                (EthLlcOther *) (pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc));

            switch (ntohs(p->ehllcother->proto_id)) {
            case ETHERNET_TYPE_IP:
                DecodeIP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                     sizeof(EthLlcOther),
                     pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                     sizeof(EthLlcOther), p, snaplen);
                return;

            case ETHERNET_TYPE_ARP:
            case ETHERNET_TYPE_REVARP:
                DecodeARP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                      sizeof(EthLlcOther),
                      pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                      sizeof(EthLlcOther), p, snaplen);
                return;
            case ETHERNET_TYPE_EAPOL:
                DecodeEapol(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                        sizeof(EthLlcOther),
                        pkt_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                        sizeof(EthLlcOther), p, snaplen);
                return;
            case ETHERNET_TYPE_8021Q:
                DecodeVlan(p->pkt + IEEE802_11_DATA_HDR_LEN,
                       cap_len - IEEE802_11_DATA_HDR_LEN, p, snaplen);
                return;

            default:
                return;
            }
        }
        break;
    default:
        break;
    }

    return;
}

void DecodeVlan(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    unsigned short int pri;
    p->vh = (VlanTagHdr *) pkt;

    pri = VTH_PRIORITY(p->vh);

    /* check to see if we've got an encapsulated LLC layer */
    if (pri != 0) {
        p->ehllc = (EthLlc *) (pkt + sizeof(VlanTagHdr));

        if (p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP) {
            p->ehllcother = (EthLlcOther *)
                (pkt + sizeof(VlanTagHdr) + sizeof(EthLlc));

            switch (ntohs(p->ehllcother->proto_id)) {
            case ETHERNET_TYPE_IP:
                DecodeIP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) +
                     sizeof(EthLlcOther), len - sizeof(VlanTagHdr), p, snaplen);
                return;

            case ETHERNET_TYPE_ARP:
            case ETHERNET_TYPE_REVARP:
                DecodeARP(p->pkt + sizeof(VlanTagHdr) + sizeof(EthLlc) +
                      sizeof(EthLlcOther), len - sizeof(VlanTagHdr), p,
                      snaplen);
                return;

            default:
                return;
            }
        }
    } else {
        switch (ntohs(p->vh->vth_proto)) {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + sizeof(VlanTagHdr), len - sizeof(VlanTagHdr), p, snaplen);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(pkt + sizeof(VlanTagHdr), len - sizeof(VlanTagHdr), p, snaplen);
            return;

        default:
            return;
        }
    }
}

/*
 * Function: DecodeNullPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeNullPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    len;
    unsigned int    cap_len;

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    /* do a little validation */
    if (cap_len < NULL_HDRLEN) {
        return;
    }

    DecodeIP(p->pkt + NULL_HDRLEN, cap_len - NULL_HDRLEN, p, snaplen);
}

/*
 * Function: DecodeTRPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments: p=> pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTRPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* suprisingly, the length of the packet */
    unsigned int    cap_len;    /* caplen value */
    unsigned int    dataoff;    /* data offset is variable here */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < TR_HLEN) {
        return;
    }

    /* lay the tokenring header structure over the packet data */
    p->trh = (Trh_hdr *) pkt;

    /*
     * according to rfc 1042:
     The presence of a Routing Information Field is indicated by the Most
     Significant Bit (MSB) of the source address, called the Routing
     Information Indicator (RII).  If the RII equals zero, a RIF is
     not present.  If the RII equals 1, the RIF is present.
     ..
     However the MSB is already zeroed by this moment, so there's no
     real way to figure out whether RIF is presented in packet, so we are
     doing some tricks to find IPARP signature..
     */

    /*
     * first I assume that we have single-ring network with no RIF
     * information presented in frame
     */
    p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));

    if (p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP) {
        /*
         * DSAP != SSAP != 0xAA .. either we are having frame which doesn't
         * carry IP datagrams or has RIF information present. We assume
         * lattest ...
         */
        p->trhmr = (Trh_mr *) (pkt + sizeof(Trh_hdr));
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr));
        dataoff = sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr) + sizeof(Trh_llc);
    } else {
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));
        dataoff = sizeof(Trh_hdr) + sizeof(Trh_llc);
    }

    /*
     * ideally we would need to check both SSAP, DSAP, and protoid fields: IP
     * datagrams and ARP requests and replies are transmitted in standard
     * 802.2 LLC Type 1 Unnumbered Information format, control code 3, with
     * the DSAP and the SSAP fields of the 802.2 header set to 170, the
     * assigned global SAP value for SNAP [6].  The 24-bit Organization Code
     * in the SNAP is zero, and the remaining 16 bits are the EtherType from
     * Assigned Numbers [7] (IP = 2048, ARP = 2054). .. but we would check
     * SSAP and DSAP and assume this would be enough to trust.
     */
    if (p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP) {
        p->trhllc = NULL;
        return;
    }
    pkt_len -= dataoff;
    cap_len -= dataoff;

    switch (htons(p->trhllc->ethertype)) {
    case ETHERNET_TYPE_IP:

        DecodeIP(p->pkt + dataoff, cap_len, p, snaplen);
        return;

    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
        return;

    case ETHERNET_TYPE_8021Q:
        DecodeVlan(p->pkt + dataoff, cap_len, p, snaplen);
        return;

    default:
        return;
    }

    return;
}

/*
 * Function: DecodeFDDIPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Mainly taken from CyberPsycotic's Token Ring Code -worm5er
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* length of the packet */
    unsigned int    cap_len;    /* capture length variable */
    unsigned int    dataoff;    /* data offset is variable here */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    pkt_len = pkthdr->len;
    cap_len = pkthdr->caplen;

    if ((unsigned int)snaplen < pkt_len) {
        pkt_len = cap_len;
    }
    /* Bounds checking (might not be right yet -worm5er) */
    if (p->pkth->caplen < FDDI_MIN_HLEN) {
        return;
    }
    /* let's put this in as the fddi header structure */
    p->fddihdr = (Fddi_hdr *) pkt;

    p->fddisaps = (Fddi_llc_saps *) (pkt + sizeof(Fddi_hdr));

    if ((p->fddisaps->dsap == FDDI_DSAP_IP) && (p->fddisaps->ssap == FDDI_SSAP_IP)) {
        p->fddiiparp = (Fddi_llc_iparp *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));

        dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps) + sizeof(Fddi_llc_iparp);
    } else if ((p->fddisaps->dsap == FDDI_DSAP_SNA) && (p->fddisaps->ssap == FDDI_SSAP_SNA)) {
        p->fddisna = (Fddi_llc_sna *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));
        dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps) + sizeof(Fddi_llc_sna);
    } else {
        p->fddiother = (Fddi_llc_other *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_other));

        dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps) + sizeof(Fddi_llc_other);
    }

    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    if ((p->fddisaps->dsap != FDDI_DSAP_IP) && (p->fddisaps->ssap != FDDI_SSAP_IP)) {
        return;
    }

    pkt_len -= dataoff;
    cap_len -= dataoff;

    switch (htons(p->fddiiparp->ethertype)) {
    case ETHERNET_TYPE_IP:

        DecodeIP(p->pkt + dataoff, cap_len, p, snaplen);
        return;

    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
        return;

    case ETHERNET_TYPE_8021Q:
        DecodeVlan(p->pkt + dataoff, cap_len, p, snaplen);
        return;

    default:
        return;
    }

    return;
}

/*
 * Function: DecodeLinuxSLLPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets)
 *          packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */

#ifdef DLT_LINUX_SLL

void DecodeLinuxSLLPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* the length of the packet */
    unsigned int    cap_len;    /* caplen value */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < SLL_HDR_LEN) {
        return;
    }
    /* lay the ethernet structure over the packet data */
    p->sllh = (SLLHdr *) pkt;

    /* grab out the network type */
    switch (ntohs(p->sllh->sll_protocol)) {
    case ETHERNET_TYPE_IP:
        DecodeIP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p, snaplen);
        return;

    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
        DecodeARP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p, snaplen);
        return;

    case ETHERNET_TYPE_IPV6:
        DecodeIPv6(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p, snaplen);
        return;

    case ETHERNET_TYPE_IPX:
        DecodeIPX(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), snaplen);
        return;

    case LINUX_SLL_P_802_3:
        return;

    case LINUX_SLL_P_802_2:
        return;

    case ETHERNET_TYPE_8021Q:
        DecodeVlan(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p, snaplen);
        return;

    default:
        return;
    }

    return;
}

#endif              /* DLT_LINUX_SLL */

/*
 * Function: DecodePflog(anonpacket *, struct pcap_pkthdr *, unsigned char *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* suprisingly, the length of the packet */
    unsigned int    cap_len;    /* caplen value */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < PFLOG_HDRLEN) {
        return;
    }

    /* lay the pf header structure over the packet data */
    p->pfh = (PflogHdr *) pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch (ntohl(p->pfh->af)) {
    case AF_INET:       /* IPv4 */

        DecodeIP(p->pkt + PFLOG_HDRLEN, cap_len - PFLOG_HDRLEN, p, snaplen);
        return;

#ifdef AF_INET6
    case AF_INET6:      /* IPv6 */
        return;
#endif

    default:
        /* To my knowledge, pflog devices can only
         * pass IP and IP6 packets. -fleck
         */
        return;
    }

    return;
}

/*
 * Function: DecodePPPoEPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoEPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    pkt_len;    /* suprisingly, the length of the packet */
    unsigned int    cap_len;    /* caplen value */
    PPPoEHdr       *ppppoep = 0;
    PPPoE_Tag      *ppppoe_tag = 0;
    PPPoE_Tag       tag;    /* needed to avoid alignment problems */

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if ((unsigned int)snaplen < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if (p->pkth->caplen < ETHERNET_HEADER_LEN) {

        return;
    }

    p->eh = (EtherHdr *) pkt;

    ppppoep = (PPPoEHdr *) pkt;

    /* grab out the network type */
    switch (ntohs(p->eh->ether_type)) {
    case ETHERNET_TYPE_PPPoE_DISC:

        break;

    case ETHERNET_TYPE_PPPoE_SESS:
        DecodePPPoEPkt(p, pkthdr, pkt, snaplen);
        break;

    default:
        return;
    }

    if (ntohs(p->eh->ether_type) != ETHERNET_TYPE_PPPoE_DISC) {
        DecodePppPkt(p, pkthdr, pkt + 18, snaplen);
        return;
    }

    ppppoe_tag = (PPPoE_Tag *) (pkt + sizeof(PPPoEHdr));

    while (ppppoe_tag < (PPPoE_Tag *) (pkt + pkthdr->caplen)) {
        /* no guarantee in PPPoE spec that ppppoe_tag is aligned at all... */
        memcpy(&tag, ppppoe_tag, sizeof(tag));

        if (ntohs(tag.length) > 0) {
        }

        ppppoe_tag = (PPPoE_Tag *) ((char *)(ppppoe_tag + 1) + ntohs(tag.length));
    }

    return;
}

/*
 * Function: DecodePppPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decoded PPP traffic
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    len;
    unsigned int    cap_len;
    struct ppp_header *ppphdr;

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;
    ppphdr = (struct ppp_header *)pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    /* do a little validation */
    if (cap_len < PPP_HDRLEN) {
        return;
    }

    /*
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (ntohs(ppphdr->protocol)) {
    case PPP_VJ_COMP:
        break;
    case PPP_VJ_UCOMP:
        /* VJ compression modifies the protocol field. It must be set
         * to tcp (only TCP packets can be VJ compressed) */
        if (cap_len < PPP_HDRLEN + IP_HEADER_LEN) {
            return;
        }

        ((IPHdr *) (p->pkt + PPP_HDRLEN))->ip_proto = IPPROTO_TCP;
        /* fall through */

    case PPP_IP:
        DecodeIP(p->pkt + PPP_HDRLEN, cap_len - PPP_HDRLEN, p, snaplen);
        break;

    case PPP_IPX:
        DecodeIPX(p->pkt + PPP_HDRLEN, cap_len - PPP_HDRLEN, snaplen);
        break;
    }
}

/*
 * Function: DecodeSlipPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    unsigned int    len;
    unsigned int    cap_len;

    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    len = pkthdr->len;
    cap_len = pkthdr->caplen;

    /* do a little validation */
    if (cap_len < SLIP_HEADER_LEN) {
        return;
    }

    DecodeIP(p->pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, p, snaplen);
}

/*
 * Function: DecodeRawPkt(anonpacket *, struct pcap_pkthdr *, unsigned char *, int)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP. Originally
 * written by Jed Pickle.
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *            snaplen => number of bytes in the packet from pcap hdr
 *
 * Returns: Nothing
 */
void DecodeRawPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DecodeIP(pkt, p->pkth->caplen, p, snaplen);

    return;
}

/*
 * DecodeRawPkt6(anonpacket *, struct pcap_pkthdr *, unsigned char *, int)
 *
 * Returns: Nothing
 */
void DecodeRawPkt6(anonpacket *p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt  = pkt;

    DecodeIPv6(pkt, p->pkth->caplen, p, snaplen);

    return;
}

/*
 * Function: DecodeI4LRawIPPkt(anonpacket *, char *, struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LRawIPPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt, int snaplen)
{
    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DecodeIP(pkt + 2, p->pkth->len - 2, p, snaplen);

    return;
}

/*
 * Function: DecodeI4LCiscoIPPkt(anonpacket *, char *,
 *                               struct pcap_pkthdr*, unsigned char*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LCiscoIPPkt(anonpacket * p, struct pcap_pkthdr *pkthdr, unsigned char *pkt,
             int snaplen)
{
    memset(p, 0, sizeof(*p));

    p->pkth = pkthdr;
    p->pkt = pkt;

    DecodeIP(pkt + 4, p->pkth->caplen - 4, p, snaplen);

    return;
}

/*
 * Function: DecodeIP(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */
void DecodeIP(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    unsigned int    ip_len; /* length from the start of the ip hdr to the
                 * pkt end */
    unsigned int    hlen;   /* ip header length */
//    unsigned short int csum;             /* checksum */

    /* lay the IP struct over the raw data */
    p->iph = (IPHdr *) pkt;

    /* do a little validation */
    if (len < IP_HEADER_LEN) {
        p->iph = NULL;

        return;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (IP_VER(p->iph) != 4) {
        p->iph = NULL;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);
    /* set the IP header length */
    hlen = IP_HLEN(p->iph) << 2;

    /* header length sanity check */
    if (hlen < IP_HEADER_LEN) {
        /* XXX: this is a bogus packet, perhaps we should generate an alert */

        p->iph = NULL;
        return;
    }

    if (ip_len != len) {
        if (ip_len > len) {
            ip_len = len;
        } else {
        }
    }

    if (ip_len < hlen) {
        p->iph = NULL;
        return;
    }

    /* test for IP options */
    p->ip_options_len = hlen - IP_HEADER_LEN;

    if (p->ip_options_len > 0) {
        p->ip_options_data = pkt + IP_HEADER_LEN;
        DecodeIPOptions((pkt + IP_HEADER_LEN), p->ip_options_len, p, snaplen);
    } else {
        p->ip_option_count = 0;
    }

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */
    p->rf = (unsigned char)((p->frag_offset & 0x8000) >> 15);
    p->df = (unsigned char)((p->frag_offset & 0x4000) >> 14);
    p->mf = (unsigned char)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if (p->frag_offset || p->mf) {
        /* set the packet fragment flag */
        p->frag_flag = 1;
    }

    /* if this packet isn't a fragment */
    if (!(p->frag_flag)) {
        /* set the packet fragment flag */
        p->frag_flag = 0;

        switch (p->iph->ip_proto) {
        case IPPROTO_TCP:
            DecodeTCP(pkt + hlen, ip_len, p, snaplen);
            return;

        case IPPROTO_UDP:
            DecodeUDP(pkt + hlen, ip_len, p, snaplen);
            return;

        case IPPROTO_ICMP:
            DecodeICMP(pkt + hlen, ip_len, p, snaplen);
            return;

        default:

            p->data = pkt + hlen;
            p->dsize = (unsigned int)ip_len;
            return;
        }
    } else {
        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (unsigned int)ip_len;
    }
}

/**
 * @name DecodeIPv6
 *
 * @brief Decodes IPv6 headers.
 *
 * @param pkt [in] pointer to the packet data
 * @param len [in] length of packet data buffer
 * @param p   [in] pointer to anonpacket structure
 * @param snaplen [in] length of packet from pcap header
 *
 * @return Nothing
 */
void DecodeIPv6(unsigned char *pkt, const unsigned int len, anonpacket *p, int snaplen)
{
    IPv6Hdr     *hdr = (IPv6Hdr *)pkt;
    uint32_t    payload_len;

    if(len < IPV6_HDR_LEN) {
        p->ipv6_hdr = NULL;
        return;
    }

    if(hdr->ipv6_vfc >> 4 != 6) {
        p->ipv6_hdr = NULL;
        return;
    }

    if(hdr->ipv6_next == IPPROTO_IPIP
    || hdr->ipv6_next == IPPROTO_IPV6
    || hdr->ipv6_next == IPPROTO_GRE) {
        /* Multiple encapsulation in packet */
        return;
    } else {
        /*
         * Encapsulated packet.
         * Save the 'outer' headers and proceed.
         */
    }

    payload_len = ntohs(hdr->ipv6_plen) + IPV6_HDR_LEN;

    if(payload_len > len) {
        return;
    }

    /* Lay the IP struct over data */
    p->ipv6_hdr = (IPv6Hdr *) pkt;

    /* TODO */
}


/*
 * Function: DecodeIPOnly(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the IP network layer but not recurse
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
int DecodeIPOnly(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    unsigned int    ip_len; /* length from the start of the ip hdr to the
                 * pkt end */
    unsigned int    hlen;   /* ip header length */

    /* lay the IP struct over the raw data */
    p->orig_iph = (IPHdr *) pkt;

    /* do a little validation */
    if (len < IP_HEADER_LEN) {
        p->orig_iph = NULL;
        return (0);
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (IP_VER(p->orig_iph) != 4) {

        p->orig_iph = NULL;

        return (0);
    }

    /* set the IP datagram length */
    ip_len = ntohs(p->orig_iph->ip_len);

    /* set the IP header length */
    hlen = IP_HLEN(p->orig_iph) << 2;

    if (len < hlen) {

        p->orig_iph = NULL;

        return (0);
    }

    p->ip_option_count = 0;

    /* set the remaining packet length */
    ip_len = len - hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->orig_iph->ip_off);

    /* get the values of the reserved, more
     * fragments and don't fragment flags
     */
    p->rf = (unsigned char)(p->frag_offset & 0x8000) >> 15;
    p->df = (unsigned char)(p->frag_offset & 0x4000) >> 14;
    p->mf = (unsigned char)(p->frag_offset & 0x2000) >> 13;

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if (p->frag_offset || p->mf) {
        /* set the packet fragment flag */
        p->frag_flag = 1;

        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (unsigned int)ip_len;
    } else {
        p->frag_flag = 0;

        switch (p->orig_iph->ip_proto) {
        case IPPROTO_TCP:   /* decode the interesting part of the header */
            if (ip_len > 4) {
                p->orig_tcph = (TCPHdr *) (pkt + hlen);

                /* stuff more data into the printout data struct */
                p->orig_sp = ntohs(p->orig_tcph->th_sport);
                p->orig_dp = ntohs(p->orig_tcph->th_dport);
            }

            break;

        case IPPROTO_UDP:
            if (ip_len > 4) {
                p->orig_udph = (UDPHdr *) (pkt + hlen);

                /* fill in the printout data structs */
                p->orig_sp = ntohs(p->orig_udph->uh_sport);
                p->orig_dp = ntohs(p->orig_udph->uh_dport);
            }

            break;

        case IPPROTO_ICMP:
            if (ip_len > 4) {
                p->orig_icmph = (ICMPHdr *) (pkt + hlen);
            }

            break;
        }
    }

    return (1);
}

/*
 * Function: DecodeSCTP(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the SCTP transport layer.
 *
 * Arguments:   pkt => pointer to the packet data
 *      len => length from pkt to the end of the packet
 *      p   => pointer to packet decoding structure
 *
 * Returns: void
 */
void DecodeSCTP(unsigned char *pkt, const unsigned int len, anonpacket *p, int snaplen)
{
    /* TODO */

    return;
}

/*
 * Function: DecodeTCP(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
void DecodeTCP(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    struct pseudoheader {   /* pseudo header for TCP checksum calculations */
        unsigned int    sip, dip;   /* IP addr */
        unsigned char   zero;   /* checksum placeholder */
        unsigned char   protocol;   /* protocol number */
        unsigned int    tcplen; /* tcp packet length */
    };
    unsigned int    hlen;   /* TCP header length */
//    u_short csum;              /* checksum */
//    struct pseudoheader ph;    /* pseudo header declaration */

    if (len < 20) {

        p->tcph = NULL;
        return;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = (TCPHdr *) pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(p->tcph) << 2;

    if (hlen < 20) {

        p->tcph = NULL;

        return;
    }

    /* if options are present, decode them */
    p->tcp_options_len = hlen - 20;

    if (p->tcp_options_len > 0) {

        p->tcp_options_data = pkt + 20;
        DecodeTCPOptions((unsigned char *)(pkt + 20), p->tcp_options_len, p, snaplen);
    } else {
        p->tcp_option_count = 0;
    }

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);

    /* set the data pointer and size */
    p->data = (unsigned char *)(pkt + hlen);

    if (hlen < len) {
        p->dsize = (unsigned int)(len - hlen);
    } else {
        p->dsize = 0;
    }

}

/*
 * Function: DecodeUDP(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeUDP(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    struct pseudoheader {
        unsigned int    sip, dip;
        unsigned char   zero;
        unsigned char   protocol;
        unsigned int    udplen;
    };
//    u_short csum;
//    struct pseudoheader ph;

    if (len < sizeof(UDPHdr)) {

        p->udph = NULL;

        return;
    }

    /* set the ptr to the start of the UDP header */
    p->udph = (UDPHdr *) pkt;

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

    p->data = (unsigned char *)(pkt + UDP_HEADER_LEN);

    if ((len - UDP_HEADER_LEN) > 0) {
        p->dsize = (unsigned int)(len - UDP_HEADER_LEN);
    } else {
        p->dsize = 0;
    }
}

/*
 * Function: DecodeICMP(unsigned char *, const unsigned int, anonpacket *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
void DecodeICMP(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
//    unsigned short int csum;
    unsigned int    orig_p_caplen;

    if (len < ICMP_HEADER_LEN) {

        p->icmph = NULL;
        return;
    }

    /* set the header ptr first */
    p->icmph = (ICMPHdr *) pkt;

    switch (p->icmph->type) {
    case ICMP_ECHOREPLY:
    case ICMP_DEST_UNREACH:
    case ICMP_SOURCE_QUENCH:
    case ICMP_REDIRECT:
    case ICMP_ECHO:
    case ICMP_ROUTER_ADVERTISE:
    case ICMP_ROUTER_SOLICIT:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
        if (len < 8) {
            p->icmph = NULL;

            return;
        }

        break;

    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        if (len < 20) {
            p->icmph = NULL;
            return;
        }

        break;

    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        if (len < 12) {
            p->icmph = NULL;
            return;
        }

        break;
    }

    p->dsize = (unsigned int)(len - ICMP_HEADER_LEN);
    p->data = pkt + ICMP_HEADER_LEN;

    switch (p->icmph->type) {
    case ICMP_ECHOREPLY:
        /* setup the pkt id ans seq numbers */
        p->dsize -= sizeof(struct idseq);
        p->data += sizeof(struct idseq);
        break;

    case ICMP_ECHO:
        /* setup the pkt id and seq numbers */
        p->dsize -= sizeof(struct idseq);   /* add the size of the
                             * echo ext to the data
                             * ptr and subtract it
                             * from the data size */
        p->data += sizeof(struct idseq);
        break;

    case ICMP_DEST_UNREACH:
    {
        /* if unreach packet is smaller than expected! */
        if (len < 16) {

            /* if it is less than 8 we are in trouble */
            if (len < 8)
                break;
        }

        orig_p_caplen = len - 8;

    }

        break;

    case ICMP_REDIRECT:
    {
        /* if unreach packet is smaller than expected! */
        if (p->dsize < 28) {
            if (p->dsize < 8)
                break;
        }

        orig_p_caplen = p->dsize - 8;

    }

        break;
    }

    return;
}

/*
 * Function: DecodeARP(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeARP(unsigned char *pkt, unsigned int len, anonpacket * p, int snaplen)
{

    p->ah = (EtherARP *) pkt;

    if (len < sizeof(EtherARP)) {
        return;
    }

    return;
}

/*
 * Function: DecodeEapol(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Decode 802.1x eapol stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapol(unsigned char *pkt, unsigned int len, anonpacket * p, int snaplen)
{
    p->eplh = (EtherEapol *) pkt;
    if (len < sizeof(EtherEapol)) {

        return;
    }
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p, snaplen);
    } else if (p->eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p, snaplen);
    }
    return;
}

/*
 * Function: DecodeEapolKey(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapolKey(unsigned char *pkt, unsigned int len, anonpacket * p, int snaplen)
{
    p->eapolk = (EapolKey *) pkt;
    if (len < sizeof(EapolKey)) {

        return;
    }

    return;
}

/*
 * Function: DecodeEAP(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEAP(unsigned char *pkt, const unsigned int len, anonpacket * p, int snaplen)
{
    p->eaph = (EAPHdr *) pkt;
    if (len < sizeof(EAPHdr)) {
        return;
    }
    if (p->eaph->code == EAP_CODE_REQUEST || p->eaph->code == EAP_CODE_RESPONSE) {
        p->eaptype = pkt + sizeof(EAPHdr);
    }
    return;
}

/*
 * Function: DecodeIPX(unsigned char *, unsigned int)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(unsigned char *pkt, unsigned int len, int snaplen)
{
    return;
}

/*
 * Function: DecodeTCPOptions(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeTCPOptions(unsigned char *o_list, unsigned int o_len, anonpacket * p, int snaplen)
{
    unsigned char  *option_ptr;
    unsigned int    bytes_processed;
    unsigned int    current_option;
    unsigned char   done = 0;

    if (TCP_OFFSET(p->tcph) == 5)
        return;

    option_ptr = o_list;
    bytes_processed = 0;
    current_option = 0;

    while ((bytes_processed < o_len) && (current_option < 40) && !done) {
        p->tcp_options[current_option].code = *option_ptr;

        switch (*option_ptr) {
        case TCPOPT_NOP:
        case TCPOPT_EOL:
            if (*option_ptr == TCPOPT_EOL)
                done = 1;

            p->tcp_options[current_option].len = 0;
            p->tcp_options[current_option].data = NULL;
            bytes_processed++;
            current_option++;
            option_ptr++;

            break;

        case TCPOPT_SACKOK:
            p->tcp_options[current_option].len = 0;
            p->tcp_options[current_option].data = NULL;
            bytes_processed += 2;
            option_ptr += 2;
            current_option++;
            break;

        case TCPOPT_WSCALE:
            p->tcp_options[current_option].len = 3;
            p->tcp_options[current_option].data = option_ptr + 2;
            option_ptr += 3;
            bytes_processed += 3;
            current_option++;
            break;

        default:
            p->tcp_options[current_option].len = *(option_ptr + 1);

            if (p->tcp_options[current_option].len > 40) {
                p->tcp_options[current_option].len = 40;
            } else if (p->tcp_options[current_option].len == 0) {
                /* got a bad option, we're all done */
                done = 1;
                p->tcp_lastopt_bad = 1;
            }

            p->tcp_options[current_option].data = option_ptr + 2;
            option_ptr += p->tcp_options[current_option].len;
            bytes_processed += p->tcp_options[current_option].len;
            current_option++;
            break;
        }
    }

    if (bytes_processed > o_len) {
        p->tcp_options[current_option].len =
            p->tcp_options[current_option].len - (bytes_processed - o_len);
        /*
         * in reality shouldn't happen until we got the option type and len
         * on the packet header boundary.. then we just drop last option (as
         * it is corrupted anyway).
         */
/*        if(p->tcp_options[current_option].len < 0)
            current_option--;
*/
    }

    p->tcp_option_count = current_option;

    return;
}

/*
 * Function: DecodeIPOptions(unsigned char *, unsigned int, anonpacket *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeIPOptions(unsigned char *o_list, unsigned int o_len, anonpacket * p, int snaplen)
{
    unsigned char  *option_ptr;
    unsigned int    bytes_processed;
    unsigned int    current_option;
    unsigned char   done = 0;

    option_ptr = o_list;
    bytes_processed = 0;
    current_option = 0;

    if (IP_HLEN(p->iph) == 5)
        return;

    while ((bytes_processed < o_len) && (current_option < 40) && !done) {

        p->ip_options[current_option].code = *option_ptr;

        switch (*option_ptr) {
        case IPOPT_RTRALT:
        case IPOPT_NOP:
        case IPOPT_EOL:
            /* if we hit an EOL, we're done */
            if (*option_ptr == IPOPT_EOL)
                done = 1;

            p->ip_options[current_option].len = 0;
            p->ip_options[current_option].data = NULL;
            bytes_processed++;
            current_option++;
            option_ptr++;

            break;

        default:
            p->ip_options[current_option].len = *(option_ptr + 1);

            if (p->ip_options[current_option].len > 40) {
                p->ip_options[current_option].len = 40;
            } else if (p->ip_options[current_option].len == 0) {
                /*
                 * this shouldn't happen, indicates a bad option list
                 * so we bail
                 */
                done = 1;
                p->ip_lastopt_bad = 1;
            }

            p->ip_options[current_option].data = option_ptr + 2;
            option_ptr += p->ip_options[current_option].len;
            bytes_processed += p->ip_options[current_option].len;
            current_option++;
            break;

        }
    }

    if (bytes_processed > o_len) {
        p->ip_options[current_option].len =
            p->ip_options[current_option].len - (bytes_processed - o_len);
/*        if(p->ip_options[current_option].len < 0)
            current_option--;*/
    }

    p->ip_option_count = current_option;

    return;
}

/*
 * Sets root decoder based on datalink.
 *
 * Returns the grinder on success, NULL on error.
 */
grinder_t SetPktProcessor(int datalink)
{
    grinder_t       grinder;

    switch (datalink) {
    case DLT_EN10MB:
        /* Ethernet */
        grinder = DecodeEthPkt;
        break;

#ifdef DLT_IEEE802_11
    case DLT_IEEE802_11:
        grinder = DecodeIEEE80211Pkt;
        break;
#endif
/* TODO IPsec encapsulated packet grinder
 *
#ifdef DLT_ENC
    case DLT_ENC:
        break;
#else
    case 13:
#endif
*/
    case 13:
    case DLT_IEEE802:
        /* Token Ring */
        grinder = DecodeTRPkt;
        break;

    case DLT_FDDI:
        /* FDDI */
        grinder = DecodeFDDIPkt;
        break;

    case DLT_SLIP:
        /* Serial Line Internet Protocol */
        grinder = DecodeSlipPkt;
        break;

    case DLT_PPP:
        /* point-to-point protocol */
        grinder = DecodePppPkt;
        break;

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
        grinder = DecodeLinuxSLLPkt;
        break;
#endif

#ifdef DLT_PFLOG
    case DLT_PFLOG:
        grinder = DecodePflog;
        break;
#endif

#ifdef DLT_LOOP
    case DLT_LOOP:
#endif
    case DLT_NULL:
        grinder = DecodeNullPkt;
        break;

#ifdef DLT_RAW
    case DLT_RAW:
#endif
    case DLT_IPV4:
        grinder = DecodeRawPkt;
        break;

/*  TODO In progress TODO
    case DLT_IPV6:
        grinder = DecodeRawPkt6;
        break;
*/

#ifdef DLT_I4L_RAWIP
    case DLT_I4L_RAWIP:
        grinder = DecodeI4LRawIPPkt;
        break;
#endif
#ifdef DLT_I4L_IP
    case DLT_I4L_IP:
        if (!pv.readmode_flag && !pv.quiet_flag)
            LogMessage("Decoding I4L-ip on interface %s\n",
                   PRINT_INTERFACE(pv.interfaces[num]));

        grinder = DecodeEthPkt;

        break;
#endif

#ifdef DLT_I4L_CISCOHDLC
    case DLT_I4L_CISCOHDLC:
        grinder = DecodeI4LCiscoIPPkt;
        break;
#endif

    default:
        /* Unhandled. */
        fprintf(stderr, "Unable to decode data link type %d\n", datalink);
        return NULL;
    }

    return grinder;
}
