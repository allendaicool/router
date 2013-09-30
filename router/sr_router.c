/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    if (len < sizeof(sr_ethernet_hdr_t)) {
        puts("Packet is smaller than an ethernet header. Discarding.");
        return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)packet;

    /* Endianness */
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    switch (ether_type) {

        /* 
         * ARP Implementation 
         */

        case ethertype_arp:
            sr_handlepacket_arp(sr, eth_hdr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
            break;

        /* 
         * IP Implementation
         */

        case ethertype_ip:
            sr_handlepacket_ip(sr, eth_hdr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
            break;

    } /* end switch */
}/* end sr_handlepacket */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp
 * Scope:  Private
 *
 * This method processes an ARP bundle
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket_arp(struct sr_instance* sr,
        sr_ethernet_hdr_t* eth_hdr,
        uint8_t* packet/* not even a malloc pointer */,
        unsigned int len,
        char* interface/* lent */) 
{
    puts("handling ARP header");
    sr_arp_hdr_t *arp_hdr;

    /* REQUIRES */
    assert(packet);

    if (len < sizeof(sr_arp_hdr_t)) {
        puts("Ethernet payload (claiming to contain ARP) is smaller than ARP header. Discarding.");
        return;
    }

    arp_hdr = (sr_arp_hdr_t*)packet;

    struct in_addr ar_from;
    ar_from.s_addr = arp_hdr->ar_sip;
    printf("from (network order) %s\n",inet_ntoa(ar_from));

    /* Endianness */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);

    switch (ar_op) {

        /*
         * ARP Request handling
         */

        case arp_op_request:
            puts("received ARP OP request.");

            /* The VNS transport layer shouldn't allow any packets that aren't for our
             * interface, but it's still worth checking, just in case something goes wrong
             * of *gasp* we write a unit test about it */

            struct sr_if* iface = sr_get_interface(sr, interface);
            if (iface->ip == ntohl(arp_hdr->ar_tip)) {

                /* Flip around the source and destination IP, keeping both in network order */

                uint32_t ip_buf = arp_hdr->ar_tip;
                arp_hdr->ar_tip = arp_hdr->ar_sip;
                arp_hdr->ar_sip = ip_buf;

                /* Flip around source and dest MAC on the ETH header */

                uint8_t ether_buf[ETHER_ADDR_LEN];
                memcpy(ether_buf,eth_hdr->ether_shost,ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost,iface->addr,ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost,ether_buf,ETHER_ADDR_LEN);

                /* Change ARP operation to a reply */

                arp_hdr->ar_op = htons(arp_op_reply);

                /* Send the modified packet back out */

                puts("sending ARP OP reply");
                sr_send_packet(sr, (uint8_t*)eth_hdr, len + sizeof(sr_ethernet_hdr_t), interface);
            }
            else {
                puts("ARP request received that's not for us.");
            }

            break;

        /*
         * ARP Reply handling
         */

        case arp_op_reply:
            puts("received ARP OP reply.");

            /* Insert the new IP->MAC mapping into the cache, using network endianness for IP */

            struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache),eth_hdr->ether_shost,arp_hdr->ar_sip);

            /* If there were requests waiting on this mapping */

            if (req) {
                struct sr_packet* packet_walker = req->packets;
                while (packet_walker) {

                    /* Copy the newly acquired dest MAC address over */

                    sr_ethernet_hdr_t* packet_eth_hdr = (sr_ethernet_hdr_t*)(packet_walker->buf);
                    memcpy(packet_eth_hdr->ether_dhost,eth_hdr->ether_shost,ETHER_ADDR_LEN);

                    /* Send the adjusted packet down the correct interface */

                    sr_send_packet(sr, packet_walker->buf, packet_walker->len, packet_walker->iface);
                    
                    /* Continue walking the linked list */

                    packet_walker = packet_walker->next;
                }

                /* Free the memory associated with these requests */

                sr_arpreq_destroy(&(sr->cache),req);
            }
            else {
                puts("no cached requests waiting on this ARP.");
            }
            break;
    }
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket_ip
 * Scope:  Private
 *
 * This method processes an IP bundle
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket_ip(struct sr_instance* sr,
        sr_ethernet_hdr_t* eth_hdr,
        uint8_t* packet/* not even a malloc pointer */,
        unsigned int len,
        char* interface/* lent */) 
{
    puts("handling IP header");
    sr_ip_hdr_t *ip_hdr;
    struct sr_if* if_dst;
    struct sr_rt* rt_dst;

    /* REQUIRES */
    assert(packet);

    if (len < sizeof(sr_ip_hdr_t)) {
        puts("Ethernet payload (claiming to contain IP) is smaller than IP header. Discarding.");
        return;
    }

    ip_hdr = (sr_ip_hdr_t*)packet;

    /* Endianness */
    uint32_t ip_dst = ntohl(ip_hdr->ip_dst);

    /* Check for a corrupt packet */
    if (sr_ip_packet_checksum(ip_hdr) != ntohs(ip_hdr->ip_sum)) {
        /* TODO: Send an ICMP packet back */
        /* TODO: return */
    }

    /* Decrement time to live */
    printf("TTL: %i\n", ip_hdr->ip_ttl);
    if (ip_hdr->ip_ttl-- <= 0) {
        /* TODO: Send an ICMP packet back */
        puts("Packet TTL expired");
        return;
    }

    /* Check for any IP packets destined for our interfaces */

    if_dst = sr_get_interface_ip (sr, ip_dst);
    if (if_dst != 0) {

        puts("IP packet is destined for our interfaces.");

        /* If this IP packet is destined for us */

        switch (ip_hdr->ip_p) {

            /*
             * ICMP handling.
             */

            case ip_protocol_icmp:
                sr_handlepacket_icmp(sr, packet + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t), interface);
                return;

            /*
             * TCP and UDP handling, which are both the same
             */

            case ip_protocol_tcp:
            case ip_protocol_udp:
                puts("Received a TCP/UDP request.");
                return;
        }

        puts("IP packet protocol unrecognized.");
        return;
    }

    /* Check for longest match in routing table */

    rt_dst = sr_rt_longest_match(sr,ip_dst);

    /* If we found any matches, forward the packet */

    if (rt_dst != 0) {

        printf("Forwarding IP packet to %s\n",inet_ntoa(rt_dst->gw));

        /* Change the source MAC address of the packet to reflect the interface we're sending out through.
         * Otherwise, though, the packet (including ethernet header) is forwarded unchanged. */

        struct sr_if* gw_if = sr_get_interface(sr, rt_dst->interface);
        memcpy(eth_hdr->ether_shost,gw_if->addr,ETHER_ADDR_LEN);

        /* Lookups in the ARP cache keep IP addresses in network byte order, so we need to convert. */

        struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), htonl(rt_dst->gw.s_addr));

        if (entry) {
            /* use next_hop_ip->mac mapping in entry to send the packet */
            puts("ARP cache entry exists");
            memcpy(eth_hdr->ether_dhost,entry->mac,ETHER_ADDR_LEN);
            sr_send_packet(sr, (uint8_t*)eth_hdr, len + sizeof(sr_ethernet_hdr_t), rt_dst->interface);

            free(entry);
        }
        else {
            puts("ARP cache entry doesn't exist. Queuing.");
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, htonl(rt_dst->gw.s_addr), (uint8_t*)eth_hdr, len + sizeof(sr_ethernet_hdr_t), rt_dst->interface);
            sr_handle_arpreq(sr,req);
        }

        return;
    }

    /* If we get here, it means that it's not for us, and there's noone to forward it to.
     * Thus, it's time for some ICMP. 
     */

    puts("Nothing in the forwarding table.");

    /* TODO: Send an ICMP host unreachable error back */
}


/*---------------------------------------------------------------------
 * Method: sr_ip_packet_checksum(sr_ip_hdr_t* ip_hdr)
 * Scope:  Private
 *
 * This method calculates and returns the checksum for an IP header.
 *
 *---------------------------------------------------------------------*/

uint16_t sr_ip_packet_checksum(sr_ip_hdr_t* ip_hdr) {
    return 0;
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket_icmp(sr_icmp_hdr_t *icmp_hdr)
 * Scope:  Private
 *
 * This method processes a ICMP bundle
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket_icmp(struct sr_instance* sr,
        uint8_t* packet/* not even a malloc pointer */,
        unsigned int len,
        char* interface/* lent */) 
{
    puts("handling ICMP header");
    sr_icmp_hdr_t *icmp_hdr;

    /* REQUIRES */
    assert(packet);

    icmp_hdr = (sr_icmp_hdr_t*)packet;

    if (len < sizeof(sr_icmp_hdr_t)) {
        puts("IP payload (claiming to contain ICMP) is smaller than ICMP header. Discarding.");
        return;
    }
    else {
        puts("Got IP payload");
    }
}


/*---------------------------------------------------------------------
 * Method: sr_build_icmp_packet(..)
 * Scope:  global
 *
 * This method builds an ICMP packet complete with IP and ETH headers,
 * ready for transport.
 *
 *---------------------------------------------------------------------*/

uint8_t *sr_build_icmp_packet(
    uint8_t  ether_dhost[ETHER_ADDR_LEN], /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN], /* source ethernet address */
    uint32_t ip_src, /* src address */
    uint32_t ip_dst, /* dest address */
    uint8_t icmp_type,
    uint8_t icmp_code,
    unsigned int* len /* returns the length of the packet */)
{
    *len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t *buf = malloc(*len);

    /* Clear the buf just in case */

    memset(buf,0,*len);

    /* Get the headers in this packet */

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)buf;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Fill in values we care about */

    memcpy(eth_hdr->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost,ether_shost,ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    ip_hdr->ip_src = htonl(ip_src);
    ip_hdr->ip_dst = htonl(ip_dst);
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_ttl = (uint8_t)64; /* one byte, no need for htons */

    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;

    return buf;
}


/*---------------------------------------------------------------------
 * Method: sr_build_arp_packet(..)
 * Scope:  global
 *
 * This method builds an ARP packet complete with IP and ETH headers,
 * ready for transport.
 *
 *---------------------------------------------------------------------*/

uint8_t *sr_build_arp_packet(
    uint8_t  ether_dhost[ETHER_ADDR_LEN], /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN], /* source ethernet address */
    uint32_t ip_src, /* src address */
    uint32_t ip_dst, /* dest address */
    unsigned short ar_op, /* ARP opcode (command) */
    unsigned int* len /* returns the length of the packet */)
{
    *len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = malloc(*len);

    /* Clear the buf just in case */

    memset(buf,0,*len);

    /* Get the headers in this packet */

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)buf;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

    /* Fill in values we care about */

    memcpy(eth_hdr->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost,ether_shost,ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    arp_hdr->ar_sip = htonl(ip_src);
    arp_hdr->ar_tip = htonl(ip_dst);

    arp_hdr->ar_op = htons(ar_op);

    return buf;
}



/*---------------------------------------------------------------------
 * Method: sr_build_dummy_tcp_packer(..)
 * Scope:  global
 *
 * This method builds a TCP packet complete with IP and ETH headers,
 * ready for transport. It only exists for making TCP packets for the
 * Unit Tests, but it makes the most sense for it to live here with the
 * other packets.
 *
 *---------------------------------------------------------------------*/

uint8_t *sr_build_dummy_tcp_packet(
    uint8_t  ether_dhost[ETHER_ADDR_LEN], /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN], /* source ethernet address */
    uint32_t ip_src, /* src address */
    uint32_t ip_dst, /* dest address */
    unsigned int* len /* returns the length of the packet */)
{
    *len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 40; /* we don't actually fill in tcp, we just claim to be tcp */
    uint8_t *buf = malloc(*len);

    /* Clear the buf just in case */

    memset(buf,0,*len);

    /* Get the headers in this packet */

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*)buf;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

    /* Fill in values we care about */

    memcpy(eth_hdr->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost,ether_shost,ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    ip_hdr->ip_src = htonl(ip_src);
    ip_hdr->ip_dst = htonl(ip_dst);
    ip_hdr->ip_p = ip_protocol_tcp;
    ip_hdr->ip_ttl = (uint8_t)64;

    return buf;
}
