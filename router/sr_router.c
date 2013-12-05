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

    char* temp_ip = ip_to_str(arp_hdr->ar_sip);
    printf("from (network order) %s\n",temp_ip);
    free(temp_ip);

    /* Endianness */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);

    switch (ar_op) {

        /*
         * ARP Request handling
         */

        case arp_op_request:
            puts("received ARP OP request.");

            /* The VNS transport layer shouldn't allow any ARP packets that aren't for our
             * interface, but it's still worth checking, just in case something goes wrong
             * or *gasp* we write a unit test about it */

            struct sr_if* iface = sr_get_interface(sr, interface);
            if (iface->ip == arp_hdr->ar_tip) {

                /* Flip around the source and destination IP, keeping both in network order */

                uint32_t ip_buf = arp_hdr->ar_tip;
                arp_hdr->ar_tip = arp_hdr->ar_sip;
                arp_hdr->ar_sip = ip_buf;

                /* Flip around source and dest MAC on the ETH header */

                uint8_t ether_buf[ETHER_ADDR_LEN];
                memcpy(ether_buf,eth_hdr->ether_shost,ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost,iface->addr,ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost,ether_buf,ETHER_ADDR_LEN);

                /* Flip around eth on ARP header */

                memcpy(ether_buf,arp_hdr->ar_sha,ETHER_ADDR_LEN);
                memcpy(arp_hdr->ar_sha,iface->addr,ETHER_ADDR_LEN);
                memcpy(arp_hdr->ar_tha,ether_buf,ETHER_ADDR_LEN);

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

                    /* Send the packet, which will do the lookup against the ARP table we just filled with the answer */

                    sr_try_send_ip_packet(sr, packet_walker->ip_dst, 0, packet_walker->payload, packet_walker->ip_hdr);

                    /* Remove the reference to the packet on this buffered request */

                    packet_walker->payload = NULL;
                    
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
        uint8_t* packet/* not even a malloc pointer, don't free this */,
        unsigned int len,
        char* interface/* lent */) 
{
    puts("handling IP header");
    sr_ip_hdr_t *ip_hdr;
    struct sr_if* if_dst;

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

    uint16_t cksum_buffer = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;

    if (cksum((const void*)ip_hdr, sizeof(sr_ip_hdr_t)) != cksum_buffer) {
        puts("Checksum is corrupted. Bailing");
        return;
    }

    /* Decrement time to live */

    printf("TTL: %i\n", ip_hdr->ip_ttl);

    /* Recalculate the cksum after changing the TTL */

    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr, sizeof(sr_ip_hdr_t));

    if (ip_hdr->ip_ttl <= 0) {
        puts("Packet TTL expired");

        /* Send out a ICMP TTL expired response */

        sr_try_send_ip_packet(sr, ip_hdr->ip_src, 0,
            sr_build_icmp_t3_packet(
                ICMP_TYPE_TTL_EXCEEDED,
                ICMP_CODE_TTL_EXCEEDED,
                (uint8_t*)ip_hdr
            ),
            NULL
        );

        return;
    }

    /* Check for any IP packets destined for our interfaces */

    if_dst = sr_get_interface_ip (sr, ntohl(ip_dst));
    if (if_dst != 0) {

        puts("IP packet is destined for our interfaces.");

        /* If this IP packet is destined for us */

        switch (ip_hdr->ip_p) {

            /*
             * ICMP handling.
             */

            case ip_protocol_icmp:
                sr_handlepacket_icmp(sr, eth_hdr, ip_hdr, packet + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t), interface);
                return;

            /*
             * TCP and UDP handling, which are both the same
             */

            case ip_protocol_tcp:
            case ip_protocol_udp:
                puts("Received a TCP/UDP request.");
    
                /* Send out a ICMP port unreachable response */

                sr_try_send_ip_packet(sr, ip_hdr->ip_src, ip_hdr->ip_dst,
                    sr_build_icmp_t3_packet(
                        ICMP_TYPE_PORT_UNREACHABLE,
                        ICMP_CODE_PORT_UNREACHABLE,
                        (uint8_t*)ip_hdr
                    ),
                    NULL
                );

                return;
        }

        puts("IP packet protocol unsupported. Dropping packet.");
        return;
    }

    /* Build a packet struct to pass in the contents of the IP we're forwarding */

    uint8_t* payload_buf = ((uint8_t*)packet) + sizeof(sr_ip_hdr_t);
    int payload_len = len - sizeof(sr_ip_hdr_t);

    sr_constructed_packet_t *payload = sr_grow_or_create_payload(NULL, payload_len);
    memcpy(payload->buf, payload_buf, payload_len);

    /* Handles checking the routing table, and making any ARP requests we need to make */

    sr_try_send_ip_packet(sr, ip_hdr->ip_dst, 0, payload, ip_hdr);
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket_icmp(sr_icmp_hdr_t *icmp_hdr)
 * Scope:  Private
 *
 * This method processes a ICMP bundle
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket_icmp(struct sr_instance* sr,
        sr_ethernet_hdr_t *eth_hdr,
        sr_ip_hdr_t *ip_hdr,
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
        puts("Got ICMP header");

        if (icmp_hdr->icmp_type == ICMP_TYPE_ECHO_MESSAGE && icmp_hdr->icmp_code == ICMP_CODE_ECHO_MESSAGE) {

            puts("Responding to ECHO request");

            /* Send out a ICMP port unreachable response 
             * from the same IP that was asked about the original
             * values */

            sr_try_send_ip_packet(sr, ip_hdr->ip_src, ip_hdr->ip_dst,
                sr_build_icmp_packet(
                    ICMP_TYPE_ECHO_REPLY,
                    ICMP_CODE_ECHO_REPLY,
                    icmp_hdr->icmp_identifier,
                    icmp_hdr->icmp_seqno
                ),
                NULL
            );
        }
    }
}

/* Handles looking up a MAC address in our ARP cache, and making any ARP requests necessary
 * to send a packet along IP */

void sr_try_send_ip_packet(struct sr_instance* sr,
        uint32_t ip_dst, /* network order */
        uint32_t ip_src, /* optional value - 0 to deactivate */
        sr_constructed_packet_t *payload,
        sr_ip_hdr_t *ip_hdr)
{
    /* Check for longest match in routing table */

    struct sr_rt* rt_dst = sr_rt_longest_match(sr,ip_dst);

    /* If we found any matches, forward the packet */

    if (rt_dst != 0) {

        char* temp_ip = ip_to_str(rt_dst->gw.s_addr);
        printf("Forwarding IP packet to %s\n",temp_ip);
        free(temp_ip);

        /* Grab the interface we'll be sending the packet out through */

        struct sr_if* gw_if = sr_get_interface(sr, rt_dst->interface);

        /* Lookups in the ARP cache keep IP addresses in network byte order, so we need to convert. */

        struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), rt_dst->gw.s_addr);

        /* Check whether or not we're overriding the source of the packet */

        temp_ip = ip_to_str(ip_src);
        printf("Overriding src IP: %s\n",temp_ip);
        free(temp_ip);

        if (ip_src == 0) {
            ip_src = gw_if->ip;
        }

        if (entry) {

            puts("ARP cache entry exists.");

            /* use next_hop_ip->mac mapping in entry to send the packet */
            
            sr_constructed_packet_t *ip_packet = sr_build_eth_packet(
                gw_if->addr, /* src */
                entry->mac, /* dst */
                ethertype_ip,

                sr_build_ip_packet(
                    ip_src, /* src */
                    ip_dst, /* dst */
                    ip_protocol_icmp,

                    payload
                )
            );

            /* If they pass in an ip header, lets copy it over */

            if (ip_hdr != NULL) {
                puts("Copying passed in IP header\n");

                /* Now let's copy it over */

                sr_ip_hdr_t* ip_hdr_buf = (sr_ip_hdr_t*)(ip_packet->buf + sizeof(sr_ethernet_hdr_t));
                memcpy(ip_hdr_buf, ip_hdr, sizeof(sr_ip_hdr_t));
            }

            /* Send out the packet we just built */

            sr_send_packet(sr, (uint8_t*)ip_packet->buf, ip_packet->len, rt_dst->interface);

            /* Cleanup */

            free(entry);
            sr_free_packet(ip_packet);
        }
        else {

            puts("ARP cache entry doesn't exist. Queuing the packet contents.");

            /* We don't free the payload, because it gets put directly into the queue */

            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, rt_dst->gw.s_addr, ip_dst, payload, ip_hdr, rt_dst->interface);
            sr_handle_arpreq(sr,req);
        }

        return;
    }

    /* If we get here, it means that it's not for us, and there's noone to forward it to.
     * Thus, it's time for some ICMP, if we were trying to send an IP request.
     */

    puts("Nothing in the forwarding table for the destination IP.");

    /* If ip_hdr == NULL, then we were sending this packet out, and there's no reason to
     * respond to ourselves with an ICMP host unreachable error.
     */

    if (ip_hdr != NULL) {
        puts("Was an IP packet (as expected). Checking if its an ICMP error, which we'll drop.");

        /* Free the payload we won't be using */

        sr_free_packet(payload);

        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type == 3) { /* Don't foward anything with type 3 */
                puts("Was an ICMP error. Dropping.");
                return;
            }
        }
        else {
            puts("Wasn't ICMP.");
        }

        puts("Wasn't an ICMP error.");

        /* Recurse to send this packet back */

        sr_try_send_ip_packet(sr, ip_hdr->ip_src, ip_hdr->ip_dst,
            sr_build_icmp_t3_packet(
                ICMP_TYPE_HOST_UNREACHABLE,
                ICMP_CODE_HOST_UNREACHABLE,

                /* reconstruct the original IP packet */

                (uint8_t*)ip_hdr
            ),
            NULL
        );
    }
}

/* Creates an ethernet header on a payload, returning the newly enlarged packet */

sr_constructed_packet_t *sr_build_eth_packet(uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t ether_dhost[ETHER_ADDR_LEN], uint16_t ether_type, sr_constructed_packet_t* payload) {
    sr_constructed_packet_t* eth_packet = sr_grow_or_create_payload(payload, sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(eth_packet->buf);

    memcpy(eth_hdr->ether_dhost,ether_dhost,ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost,ether_shost,ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ether_type);

    return eth_packet;
}

/* Creates an ARP header, potentially containing a payload, and returns the packet */

sr_constructed_packet_t *sr_build_arp_packet(uint32_t ip_src, uint32_t ip_dst, uint8_t ether_shost[ETHER_ADDR_LEN], uint8_t ether_dhost[ETHER_ADDR_LEN], unsigned short ar_op, sr_constructed_packet_t* payload) {
    sr_constructed_packet_t* arp_packet = sr_grow_or_create_payload(payload, sizeof(sr_arp_hdr_t));

    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(arp_packet->buf);

    arp_hdr->ar_hrd = htons(1); /* Ethernet hardware */
    arp_hdr->ar_pro = htons(0x0800); /* IPv4 */
    arp_hdr->ar_hln = 6; /* 6 byte ethernet addrs */
    arp_hdr->ar_pln = 4; /* 4 byte IP addrs */

    arp_hdr->ar_sip = ip_src;
    arp_hdr->ar_tip = ip_dst;
    arp_hdr->ar_op = htons(ar_op);

    memcpy(arp_hdr->ar_sha,ether_shost,ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha,ether_dhost,ETHER_ADDR_LEN);

    return arp_packet;
}

/* Creates an IP header, returning the packet */

sr_constructed_packet_t *sr_build_ip_packet(uint32_t ip_src, uint32_t ip_dst, uint8_t ip_p, sr_constructed_packet_t* payload) {

    sr_constructed_packet_t* ip_packet = sr_grow_or_create_payload(payload, sizeof(sr_ip_hdr_t));

    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(ip_packet->buf);

    /* Fill in values, with due respect for byte order */

    ip_hdr->ip_hl = 0x05; /* 20, because some strange bitfield shennanigans is going on */
    ip_hdr->ip_v = 0x04; /* 4 */
    ip_hdr->ip_src = ip_src;
    ip_hdr->ip_dst = ip_dst;
    ip_hdr->ip_p = ip_p; /* one byte, no need for htons */
    ip_hdr->ip_ttl = (uint8_t)64; /* one byte, no need for htons */
    ip_hdr->ip_len = htons(ip_packet->len);

    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    return ip_packet;
}

/* Creates an ICMP header, returning the packet to this point */

sr_constructed_packet_t *sr_build_icmp_packet(uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_identifier, uint16_t icmp_seqno) {

    sr_constructed_packet_t* icmp_packet = sr_grow_or_create_payload(NULL, sizeof(sr_icmp_hdr_t));

    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(icmp_packet->buf);

    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_identifier = icmp_identifier;
    icmp_hdr->icmp_seqno = icmp_seqno;

    icmp_hdr->icmp_sum = htons(cksum((const void*)icmp_hdr,sizeof(sr_icmp_hdr_t)));

    return icmp_packet;
}


/* Creates an ICMP type 3 header, returning the packet to this point */

sr_constructed_packet_t *sr_build_icmp_t3_packet(uint8_t icmp_type, uint8_t icmp_code, uint8_t* trigger_packet) {

    /* REQUIRES */

    assert(trigger_packet);

    sr_constructed_packet_t* icmp_packet = sr_grow_or_create_payload(NULL, sizeof(sr_icmp_t3_hdr_t));

    sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(icmp_packet->buf);

    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;

    memcpy(icmp_hdr->data, trigger_packet, ICMP_DATA_SIZE);

    icmp_hdr->icmp_sum = htons(cksum((const void*)icmp_hdr,sizeof(sr_icmp_t3_hdr_t)));

    return icmp_packet;
}

/* Creates a dummy packet, purely for testing purposes */

sr_constructed_packet_t *sr_build_dummy_tcp_packet() {
    return sr_grow_or_create_payload(NULL, 64);
}

