/*
 * Created by Keenon Werling, Sep 27 2013,
 * 
 * a unit testing framework to interact with a mocked transport
 * layer. Include by running "make test".
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <signal.h>

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_unit_test.h"
#include "sr_protocol.h"
#include "sr_utils.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/* Create the outgoing message cache */

uint8_t* last_msg_buf = NULL;
unsigned int last_msg_len = 0;
char* last_msg_iface = NULL;

/* Not worth making a header file for this */

int sr_mock_receive_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */);

/*-----------------------------------------------------------------------------
 * Method: sr_run_unit_tests(..)
 * Scope: global
 *
 * Runs the unit tests against my mocked up transport layer. Here's the story
 * of the tests that we run:
 *
 * We use a dummy host A (ip=10.0.1.1, mac="host_a") and host B (ip=4.3.2.5, mac="host_b"), 
 * sending through our interface eth3 (ip=, mac="eth3ma").
 *
 * Test 1: Just a toy test, try to send a packet that's too short to contain an eth
 * header. Will be dropped. Expect no response.
 *
 * Tests 2,3,4: First, we send a dummy TCP packet to 4.3.2.5, which should be
 * routed through GW 4.3.2.0, which we don't have a mapping for in our ARP
 * cache. This should generate an ARP request on a broadcast MAC address,
 * asking about 4.3.2.0. When we reply with an ARP response containing that
 * mapping, sent to our IP and MAC address, we then expect the waiting packet
 * to be forwarded. Finally, in test 4 we send another packet through the GW
 * 4.3.2.0, and expect it to be forwarded immediately, using the ARP cache
 * entry.
 *
 * Test 5: ARP request to one of our interfaces. Expect an ARP reply, with the
 * MAC address.
 *
 * Test 6: TCP to one of our interfaces. ICMP port unreachable response.
 *
 * Test 7: ICMP ECHO received. Generates an ECHO response.
 *
 * Test 8: ICMP packet that TTL reached 0
 *
 * Test 9: Receive an ETH packet with corrupted checksum. Drop it. Expect no
 * response.
 *
 * Test 10: ICMP packet destination has no forwarding table entry. ICMP host
 * unreachable response.
 *
 * Test 11: ARP request times out after 5 requests, ICMP unreachable sent out
 *
 *---------------------------------------------------------------------------*/

typedef struct sr_unit_test_shared_state {

    /* MAC addresses */

    uint8_t host_a_gw_eth[ETHER_ADDR_LEN];
    uint8_t me_a_eth[ETHER_ADDR_LEN];

    uint8_t host_b_gw_eth[ETHER_ADDR_LEN];
    uint8_t me_b_eth[ETHER_ADDR_LEN];

    /* Broadcast eth for ARP reqs */

    uint8_t broadcast_eth[ETHER_ADDR_LEN];

    /* IPs */

    uint32_t host_a_ip;
    uint32_t me_a_ip;

    uint32_t host_b_ip;
    uint32_t me_b_ip;

    uint32_t host_b_gw_ip;

    uint32_t host_c_ip;

    /* Interfaces */

    char* if_a_name;
    char* if_b_name;

    /* References to our router instance */

    struct sr_instance *sr;

} sr_unit_test_shared_state_t;

/* Setup the shared state for the unit tests, to avoid having to do a bunch of
 * redundant and confusing invention of ETH and MAC addresses for imaginary packets. */

sr_unit_test_shared_state_t *sr_setup_unit_test_shared_state(struct sr_instance *sr) {
    sr_unit_test_shared_state_t* shared_state = malloc(sizeof(sr_unit_test_shared_state_t));

    /* Setup MAC address arrays */

    memcpy(shared_state->host_a_gw_eth,"host_a",ETHER_ADDR_LEN);
    memcpy(shared_state->me_a_eth,"eth0ma",ETHER_ADDR_LEN);

    memcpy(shared_state->host_b_gw_eth,"host_b",ETHER_ADDR_LEN);
    memcpy(shared_state->me_b_eth,"eth3ma",ETHER_ADDR_LEN);

    /* Setup broadcast MAC */

    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        shared_state->broadcast_eth[i] = ~((uint8_t)0);
    }

    /* Parse in the IPs we'll be using */

    struct in_addr host_a_addr;
    struct in_addr host_b_addr;
    struct in_addr host_b_gw_addr;
    struct in_addr host_c_addr;
    
    inet_aton("10.0.1.1",&host_a_addr);
    inet_aton("4.3.2.5",&host_b_addr);
    inet_aton("4.3.2.0",&host_b_gw_addr);
    inet_aton("4.3.0.0",&host_c_addr);

    shared_state->host_a_ip = ((uint32_t)host_a_addr.s_addr);
    shared_state->me_a_ip = sr_get_interface(sr, "eth0")->ip;

    shared_state->host_b_ip = ((uint32_t)host_b_addr.s_addr);
    shared_state->host_b_gw_ip = (uint32_t)host_b_gw_addr.s_addr;
    shared_state->me_b_ip = sr_get_interface(sr, "eth3")->ip;

    shared_state->host_c_ip = (uint32_t)host_c_addr.s_addr;

    /* Create the name of the interfaces we're using */

    shared_state->if_a_name = strdup("eth0");
    shared_state->if_b_name = strdup("eth3");

    /* Drop in our router instance reference */

    shared_state->sr = sr;

    return shared_state;
}

void sr_free_unit_test_shared_state(sr_unit_test_shared_state_t *shared_state) {
    free(shared_state->if_a_name);
    free(shared_state->if_b_name);
    free(shared_state);
}

/**********************************************************
 *                    TEST 1
 ***********************************************************
 * Test a packet that is too short to contain an ethernet header.
 * This should provoke no response. */

int sr_unit_test_1(sr_unit_test_shared_state_t *shared_state) {
    unsigned int test_1_len = 5;
    uint8_t* test_1_buf = malloc(test_1_len);

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "1 - Packet too short to contain ethernet header",
            test_1_buf,
            test_1_len,
            shared_state->if_a_name,
            0, /* we don't want a response */
            NULL,
            0,
            NULL,
            0);

    free(test_1_buf);

    return result;
}

/**********************************************************
 *                    TEST 2
 ***********************************************************
 * Here's a legitimate ethernet header, carrying a TCP packet A->B to
 * an interface we have in the routing table, but don't yet have an ARP
 * cached value for. This should generate an ARP request. In TEST 3, 
 * we'll mock an ARP response, and check that the packet gets sent from 
 * the queue. */

int sr_unit_test_2(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host A
     * to host B, which should forward it through to the gateway 
     * 4.3.2.0 */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_a_gw_eth,
        shared_state->me_a_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_a_ip,
            shared_state->host_b_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* Here's the outgoing ARP packet, requesting the IP addr
     * of host B GW, which will go out through the interface matching
     * host B's IP in out gateway table. */

    sr_constructed_packet_t *outgoing_arp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->broadcast_eth,
        ethertype_arp,

        sr_build_arp_packet(
            shared_state->me_b_ip,
            shared_state->host_b_gw_ip,
            shared_state->me_b_eth,
            shared_state->broadcast_eth,
            arp_op_request,
            NULL
        )
    );

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "2 - TCP forward, but not in ARP cache",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_a_name,
            1,
            outgoing_arp_packet->buf,
            outgoing_arp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_arp_packet);

    return result;
}

/**********************************************************
 *                    TEST 3
 ***********************************************************
 * Here we mock an ARP response to the request that the last test should
 * have generated. We expect that on the receipt of the response, the packet
 * that we buffered from TEST 2 is sent along. */

int sr_unit_test_3(sr_unit_test_shared_state_t *shared_state) {

    /* Here's the incoming ARP packet, giving us the MAC addr
     * of host B */

    sr_constructed_packet_t *incoming_arp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_arp,

        sr_build_arp_packet(
            shared_state->host_b_gw_ip,
            shared_state->me_b_ip,
            shared_state->host_b_gw_eth,
            shared_state->me_b_eth,
            arp_op_reply,
            NULL
        )
    );

    /* Here's our dummy TCP packet, being sent out as soon as we
     * get a reply from host B giving us an Eth address. */
    
    sr_constructed_packet_t *outgoing_tcp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_a_ip,
            shared_state->host_b_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* decrement the TTL field on the packet we just made */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((outgoing_tcp_packet->buf)+sizeof(sr_ethernet_hdr_t)));
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "3 - ARP reply received, forward packet waiting on reply",
            incoming_arp_packet->buf,
            incoming_arp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_tcp_packet->buf,
            outgoing_tcp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_arp_packet);
    sr_free_packet(outgoing_tcp_packet);

    return result;
}

/**********************************************************
 *                    TEST 4
 ***********************************************************
 * Now we test whether we can go look up the existing ARP cache entry for
 * a new incoming packet going out along the same gateway we just did our
 * ARP exchange for. */

int sr_unit_test_4(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host A
     * to host B, which should forward it through to the gateway 
     * 4.3.2.0 */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_a_gw_eth,
        shared_state->me_a_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_a_ip,
            shared_state->host_b_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );
    
    /* Here's our outgoing tcp packet, which is identical except for
     * a change in the ethernet header to forward it to the next hop,
     * and coming out of a different interface, and having a slightly
     * smaller TTL field. */
    
    sr_constructed_packet_t *outgoing_tcp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_a_ip,
            shared_state->host_b_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* decrement the TTL field on the packet we just made */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((outgoing_tcp_packet->buf)+sizeof(sr_ethernet_hdr_t)));
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "4 - Forward packet with ARP cache present",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_a_name,
            1,
            outgoing_tcp_packet->buf,
            outgoing_tcp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_tcp_packet);

    return result;
}

/**********************************************************
 *                    TEST 5
 ***********************************************************
 * Receiving an ARP request to one of our interface IPs, and generating a
 * valid response for it. */

int sr_unit_test_5(sr_unit_test_shared_state_t *shared_state) {

    /* Here's the incoming ARP request packet, asking for our MAC
     * from host B's GW (which is, for the sake of testing, too dumb 
     * to get it from the packets we just sent to it) */

    sr_constructed_packet_t *incoming_arp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->broadcast_eth,
        ethertype_arp,

        sr_build_arp_packet(
            shared_state->host_b_gw_ip,
            shared_state->me_b_ip,
            shared_state->host_b_gw_eth,
            shared_state->broadcast_eth,
            arp_op_request,
            NULL
        )
    );

    /* Reply ARP, back to the GW for host B */

    sr_constructed_packet_t *outgoing_arp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_arp,

        sr_build_arp_packet(
            shared_state->me_b_ip,
            shared_state->host_b_gw_ip,
            shared_state->me_b_eth,
            shared_state->host_b_gw_eth,
            arp_op_reply,
            NULL
        )
    );

    int result = sr_unit_test_packet(shared_state->sr,
            "5 - Receive broadcast ARP request",
            incoming_arp_packet->buf,
            incoming_arp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_arp_packet->buf,
            outgoing_arp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_arp_packet);
    sr_free_packet(outgoing_arp_packet);

    return result;
}

/**********************************************************
 *                    TEST 6
 ***********************************************************
 * Receiving a TCP request to one of our interfaces. This triggers
 * an ICMP port unreachable response. */

int sr_unit_test_6(sr_unit_test_shared_state_t *shared_state) {

    /* Here's a dummy TCP packet to our interface for host B */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->me_b_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );
    
    /* Here's our outgoing icmp packet, with a port unreachable
     * response */
    
    sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->me_b_ip,
            shared_state->host_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_t3_packet(
                ICMP_TYPE_PORT_UNREACHABLE,
                ICMP_CODE_PORT_UNREACHABLE,
                ((uint8_t*)(incoming_tcp_packet->buf))+sizeof(sr_ethernet_hdr_t)
            )
        )
    );

    /* decrement the TTL field on the packet inside the ICMP packet we just made. */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((outgoing_icmp_packet->buf)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)-ICMP_DATA_SIZE));
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    int result = sr_unit_test_packet(shared_state->sr,
            "6 - Receive TCP request, report ICMP port unreachable",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_icmp_packet->buf,
            outgoing_icmp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_icmp_packet);

    return result;
}

/**********************************************************
 *                    TEST 7
 ***********************************************************
 * Receiving a ICMP echo request to one of our interfaces. This triggers
 * an ICMP echo response. */

int sr_unit_test_7(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our incomin icmp packet, with a port unreachable
     * response */
    
    sr_constructed_packet_t *incoming_icmp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->me_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_packet(
                ICMP_TYPE_ECHO_MESSAGE,
                ICMP_CODE_ECHO_MESSAGE,
                NULL
            )
        )
    );

    /* Here's our outgoing icmp packet, with a port unreachable
     * response */
    
    sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->me_b_ip,
            shared_state->host_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_packet(
                ICMP_TYPE_ECHO_REPLY,
                ICMP_CODE_ECHO_REPLY,
                NULL
            )
        )
    );

    int result = sr_unit_test_packet(shared_state->sr,
            "7 - Receive ICMP echo request, make ICMP echo response",
            incoming_icmp_packet->buf,
            incoming_icmp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_icmp_packet->buf,
            outgoing_icmp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_icmp_packet);
    sr_free_packet(outgoing_icmp_packet);

    return result;
}

/**********************************************************
 *                    TEST 8
 ***********************************************************
 * We pass in a TCP packet from host B with 
 * a new incoming packet going out along the same gateway we just did our
 * ARP exchange for. */

int sr_unit_test_8(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host B
     * to host A, which should never make it to an ARP request, because
     * the TTL on this packet is 1, so it dies here. An ICMP expired is
     * sent back to host B (though its gateway in our ARP table). */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->host_a_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* set the TTL field on the packet we just made to 1, then recomput cksum */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((incoming_tcp_packet->buf)+sizeof(sr_ethernet_hdr_t)));
    ip_hdr->ip_ttl = 1;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    /* Here's our outgoing icmp packet, with a timeout response */
    
    sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->me_b_ip,
            shared_state->host_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_packet(
                ICMP_TYPE_TTL_EXCEEDED,
                ICMP_CODE_TTL_EXCEEDED,
                (uint8_t*)ip_hdr
            )
        )
    );

    sr_ip_hdr_t* ip_inside_icmp = (sr_ip_hdr_t*)(outgoing_icmp_packet->buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + 4);
    ip_inside_icmp->ip_ttl = 0;
    ip_inside_icmp->ip_sum = 0;
    ip_inside_icmp->ip_sum = cksum((const void*)ip_inside_icmp,sizeof(sr_ip_hdr_t));

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "8 - TTL timeout generating an ICMP response",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_icmp_packet->buf,
            outgoing_icmp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_icmp_packet);

    return result;
}

/**********************************************************
 *                    TEST 9
 ***********************************************************
 * We pass in a ethernet header with a corrupt checksum.
 * Expect no response. */

int sr_unit_test_9(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host B
     * to host A, which should never make it to an ARP request, because
     * the TTL on this packet is 1, so it dies here. An ICMP expired is
     * sent back to host B (though its gateway in our ARP table). */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->host_a_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* Set the TTL field on the packet we just made to 1, which corrupts the checksum */

    ((sr_ip_hdr_t*)((incoming_tcp_packet->buf)+sizeof(sr_ethernet_hdr_t)))->ip_ttl = 1;

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "9 - Corrupted checksum",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_b_name,
            0,
            NULL,
            0,
            NULL,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);

    return result;
}

/**********************************************************
 *                    TEST 10
 ***********************************************************
 * A dummy TCP packet arrives that we have no forwarding table
 * entry for. Send back an ICMP response that the host is unreachable.
 * We doctor the rtable to make our default IP actually require a full
 * match. */

int sr_unit_test_10(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host B,
     * to some interface that doesn't exist in our routing table. */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->host_a_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* Here's our outgoing icmp packet, with a timeout response */
    
    sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->me_b_ip,
            shared_state->host_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_t3_packet(
                ICMP_TYPE_HOST_UNREACHABLE,
                ICMP_CODE_HOST_UNREACHABLE,
                ((uint8_t*)(incoming_tcp_packet->buf))+sizeof(sr_ethernet_hdr_t)
            )
        )
    );

    /* decrement the TTL field on the packet inside the ICMP packet we just made. */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((outgoing_icmp_packet->buf)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)-ICMP_DATA_SIZE));
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "10 - No forwarding table entry",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_icmp_packet->buf,
            outgoing_icmp_packet->len,
            shared_state->if_b_name,
            0);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_icmp_packet);

    return result;
}

/**********************************************************
 *                    TEST 11
 ***********************************************************
 * A TCP packet arrives for somewhere that isn't responding to ARP
 * requests. We time out the request, and then trigger an ICMP packet,
 * declaring that the host is unreachable. */

int sr_unit_test_11(sr_unit_test_shared_state_t *shared_state) {

    /* Here's our dummy TCP packet, passing through from host A
     * to B (something that isn't in our ARP cache). We time the ARP
     * cache out, and then expect an ICMP host unreachable response. */
    
    sr_constructed_packet_t *incoming_tcp_packet = sr_build_eth_packet(
        shared_state->host_b_gw_eth,
        shared_state->me_b_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->host_b_ip,
            shared_state->host_c_ip,
            ip_protocol_tcp,

            sr_build_dummy_tcp_packet()
        )
    );

    /* Here's our outgoing icmp packet, with a timeout response */
    
    sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
        shared_state->me_b_eth,
        shared_state->host_b_gw_eth,
        ethertype_ip,

        sr_build_ip_packet(
            shared_state->me_b_ip,
            shared_state->host_b_ip,
            ip_protocol_icmp,

            sr_build_icmp_t3_packet(
                ICMP_TYPE_HOST_UNREACHABLE,
                ICMP_CODE_HOST_UNREACHABLE,
                ((uint8_t*)(incoming_tcp_packet->buf))+sizeof(sr_ethernet_hdr_t)
            )
        )
    );

    /* decrement the TTL field on the packet inside the ICMP packet we just made. */

    sr_ip_hdr_t* ip_hdr = ((sr_ip_hdr_t*)((outgoing_icmp_packet->buf)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)-ICMP_DATA_SIZE));
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((const void*)ip_hdr,sizeof(sr_ip_hdr_t));

    /* Run the Unit Test */

    int result = sr_unit_test_packet(shared_state->sr,
            "11 - Timeout cache entry",
            incoming_tcp_packet->buf,
            incoming_tcp_packet->len,
            shared_state->if_b_name,
            1,
            outgoing_icmp_packet->buf,
            outgoing_icmp_packet->len,
            shared_state->if_b_name,
            5);

    /* Cleanup */

    sr_free_packet(incoming_tcp_packet);
    sr_free_packet(outgoing_icmp_packet);

    return result;
}

/* Run the actual unit tests */

void sr_run_unit_tests(struct sr_instance* sr /* borrowed */)
{
    int num_tests = 11;
    int successful_tests = 0;

    puts("\n********\nRUNNING UNIT TESTS\n********\n");

    /* Setup the shared state */

    sr_unit_test_shared_state_t *shared_state = sr_setup_unit_test_shared_state(sr);

    /* Do the actual tests */

    successful_tests += sr_unit_test_1(shared_state);
    successful_tests += sr_unit_test_2(shared_state);
    successful_tests += sr_unit_test_3(shared_state);
    successful_tests += sr_unit_test_4(shared_state);
    successful_tests += sr_unit_test_5(shared_state);
    successful_tests += sr_unit_test_6(shared_state);
    successful_tests += sr_unit_test_7(shared_state);
    successful_tests += sr_unit_test_8(shared_state);
    successful_tests += sr_unit_test_9(shared_state);
    successful_tests += sr_unit_test_10(shared_state);
    successful_tests += sr_unit_test_11(shared_state);

    /* Clean up */

    sr_free_unit_test_shared_state(shared_state);

    /* Output overall test results */

    printf("********\n%i successful tests of %i\n",successful_tests,num_tests);
}

/*-----------------------------------------------------------------------------
 * Method: sr_unit_test_record_sent_msg(..)
 * Scope: global
 *
 * Called by a mocked transport layer, to let us check which message was sent
 * in response to our passing a packed to the router.
 *
 *---------------------------------------------------------------------------*/

void sr_unit_test_record_sent_msg(uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
    /* If for whatever reason we have non-NULL values
     * in our last_msg buffers, free and NULL them */

    sr_clear_last_unit_test();

    /* Copy results into the last sent msg buffer */

    last_msg_len = len;
    last_msg_buf = malloc(len);
    memcpy(last_msg_buf,buf,len);
    last_msg_iface = strdup(iface);
}

/*-----------------------------------------------------------------------------
 * Method: sr_unit_test_packet(..)
 * Scope: private
 *
 * Lets us specify the input packet, and the desired response packet, as well
 * as a title for the test, so that we can do some nice output formatting :)
 *
 *---------------------------------------------------------------------------*/

int sr_unit_test_packet(struct sr_instance* sr /* borrowed */,
        const char* test_name,
        uint8_t* src_buf, /* borrowed */
        unsigned int src_len,
        char* src_iface_name, /* borrowed */
        const int dst_desired, /* whether or not we should expect a response from the router */
        const uint8_t* dst_buf, /* borrowed */
        const unsigned int dst_len,
        const char* dst_iface_name /* borrowed */,
        const int simulate_seconds_before_response)
{
    printf("------------\nTest name: %s\n------------\n",test_name);
    puts("Clearing sent msg buffer.");
    sr_clear_last_unit_test();
    puts("Sending unit test to sr_handlepacket(..)\nThe following is output of the router:\n----");

    sr_mock_receive_packet(sr,
                            src_buf,
                            src_len,
                            src_iface_name);

    if (simulate_seconds_before_response) {
        printf("----");
    }
    else {
        puts("----\n");
    }
    int i;
    for (i = 0; i < simulate_seconds_before_response; i++) {
        puts("\n ** Simulating the passage of a second in the ARP cache. **");

        /* Clear the last-sent timers on all the waiting requests, so they
         * send again the next time we tell them to send */
        
        struct sr_arpreq *req_walker = sr->cache.requests;

        while (req_walker != NULL) {
            req_walker->sent = 0;
            req_walker = req_walker->next;
        }

        /* Run a sweepreqs, as though a second has just passed */

        sr_arpcache_sweepreqs(sr);
    }
    if (simulate_seconds_before_response) {
        puts("----\n");
    }

    if (dst_desired) {
        if (last_msg_buf == NULL) {
            puts(KRED "FAILED. Expected a response, and received none.\n" KWHT);
            return 0;
        }
        else {
            if (dst_len == last_msg_len) {
                if (memcmp(dst_buf,last_msg_buf,dst_len) == 0) {
                    puts(KGRN "PASSED.\n" KWHT);
                    return 1;
                }
                else {
                    puts("Response body didn't match expected response.");

                    /* If the ethernet headers match */

                    if (memcmp(dst_buf,last_msg_buf,sizeof(sr_ethernet_hdr_t)) == 0) {

                        /* If both ethernet headers are carrying an ARP header */

                        if (((sr_ethernet_hdr_t*)dst_buf)->ether_type == htons(ethertype_arp)) {

                            /* check if the ARP headers match */

                            sr_arp_hdr_t* dst_arp = (sr_arp_hdr_t*)(dst_buf + sizeof(sr_ethernet_hdr_t));
                            sr_arp_hdr_t* last_arp = (sr_arp_hdr_t*)(last_msg_buf + sizeof(sr_ethernet_hdr_t));
                            if (memcmp(dst_arp,last_arp,sizeof(sr_arp_hdr_t)) == 0) {
                                /* This should be impossible to reach, unless something fishy happened at the general memcmp */
                                puts(KBLU "PASSED. ARP headers match. *Note: this is a fishy way to pass the test, explore this*\n" KWHT);
                                return 1;
                            }

                            /* if ARP headers don't match, print differences */

                            else {
                                puts(KRED "ARP headers don't match. Printing differences:");

                                if (dst_arp->ar_hrd != last_arp->ar_hrd) {
                                    printf("Desired hardware address %i, sent hardware address %i\n",dst_arp->ar_hrd,last_arp->ar_hrd);
                                }
                                if (dst_arp->ar_pro != last_arp->ar_pro) {
                                    printf("Desired protocol address %x, sent hardware address %x\n",dst_arp->ar_pro,last_arp->ar_pro);
                                }
                                if (dst_arp->ar_hln != last_arp->ar_hln) {
                                    printf("Desired length of hardware address %i, sent length of hardware address %i\n",dst_arp->ar_hln,last_arp->ar_hln);
                                }
                                if (dst_arp->ar_pln != last_arp->ar_pln) {
                                    printf("Desired length of protocol %i, sent length of protocol %i\n",dst_arp->ar_pln,last_arp->ar_pln);
                                }
                                if (dst_arp->ar_op != last_arp->ar_op) {
                                    printf("Desired op code %i, sent op code %i\n",dst_arp->ar_op,last_arp->ar_op);
                                }
                                if (memcmp(dst_arp->ar_sha,last_arp->ar_sha,ETHER_ADDR_LEN) != 0) {
                                    printf("Sender hardware addresses don't match.\n");
                                }
                                if (memcmp(dst_arp->ar_tha,last_arp->ar_tha,ETHER_ADDR_LEN) != 0) {
                                    printf("Target hardware addresses don't match.\n");
                                }
                                if (dst_arp->ar_sip != last_arp->ar_sip) {
                                    printf("Desired sender IP ");
                                    struct in_addr temp_in_addr;
                                    temp_in_addr.s_addr = dst_arp->ar_sip;
                                    printf("%s",inet_ntoa(temp_in_addr));
                                    printf(", sent sender IP ");
                                    temp_in_addr.s_addr = last_arp->ar_sip;
                                    printf("%s\n",inet_ntoa(temp_in_addr));
                                }
                                if (dst_arp->ar_tip != last_arp->ar_tip) {
                                    printf("Desired target IP ");
                                    struct in_addr temp_in_addr;
                                    temp_in_addr.s_addr = dst_arp->ar_tip;
                                    printf("%s",inet_ntoa(temp_in_addr));
                                    printf(", sent target IP ");
                                    temp_in_addr.s_addr = last_arp->ar_tip;
                                    printf("%s\n",inet_ntoa(temp_in_addr));
                                }

                                puts("FAILED\n" KWHT);
                            }
                        }

                        /* If both ethernet headers are carrying an IP header */

                        else if (((sr_ethernet_hdr_t*)dst_buf)->ether_type == htons(ethertype_ip)) {

                            /* check if the IP headers match */

                            sr_ip_hdr_t* dst_ip = (sr_ip_hdr_t*)(dst_buf + sizeof(sr_ethernet_hdr_t));
                            sr_ip_hdr_t* last_ip = (sr_ip_hdr_t*)(last_msg_buf + sizeof(sr_ethernet_hdr_t));
                            if (memcmp(dst_ip,last_ip,sizeof(sr_ip_hdr_t)) == 0) {
                                if (dst_ip->ip_p == ip_protocol_icmp) { /* one byte, no need for htons */
                                    sr_icmp_t3_hdr_t* dst_icmp = (sr_icmp_t3_hdr_t*)(dst_buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                                    sr_icmp_t3_hdr_t* last_icmp = (sr_icmp_t3_hdr_t*)(last_msg_buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                                    if (dst_icmp->icmp_type == 3) {
                                        if (memcmp(dst_icmp,last_icmp,sizeof(sr_icmp_t3_hdr_t)) == 0) {
                                            /* This should be impossible to reach, unless something fishy happened at the general memcmp */
                                            puts(KBLU "PASSED. ICMP type 3 headers match. *Note: this is a fishy way to pass the test, explore this*\n" KWHT);
                                            return 1;
                                        }
                                    }
                                    else {
                                        if (memcmp(dst_icmp,last_icmp,sizeof(sr_icmp_hdr_t)) == 0) {
                                            /* This should be impossible to reach, unless something fishy happened at the general memcmp */
                                            puts(KBLU "PASSED. ICMP headers match. *Note: this is a fishy way to pass the test, explore this*\n" KWHT);
                                            return 1;
                                        }
                                    }

                                    puts(KRED "ICMP headers don't match. Printing differences:");

                                    if (dst_icmp->icmp_type != last_icmp->icmp_type) {
                                        printf("Desired ICMP type %i, sent ICMP type %i\n", dst_icmp->icmp_type, last_icmp->icmp_type);
                                    }
                                    if (dst_icmp->icmp_code != last_icmp->icmp_code) {
                                        printf("Desired ICMP code %i, sent ICMP code %i\n", dst_icmp->icmp_code, last_icmp->icmp_code);
                                    }
                                    if (memcmp(dst_icmp->data,last_icmp->data,ICMP_DATA_SIZE) != 0) {
                                        puts("Desired ICMP body:");
                                        int i;
                                        for (i = 0; i < ICMP_DATA_SIZE; i++) {
                                            printf("%x ",dst_icmp->data[i]);
                                        }
                                        puts("\nsent ICMP body:");
                                        for (i = 0; i < ICMP_DATA_SIZE; i++) {
                                            printf("%x ",last_icmp->data[i]);
                                        }
                                        printf("\n");
                                    }
                                    if (dst_icmp->icmp_type == 3) {
                                        if (dst_icmp->next_mtu != last_icmp->next_mtu) {
                                            printf("Desired next mtu %i, sent next mtu %i\n", dst_icmp->next_mtu, last_icmp->next_mtu);
                                        }
                                    }
                                    puts("FAILED\n" KWHT);
                                }
                                else {
                                    puts(KRED "FAILED. IP contents doesn't match. \n" KWHT);
                                    return 0;
                                }
                            }

                            /* if ARP headers don't match, print differences */

                            else {
                                puts(KRED "IP headers don't match. Printing differences:");

                                if (dst_ip->ip_ttl != last_ip->ip_ttl) {
                                    printf("Desired TTL %i, sent TTL %i\n",dst_ip->ip_ttl,last_ip->ip_ttl);
                                }
                                if (dst_ip->ip_p != last_ip->ip_p) {
                                    printf("Desired protocol %x, sent protocol %x\n",dst_ip->ip_p,last_ip->ip_p);
                                }
                                if (dst_ip->ip_sum != last_ip->ip_sum) {
                                    printf("Desired sum %i, sent sum %x\n",dst_ip->ip_sum,last_ip->ip_sum);
                                }
                                if (dst_ip->ip_src != last_ip->ip_src) {
                                    printf("Desired source IP ");
                                    struct in_addr temp_in_addr;
                                    temp_in_addr.s_addr = dst_ip->ip_src;
                                    printf("%s",inet_ntoa(temp_in_addr));
                                    printf(", sent source IP ");
                                    temp_in_addr.s_addr = last_ip->ip_src;
                                    printf("%s\n",inet_ntoa(temp_in_addr));
                                }
                                if (dst_ip->ip_dst != last_ip->ip_dst) {
                                    printf("Desired target IP ");
                                    struct in_addr temp_in_addr;
                                    temp_in_addr.s_addr = dst_ip->ip_dst;
                                    printf("%s",inet_ntoa(temp_in_addr));
                                    printf(", sent target IP ");
                                    temp_in_addr.s_addr = last_ip->ip_dst;
                                    printf("%s\n",inet_ntoa(temp_in_addr));
                                }

                                puts("FAILED\n" KWHT);
                            }
                        }
                    }
                    else {
                        puts(KRED "Ethernet headers don't match");

                        sr_ethernet_hdr_t* dst_eth = (sr_ethernet_hdr_t*)dst_buf;
                        sr_ethernet_hdr_t* last_eth = (sr_ethernet_hdr_t*)last_msg_buf;

                        if (memcmp(dst_eth->ether_shost,last_eth->ether_shost,ETHER_ADDR_LEN) != 0) {
                            printf("Desired source eth %6s, sent source eth %6s.\n",dst_eth->ether_shost,last_eth->ether_shost);
                        }
                        if (memcmp(dst_eth->ether_dhost,last_eth->ether_dhost,ETHER_ADDR_LEN) != 0) {
                            printf("Desired destination eth %6s, sent destination eth %6s.\n",dst_eth->ether_dhost,last_eth->ether_dhost);
                        }
                        if (dst_eth->ether_type != last_eth->ether_type) {
                            printf("Desired eth type %x, sent eth type %x.\n",dst_eth->ether_type,last_eth->ether_type);
                        }

                        puts("FAILED\n" KWHT);
                    }
                    return 0;
                }
            }
            else {
                puts(KRED "FAILED. Response length didn't match expected response." KWHT);
                return 0;
            }
        }
    }
    else {
        if (last_msg_buf == NULL) {
            puts(KGRN "PASSED.\n" KWHT);
            return 1;
        }
        else {
            puts(KRED "FAILED. Expected no response, and received one.\n" KWHT);
            printf("Response length: %i",last_msg_len);
            return 0;
        }
    }
}

/*-----------------------------------------------------------------------------
 * Method: sr_clear_last_unit_test(..)
 * Scope: private
 *
 * Let us clear a unit test record.
 *
 *---------------------------------------------------------------------------*/

void sr_clear_last_unit_test() {
    if (last_msg_buf != NULL) free(last_msg_buf);
    last_msg_buf = NULL;
    if (last_msg_iface != NULL) free(last_msg_iface);
    last_msg_iface = NULL;
    last_msg_len = 0;
}

