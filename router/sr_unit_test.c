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

/*-----------------------------------------------------------------------------
 * Method: sr_run_unit_tests(..)
 * Scope: global
 *
 * Runs the unit tests against my mocked up transport layer. Here's the story
 * of the tests that we run:
 *
 * Test 1: Just a toy test, send a packet that's too short to contain an eth
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
 * -------------------------- TODO below here -----------------------------
 *
 * Test 6: TCP to one of our interfaces. ICMP host unreachable response.
 *
 * Test 7: ICMP ECHO received.
 *
 * Test 8: ICMP packet destination has no forwarding table entry
 *
 * Test 9: ARP request times out after 5 requests, ICMP unreachable
 *
 * Test 10: ICMP packet that TTL reached 0
 *
 * Test 11: Receive an ETH packet with corrupted checksum. Drop it. Expect no
 * response.
 *
 * Test 12: Traceroute to us, expect a valid response.
 *
 *---------------------------------------------------------------------------*/

void sr_run_unit_tests(struct sr_instance* sr /* borrowed */)
{
    int num_tests = 5;
    int successful_tests = 0;

    puts("\n********\nRUNNING UNIT TESTS\n********\n");

    /**********************************************************
     *                    TEST 1
     ***********************************************************
     * Test a packet that is too short to contain an ethernet header.
     * This should provoke no response. */

    unsigned int test_1_len = 5;
    uint8_t* test_1_buf = malloc(test_1_len);
    char* test_1_iface_name = "eth0";

    /* Run the Unit Test */

    successful_tests += sr_unit_test_packet(sr,
            "1 - Packet too short to contain ethernet header",
            test_1_buf,
            test_1_len,
            test_1_iface_name,
            0, /* we don't want a response */
            NULL,
            0,
            NULL);

    free(test_1_buf);

    /**********************************************************
     *                    TEST 2
     ***********************************************************
     * Here's a legitimate ethernet header, carrying a TCP packet onward to
     * an interface we have in the routing table, but don't yet have an ARP
     * cached value for. This should generate an ARP request. In TEST 3, 
     * we'll mock an ARP response, and check that the packet gets sent from 
     * the queue. */

    unsigned int test_2_len = 0;

    uint8_t test_2_dest_eth[ETHER_ADDR_LEN];
    uint8_t test_2_src_eth[ETHER_ADDR_LEN];
    memcpy(test_2_dest_eth,"eth3ma",ETHER_ADDR_LEN);
    memcpy(test_2_src_eth,"fedcba",ETHER_ADDR_LEN);

    struct in_addr test_2_src_addr;
    struct in_addr test_2_dest_addr;
    struct in_addr test_2_gw_addr;
    
    inet_aton("10.0.1.1",&test_2_src_addr);
    inet_aton("4.3.2.5",&test_2_dest_addr);
    inet_aton("4.3.2.0",&test_2_gw_addr);

    /* Here's our dummy TCP packet, passing through to 4.3.2.5,
     * which should forward it through to the gateway 4.3.2.0 */

    uint8_t* test_2_buf = sr_build_dummy_tcp_packet(
        test_2_dest_eth, /* destination ethernet address */
        test_2_src_eth, /* source ethernet address */
        (uint32_t)test_2_src_addr.s_addr, /* src address */
        (uint32_t)test_2_dest_addr.s_addr, /* dest address */
        &test_2_len /* returns the length of the packet */);

    char* test_2_iface_name = "eth0";

    /* Here's the ARP request that we expect to be generated */

    uint8_t ether_broadcast[ETHER_ADDR_LEN];
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        ether_broadcast[i] = ~((uint8_t)0);
    }

    unsigned int test_2_result_len;

    uint8_t *test_2_result_buf = sr_build_arp_packet(
        ether_broadcast, /* destination ethernet address */
        test_2_dest_eth, /* source ethernet address */
        *((uint32_t*)sr->host), /* src address */
        (uint32_t)test_2_gw_addr.s_addr, /* dest address */
        arp_op_request, /* ARP opcode (command) */
        &test_2_result_len /* returns the length of the constructed packet */);

    char* test_2_result_iface_name = "eth3";

    /* Run the Unit Test */

    successful_tests += sr_unit_test_packet(sr,
            "2 - TCP forward, but not in ARP cache",
            test_2_buf,
            test_2_len,
            test_2_iface_name,
            1,
            test_2_result_buf,
            test_2_result_len,
            test_2_result_iface_name);

    /**********************************************************
     *                    TEST 3
     ***********************************************************
     * Here we mock an ARP response to the request that the last test should
     * have generated. We expect that on the receipt of the response, the packet
     * that we buffered from TEST 2 is sent along. */

    unsigned int test_3_len = 0;

    uint8_t test_3_dummy_eth[ETHER_ADDR_LEN];
    char* temp = "hellow"; 
    memcpy(test_3_dummy_eth,temp,ETHER_ADDR_LEN);

    uint8_t *test_3_buf = sr_build_arp_packet(
        test_2_src_eth, /* destination ethernet address */
        test_3_dummy_eth, /* source ethernet address */
        (uint32_t)test_2_gw_addr.s_addr, /* src address */
        *((uint32_t*)sr->host), /* dest address */
        arp_op_reply, /* ARP opcode (command) */
        &test_3_len /* returns the length of the constructed packet */);

    /* Change out the ethernet header of the test_2_buf */

    sr_ethernet_hdr_t *test_2_eth_hdr = (sr_ethernet_hdr_t*)test_2_buf;
    memcpy(test_2_eth_hdr->ether_shost,"eth3ma",ETHER_ADDR_LEN);
    memcpy(test_2_eth_hdr->ether_dhost,test_3_dummy_eth,ETHER_ADDR_LEN);

    /* Run the Unit Test */

    successful_tests += sr_unit_test_packet(sr,
            "3 - ARP reply received, forward packet waiting on reply",
            test_3_buf,
            test_3_len,
            test_2_result_iface_name,
            1,
            test_2_buf,
            test_2_len,
            test_2_result_iface_name);

    free(test_2_buf);
    free(test_3_buf);

    /**********************************************************
     *                    TEST 4
     ***********************************************************
     * Now we test whether we can go look up the existing ARP cache entry for
     * a new incoming packet going out along the same gateway we just did our
     * ARP exchange for. */

    unsigned int test_4_len = 0;

    /* Here's another dummy TCP packet, passing through to 4.3.2.5,
     * which should forward it through to the gateway 4.3.2.0 */

    uint8_t* test_4_buf = sr_build_dummy_tcp_packet(
        test_2_dest_eth, /* destination ethernet address */
        test_2_src_eth, /* source ethernet address */
        (uint32_t)test_2_src_addr.s_addr, /* src address */
        (uint32_t)test_2_dest_addr.s_addr, /* dest address */
        &test_4_len /* returns the length of the packet */);

    /* Create a duplicate packet, with the only thing different being
     * the MAC address */

    uint8_t* test_4_dst_buf = malloc(test_4_len);
    memcpy(test_4_dst_buf,test_4_buf,test_4_len);

    /* Change out the ethernet header of the test_2_buf */

    sr_ethernet_hdr_t *test_4_dst_eth_hdr = (sr_ethernet_hdr_t*)test_4_dst_buf;
    char* test_4_temp_mac = "eth3ma";
    memcpy(test_4_dst_eth_hdr->ether_shost,test_4_temp_mac,ETHER_ADDR_LEN);
    memcpy(test_4_dst_eth_hdr->ether_dhost,test_3_dummy_eth,ETHER_ADDR_LEN);

    /* Decrement the TTL field on desired packet */

    sr_ip_hdr_t *test_4_dst_ip_hdr = (sr_ip_hdr_t*)(test_4_dst_buf+sizeof(sr_ethernet_hdr_t));
    test_4_dst_ip_hdr->ip_ttl --;

    /* Run the Unit Test */

    successful_tests += sr_unit_test_packet(sr,
            "4 - Forward packet with ARP cache present",
            test_4_buf,
            test_4_len,
            test_2_result_iface_name,
            1,
            test_4_dst_buf,
            test_4_len,
            test_2_result_iface_name);

    /**********************************************************
     *                    TEST 5
     ***********************************************************
     * Receiving an ARP request to one of our interface IPs, and generating a
     * valid response for it. */

    unsigned int test_5_len = 0;

    struct in_addr test_5_if_addr;
    
    inet_aton("5.5.5.4",&test_5_if_addr);

    uint8_t *test_5_buf = sr_build_arp_packet(
        ether_broadcast, /* destination ethernet address */
        test_3_dummy_eth, /* source ethernet address */
        (uint32_t)test_2_gw_addr.s_addr, /* src address */
        (uint32_t)test_5_if_addr.s_addr, /* dest address */
        arp_op_request, /* ARP opcode (command) */
        &test_5_len /* returns the length of the constructed packet */);

    uint8_t *test_5_dst_buf = sr_build_arp_packet(
        test_3_dummy_eth, /* destination ethernet address */
        "eth3ma", /* source ethernet address */
        (uint32_t)test_5_if_addr.s_addr, /* src address */
        (uint32_t)test_2_gw_addr.s_addr, /* dest address */
        arp_op_reply, /* ARP opcode (command) */
        &test_5_len /* returns the length of the constructed packet */);

    successful_tests += sr_unit_test_packet(sr,
            "5 - Receive broadcast ARP request",
            test_5_buf,
            test_5_len,
            "eth3",
            1,
            test_5_dst_buf,
            test_5_len,
            "eth3");

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
        const char* dst_iface_name /* borrowed */)
{
    printf("------------\nTest name: %s\n------------\n",test_name);
    puts("Clearing sent msg buffer.");
    sr_clear_last_unit_test();
    puts("Sending unit test to sr_handlepacket(..)\nThe following is output of the router:\n----");
    sr_handlepacket(sr,
            src_buf,
            src_len,
            src_iface_name);
    puts("----\n");
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
                                /* This should be impossible to reach, unless something fishy happened at the general memcmp */
                                puts(KBLU "PASSED. IP headers match. *Note: this is a fishy way to pass the test, explore this*\n" KWHT);
                                return 1;
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

