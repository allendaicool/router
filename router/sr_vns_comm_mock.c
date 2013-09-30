/*-----------------------------------------------------------------------------
 * File: sr_vns_comm.c
 * Date: Spring 2002
 * Authors: Guido Apanzeller, Vikram Vijayaraghaven, Martin Casado
 * Contact: casado@stanford.edu
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 * 2003-Dec-03 09:00:52 AM :
 *   - bug sending packets read from client to sr_log_packet.  Packet was
 *     sent in network byte order ... expected host byte order.
 *     Reported by Matt Holliman & Sam Small. /mc
 *
 *  2004-Jan-29 07:09:28 PM
 *   - added check to handle signal interrupts on recv (for use with
 *     alarm(..) for timeouts.  Fixes are based on patch by
 *     Abhyudaya Chodisetti <sravanth@stanford.edu> /mc
 *
 *   2004-Jan-31 01:27:54 PM
 *    - William Chan (chanman@stanford.edu) submitted patch for UMR on
 *      sr_dump_packet(..)
 *
 *---------------------------------------------------------------------------*/

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

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_unit_test.h"

#include "sha1.h"
#include "vnscommand.h"

static void sr_log_packet(struct sr_instance* , uint8_t* , int );
static int  sr_arp_req_not_for_us(struct sr_instance* sr,
                                  uint8_t * packet /* lent */,
                                  unsigned int len,
                                  char* interface  /* lent */);

/*-----------------------------------------------------------------------------
 * Method: sr_connect_to_server()
 * Scope: Global
 *
 * Connect to the virtual server
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/
int sr_connect_to_server(struct sr_instance* sr,unsigned short port,
                         char* server)
{
    sr_generate_hwinfo(sr);
    return 0;
} /* -- sr_connect_to_server -- */


/*-----------------------------------------------------------------------------
 * Method: sr_generate_hwinfo(..)
 * scope: global
 *
 *
 * Generate a set of hardware information for testing purposes.
 *
 *---------------------------------------------------------------------------*/

int sr_generate_hwinfo(struct sr_instance* sr)
{
    int num_entries = 2;

    /* REQUIRES */
    assert(sr);

    sr_add_interface(sr,"eth0");
    sr_set_ether_ip(sr,(uint32_t)1);
    sr_set_ether_addr(sr,"eth0ma");

    sr_add_interface(sr,"eth1");
    sr_set_ether_ip(sr,(uint32_t)1);
    sr_set_ether_addr(sr,"eth1ma");

    sr_add_interface(sr,"eth2");
    sr_set_ether_ip(sr,(uint32_t)1);
    sr_set_ether_addr(sr,"eth2ma");

    sr_add_interface(sr,"eth3");
    sr_set_ether_ip(sr,(uint32_t)1);
    sr_set_ether_addr(sr,"eth3ma");

    sr_add_interface(sr,"eth4");
    sr_set_ether_ip(sr,(uint32_t)1);
    sr_set_ether_addr(sr,"eth4ma");

    printf("Router interfaces:\n");
    sr_print_if_list(sr);

    return num_entries;
} /* -- sr_handle_hwinfo -- */

/*-----------------------------------------------------------------------------
 * Method: sr_read_from_server(..)
 * Scope: global
 *
 * Houses main while loop for communicating with the virtual router server.
 *
 *---------------------------------------------------------------------------*/

int sr_read_from_server(struct sr_instance* sr /* borrowed */)
{
    sr_run_unit_tests(sr);
    return 0;
}



/*-----------------------------------------------------------------------------
 * Method: sr_ether_addrs_match_interface(..)
 * Scope: Local
 *
 * Make sure ethernet addresses are sane so we don't muck uo the system.
 *
 *----------------------------------------------------------------------------*/

static int
sr_ether_addrs_match_interface( struct sr_instance* sr, /* borrowed */
                                uint8_t* buf, /* borrowed */
                                const char* name /* borrowed */ )
{
    struct sr_ethernet_hdr* ether_hdr = 0;
    struct sr_if* iface = 0;

    /* -- REQUIRES -- */
    assert(sr);
    assert(buf);
    assert(name);

    ether_hdr = (struct sr_ethernet_hdr*)buf;
    iface = sr_get_interface(sr, name);

    if ( iface == 0 ){
        fprintf( stderr, "** Error, interface %s, does not exist\n", name);
        return 0;
    }

    if ( memcmp( ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN) != 0 ) {
        fprintf( stderr, "** Error, source address %s does not match %s (%s)\n",&(ether_hdr->ether_shost),name,&(iface->addr));
        sr_print_if_list(sr);
        return 0;
    }

    /* TODO */
    /* Check destination, hardware address.  If it is private (i.e. destined
     * to a virtual interface) ensure it is going to the correct topology
     * Note: This check should really be done server side ...
     */

    return 1;

} /* -- sr_ether_addrs_match_interface -- */

/*-----------------------------------------------------------------------------
 * Method: sr_send_packet(..)
 * Scope: Global
 *
 * Send a packet (ethernet header included!) of length 'len' to the server
 * to be injected onto the wire.
 *
 *---------------------------------------------------------------------------*/

int sr_send_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
    c_packet_header *sr_pkt;
    unsigned int total_len =  len + (sizeof(c_packet_header));

    /* REQUIRES */
    assert(sr);
    assert(buf);
    assert(iface);

    /* don't waste my time ... */
    if ( len < sizeof(struct sr_ethernet_hdr) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    if ( ! sr_ether_addrs_match_interface( sr, buf, iface) ) {
        fprintf( stderr, "*** Error: problem with ethernet header %s, check log\n", iface);
        return -1;
    }
    
    sr_unit_test_record_sent_msg(buf,
                         len,
                         iface /* borrowed */);

    /* -- log packet -- */
    sr_log_packet(sr,buf,len);

    return 0;
} /* -- sr_send_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_log_packet()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

void sr_log_packet(struct sr_instance* sr, uint8_t* buf, int len )
{
    struct pcap_pkthdr h;
    int size;

    /* REQUIRES */
    assert(sr);

    if(!sr->logfile)
    {return; }

    size = min(PACKET_DUMP_SIZE, len);

    gettimeofday(&h.ts, 0);
    h.caplen = size;
    h.len = (size < PACKET_DUMP_SIZE) ? size : PACKET_DUMP_SIZE;

    sr_dump(sr->logfile, &h, buf);
    fflush(sr->logfile);
} /* -- sr_log_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_arp_req_not_for_us()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

int  sr_arp_req_not_for_us(struct sr_instance* sr,
                           uint8_t * packet /* lent */,
                           unsigned int len,
                           char* interface  /* lent */)
{
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;
    struct sr_arp_hdr*       a_hdr = 0;

    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr) )
    { return 0; }

    assert(iface);

    e_hdr = (struct sr_ethernet_hdr*)packet;
    a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    if ( (e_hdr->ether_type == htons(ethertype_arp)) &&
            (a_hdr->ar_op      == htons(arp_op_request))   &&
            (a_hdr->ar_tip     != iface->ip ) )
    { return 1; }

    return 0;
} /* -- sr_arp_req_not_for_us -- */
