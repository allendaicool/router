/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>
#include <sys/time.h>

#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask,char* if_name)
{
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        rt_walker = sr->routing_table;
    }
    /* -- find the end of the list -- */
    else {
        rt_walker = sr->routing_table;
        while(rt_walker->next){
            rt_walker = rt_walker->next; 
        }
        rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(rt_walker->next);
        rt_walker = rt_walker->next;
    }

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);

    /*
     * We cache the bit_length of the mask, to faccilitate doing
     * a longest match without redundant work.
     */

    rt_walker->mask_bit_length = 0;

    /* There is a bit of inline assembly on x86 processors that
     * does a bit-scan from the end of the bit pattern to the front
     * and places the index of smallest 1 into match_length.
     * 
     * I would use it if ANSI would let me. Stupid ANSI flag.
     *
     * asm("bsrl %1,%0" : "=r"(match_length) : "r"(rt_walker_mask));
     *
     * Instead I use a stupidly slow loop and bit shifting scan.
     */

    unsigned int i;
    for (i = 0; i < 32; i++) {
        /* Have to double check that this is a big endian mask, so
         * we convert to network endianness, which is always big endian.
         */
        uint32_t bit_mask = 1 << i;
        if ((unsigned int)(htonl(rt_walker->mask.s_addr) & bit_mask) != 0) {
            rt_walker->mask_bit_length = 32-i;
            break;
        }
    }

} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method: sr_rt_longest_match
 *
 * Returns the longest match in the routing table for a given 32 bit
 * IPv4 address.
 *
 *---------------------------------------------------------------------*/

struct sr_rt *sr_rt_longest_match(struct sr_instance* sr, uint32_t ip) {

    struct sr_rt* rt_walker = 0;
    struct sr_rt* longest_match = NULL;
    unsigned int longest_match_length = 0;

    if(sr->routing_table == 0)
    {
        return NULL;
    }

    /* Setup to find the longest match */

    char* temp_ip = ip_to_str(ip);
    printf("Looking up longest match for %s\n",temp_ip);
    free(temp_ip);

    rt_walker = sr->routing_table;
    while (rt_walker)
    {
        uint32_t rt_walker_ip = (uint32_t)rt_walker->dest.s_addr;
        uint32_t rt_walker_mask = (uint32_t)rt_walker->mask.s_addr;

        temp_ip = ip_to_str(rt_walker->dest.s_addr);
        printf("Checking %s",temp_ip);
        free(temp_ip);
        temp_ip = ip_to_str(rt_walker->mask.s_addr);
        printf(" mask %s\n",temp_ip);
        free(temp_ip);

        /* First check for matches with some bit-twiddling, then test how 
         * long the match is.
         */

        uint32_t same_bits = ~(rt_walker_ip ^ ip);
        if ((same_bits & rt_walker_mask) == rt_walker_mask) {

            printf("Match length: %u\n", rt_walker->mask_bit_length);

            if (rt_walker->mask_bit_length >= longest_match_length) {
                longest_match_length = rt_walker->mask_bit_length;
                longest_match = rt_walker;
            }
        }

        rt_walker = rt_walker->next; 
    }

    /* Possibly no match */

    return longest_match;
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;
    
    sr_print_routing_entry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%i\n",entry->mask_bit_length);

} /* -- sr_print_routing_entry -- */
