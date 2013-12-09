
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"
#include <unistd.h>
#include <stdio.h>

#define REQUEST_DROP 1
#define DONT_REQUEST_DROP 0

void* memdup(void* src, int size) {
    void* dst = malloc(size);
    memcpy(dst,src,size);
    return dst;
}

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->incoming = NULL;
  nat->aux_val = 1024;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

/* A quick enum to transmit the relative location of IP addresses */

typedef enum {
    external_interface,
    my_interface,
    internal_interface,
    no_interface,
} sr_network_location;

typedef enum {
    outgoing_pkt,
    incoming_pkt,
    not_traversing,
} sr_traversal_direction;

/* Finds out where an IP address is located, relative to the NAT */

sr_network_location sr_get_ip_network_location(struct sr_instance* sr, uint32_t ip) {

    /* Check if the packet is headed for one of our interfaces */

    struct sr_if* if_dst = sr_get_interface_ip (sr, ip);
    if (if_dst != 0) return my_interface;

    /* If it's not, then check if its LPM is "eth1" */

    struct sr_rt* rt_dst = sr_rt_longest_match(sr,ip);
    if (rt_dst != 0) {
        if (strncmp(rt_dst->interface,"eth1",4) == 0) return internal_interface;
        else return external_interface;
    }

    /* If we didn't find an LPM, this isn't in the routing table */

    return no_interface;
}

/* Find out which direction a packet is travelling, given src and dst values */

sr_traversal_direction sr_get_traversal_direction(sr_network_location src, sr_network_location dst) {
    if (src == external_interface && dst == my_interface) return incoming_pkt;
    if (src == external_interface && dst == internal_interface) return incoming_pkt;
    if (src == internal_interface && dst == external_interface) return outgoing_pkt;
    /* If we get here, we're not traversing */
    return not_traversing;
}

/* Rewrite a packet with a given mapping, heading in a given direction */

void sr_rewrite_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_hdr, unsigned int len, struct sr_nat_mapping* mapping, sr_traversal_direction dir) {

    /* Either protocol, we need to rewrite the src IP and redo IP cksum, so do that first */
    uint16_t aux_value = 0;
    /* Get an IP address to use for translation. We know eth2 will exist, so use that one */
    struct sr_if* my_interface = sr_get_interface(sr, "eth2");
    switch (dir) {
        case incoming_pkt:
            ip_hdr->ip_dst = mapping->ip_int;
            aux_value = mapping->aux_int;
            break;
        case outgoing_pkt:
            ip_hdr->ip_src = my_interface->ip;
            ip_hdr->ip_dst = mapping->ip_ext;
            aux_value = mapping->aux_ext;
            break;
        case not_traversing:
            /* This should not happen */
            assert(0);
            break;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr,sizeof(sr_ip_hdr_t));

    /* Then we need to rewrite the auxiliary value, which is specific to protocol type */

    switch (ip_hdr->ip_p) {
        case ip_protocol_icmp:
        {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_identifier = aux_value;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr,sizeof(sr_icmp_hdr_t));
            break;
        }
        case ip_protocol_tcp:
        {
            sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
            if (dir == incoming_pkt) {
                printf("Rewriting incoming packet to dst_port %i\n",ntohs(mapping->aux_int));
                tcp_hdr->dst_port = mapping->aux_int;
            }
            else if (dir == outgoing_pkt) {
                printf("Rewriting outgoing packet to src_port %i\n",ntohs(mapping->aux_ext));
                tcp_hdr->src_port = mapping->aux_ext;
            }
            tcp_hdr->cksum = cksum_tcp(ip_hdr,tcp_hdr,len-sizeof(sr_ip_hdr_t));
            break;
        }
    }
}

/* Attempt to generate a mapping for this packet. If a mapping is returned, proceed to use it.
 * If this returns NULL, drop the packet. */

struct sr_nat_mapping *sr_generate_mapping(struct sr_instance* sr,
                                    sr_ip_hdr_t* ip_hdr, 
                                    unsigned int len,
                                    sr_traversal_direction dir,
                                    uint16_t aux_value,
                                    sr_nat_mapping_type mapping_type) {

    pthread_mutex_lock(&(sr->nat.lock));

    struct sr_nat_mapping *mapping = NULL;
    switch (dir) {
        case outgoing_pkt:

            /* This implies a bad TCP stream */
            if (mapping_type == nat_mapping_tcp) {
                sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
                if (!(tcp_hdr->flags & TCP_SYN_FLAG)) {
                    puts("bad TCP packet detected");
                    return NULL;
                }
            }

            /* We can just go ahead and create all outgoing requests that don't already exist */
            mapping = malloc(sizeof(struct sr_nat_mapping));
            mapping->ip_int = ip_hdr->ip_src;
            mapping->aux_int = aux_value;
            mapping->ip_ext = ip_hdr->ip_dst;
            mapping->aux_ext = htons(sr->nat.aux_val);
            mapping->last_updated = time(NULL);
            /* No connections to note as of yet */
            mapping->conns = NULL;

            /* Generate a new aux value for the next mapping */
            sr->nat.aux_val = (sr->nat.aux_val + 1)%65535;
            if (sr->nat.aux_val < 1024) sr->nat.aux_val = 1024;

            /* Insert into the linked list */
            if (sr->nat.mappings) {
                sr->nat.mappings->prev = mapping;
            }
            mapping->next = sr->nat.mappings;
            sr->nat.mappings = mapping;
            mapping->prev = NULL;

            /* Return a copy */
            mapping = memdup(mapping,sizeof(struct sr_nat_mapping));
            break;
        case incoming_pkt:

            /* If an incoming packet doesn't have a mapping, our response depends on packet type. */
            switch(mapping_type) {
                case nat_mapping_icmp:
                    /* Drop ICMP packets silently */
                    break;
                case nat_mapping_tcp:
                {
                    /* Queue unsolicited incoming TCP SYN packets for ICMP errors if they time out */
                    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
                    if (tcp_hdr->flags & TCP_SYN_FLAG) {
                        printf("Unsolicited inbound SYN detected\n");

                        struct sr_tcp_incoming *incomings = sr->nat.incoming;
                        while (incomings != NULL) {
                            if ((incomings->ip_ext == ip_hdr->ip_src) && (incomings->aux_ext == aux_value)) break;
                            incomings = incomings->next;
                        }

                        if (incomings == NULL) {
                            struct sr_tcp_incoming *new_incoming = (struct sr_tcp_incoming*)malloc(sizeof(struct sr_tcp_incoming));
                            new_incoming->ip_ext = ip_hdr->ip_src;
                            new_incoming->aux_ext = aux_value;
                            new_incoming->syn_arrived = time(NULL);
                            memcpy(new_incoming->data,ip_hdr,ICMP_DATA_SIZE);

                            /* Insert into the linked list */
                            if (sr->nat.incoming) sr->nat.incoming->prev = new_incoming;
                            new_incoming->next = sr->nat.incoming;
                            sr->nat.incoming = new_incoming;
                            new_incoming->prev = NULL;
                        }
                        else printf("SYN already registered\n");
                    }
                    break;
                }
            }
            break;
        case not_traversing:
            
            /* This should never happen */

            assert(0);
    }

    pthread_mutex_unlock(&(sr->nat.lock));

    return mapping;
}

/* Deals with noting connection changes by snooping TCP flags in the concurrency-aware way
 */

void sr_tcp_note_connections(struct sr_instance* sr, sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr, sr_traversal_direction dir) {
    pthread_mutex_lock(&(sr->nat.lock));

    /* Find the actual mapping for this value */

    struct sr_nat_mapping *mapping = sr->nat.mappings;
    printf("Looking up mapping for TCP connection modification\n");
    while (mapping != NULL) {
        if (dir == incoming_pkt) {
            printf("Mapping (%i), Observed (%i).\n",ntohs(mapping->aux_ext),ntohs(tcp_hdr->dst_port));
            if (tcp_hdr->dst_port == mapping->aux_ext) {
                break;
            }
        }
        else if (dir == outgoing_pkt) {
            char* temp_mapping = ip_to_str(mapping->ip_int);
            char* temp_test = ip_to_str(ip_hdr->ip_src);
            printf("Mapping (%i, %s), Observed (%i, %s).\n",ntohs(mapping->aux_int),temp_mapping,ntohs(tcp_hdr->src_port),temp_test);
            free(temp_mapping);
            free(temp_test);

            if ((ip_hdr->ip_src == mapping->ip_int) && (tcp_hdr->src_port == mapping->aux_int)) {
                break;
            }
        }
        else {
            printf("Packet direction is impossible value\n");
        }
        mapping = mapping->next;
    }

    if (mapping == NULL) {
        /* This should never happen, since we just checked that mappings are non-null before we called this function */
        printf("TCP NOTE CONNECTION has failed to find a mapping. This shouldn't happen. Go check it out. Non-fatal.");
        return;
    }

    /* Find the connection associated with this tcp flow, if there is one */

    uint32_t ip_dst;
    uint16_t port_dst;

    if (dir == incoming_pkt) {
        ip_dst = ip_hdr->ip_src;
        port_dst = tcp_hdr->src_port;
    }
    if (dir == outgoing_pkt) {
        ip_dst = ip_hdr->ip_dst;
        port_dst = tcp_hdr->dst_port;
    }

    printf("Looking up connection mapping\n");
    struct sr_nat_connection *conn = mapping->conns;    
    char* temp_test = ip_to_str(ip_dst);
    while (conn != NULL) {
        char* temp_mapping = ip_to_str(conn->ip_dst);
        printf("Connection mapping (%i, %s), Observed (%i, %s).\n",ntohs(conn->port_dst),temp_mapping,ntohs(port_dst),temp_test);
        if (conn->ip_dst == ip_dst && conn->port_dst == port_dst) {
            break;
        }
        conn = conn->next;
    }
    free(temp_test);

    /* Create a connection if there isn't one already */

    if (conn == NULL) {
        printf("Didn't find a connection, so we're creating a new one\n");
        conn = malloc(sizeof(struct sr_nat_connection));
        memset(conn,0,sizeof(struct sr_nat_connection));
        conn->ip_dst = ip_dst;
        conn->port_dst = port_dst;

        if (mapping->conns != NULL) {
            mapping->conns->prev = conn;
        }
        conn->next = mapping->conns;
        mapping->conns = conn;
        conn->prev = NULL;
    }

    /* Update the seen packet values for the connection */

    if (dir == incoming_pkt) {
        if (!conn->seen_external_syn && (tcp_hdr->flags & TCP_SYN_FLAG)) {
            conn->seen_external_syn = tcp_hdr->seqno;
            printf("SAW EXTERNAL SYN %u\n",ntohl(tcp_hdr->seqno));
        }
        if (!conn->seen_external_fin && (tcp_hdr->flags & TCP_FIN_FLAG)) {
            conn->seen_external_fin = tcp_hdr->seqno;
            printf("SAW EXTERNAL FIN %u\n",ntohl(tcp_hdr->seqno));
        }
        if (conn->seen_internal_fin) {
            printf("Checking ackno (%u) > internal fin seqno (%u)\n",ntohl(tcp_hdr->ackno),ntohl(conn->seen_internal_fin));
            if (ntohl(tcp_hdr->ackno) > ntohl(conn->seen_internal_fin)) {
                conn->seen_external_fin_ack = 1;
                puts("SAW EXTERNAL FIN-ACK");
            }
        }
    }
    if (dir == outgoing_pkt) {
        if (!conn->seen_internal_syn && (tcp_hdr->flags & TCP_SYN_FLAG)) {
            conn->seen_internal_syn = tcp_hdr->seqno;
            printf("SAW INTERNAL SYN %u\n",ntohl(tcp_hdr->seqno));
        }
        if (!conn->seen_internal_fin && (tcp_hdr->flags & TCP_FIN_FLAG)) {
            conn->seen_internal_fin = tcp_hdr->seqno;
            printf("SAW INTERNAL FIN %u\n",ntohl(tcp_hdr->seqno));
        }
        if (conn->seen_external_fin) {
            printf("Checking ackno (%u) > external fin seqno (%u)\n",ntohl(tcp_hdr->ackno),ntohl(conn->seen_external_fin));
            if (ntohl(tcp_hdr->ackno) > ntohl(conn->seen_external_fin)) {
                conn->seen_internal_fin_ack = 1;
                puts("SAW INTERNAL FIN-ACK");
            }
        }
    }
    printf("--------------\nSTATUS:\n");
    char* temp_mapping = ip_to_str(conn->ip_dst);
    printf("Connection mapping (%i, %s)\n",ntohl(conn->port_dst),temp_mapping);
    free(temp_mapping);
    printf("Seen internal syn %u\n",ntohl(conn->seen_internal_syn));
    printf("Seen external syn %u\n",ntohl(conn->seen_external_syn));
    printf("Seen internal fin %u\n",ntohl(conn->seen_internal_fin));
    printf("Seen external fin %u\n",ntohl(conn->seen_external_fin));
    printf("Seen internal fin-ack %u\n",conn->seen_internal_fin_ack);
    printf("Seen external fin-ack %u\n",conn->seen_external_fin_ack);
    printf("--------------\n");

    /* If we've seen both fin_ack's, then close up shop */

    if ((conn->seen_internal_fin_ack && conn->seen_external_fin_ack) || (tcp_hdr->flags & TCP_RST_FLAG)) {
        if (tcp_hdr->flags & TCP_RST_FLAG) printf("RST packet seen\n");
        printf("CLOSING CONNECTION\n");
        if (conn->prev) {
            conn->prev->next = conn->next;
        }
        if (conn->next) {
            conn->next->prev = conn->prev;
        }
        /* If we were the first in the list, then set the list start
         * to our next pointer */
        if (conn->prev == NULL) {
            mapping->conns = conn->next;
        }
        /* Now we get rid of the mapping. Done and done */
        free(conn);

        /* If that was the last connection for the mapping, let's delete 
         * the mapping too */
        if (mapping->conns == NULL) {
            printf("REMOVING MAPPING\n");
            if (mapping->prev) {
                mapping->prev->next = mapping->next;
            }
            if (mapping->next) {
                mapping->next->prev = mapping->prev;
            }
            if (mapping->prev == NULL) {
                sr->nat.mappings = mapping->next;
            }
            free(mapping);
        }
    }

    pthread_mutex_unlock(&(sr->nat.lock));
}

/* Rewrites an IP packet in memory according to NAT rules. A return value of 1 indicates a request
 * to drop the packet. */

int sr_nat_rewrite_ip_packet(void* sr_pointer, uint8_t* packet, unsigned int len) {
    assert(sr_pointer);
    assert(packet);

    struct sr_instance* sr = (struct sr_instance*)sr_pointer;
    
    /* We know the IP header is valid, cause the router checked for us */

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)packet;

    /* Check if we're traversing the interface, and if so, which direction */

    sr_network_location src_loc = sr_get_ip_network_location(sr, ip_hdr->ip_src);
    sr_network_location dst_loc = sr_get_ip_network_location(sr, ip_hdr->ip_dst);
    sr_traversal_direction dir = sr_get_traversal_direction(src_loc,dst_loc);

    /* Get the aux value and packet type for looking up the mapping */

    uint16_t aux_value = 0;
    sr_nat_mapping_type mapping_type;
    int unsupported_protocol = 0;

    switch (ip_hdr->ip_p) {
        case ip_protocol_icmp:
        {
            sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t*)(packet+sizeof(sr_ip_hdr_t));
            aux_value = icmp->icmp_identifier;
            mapping_type = nat_mapping_icmp;
            break;
        }
        case ip_protocol_tcp:
        {
            sr_tcp_hdr_t *tcp = (sr_tcp_hdr_t*)(packet+sizeof(sr_ip_hdr_t));
            if (dir == incoming_pkt) aux_value = tcp->dst_port;
            else if (dir == outgoing_pkt) aux_value = tcp->src_port;
            mapping_type = nat_mapping_tcp;
            break;
        }
        default:
            unsupported_protocol = 1;
    }

    /* Lookup the mapping for the packet */

    struct sr_nat_mapping* mapping = NULL;

    switch (dir) {
        case incoming_pkt:
        {
            puts("Packet incoming through NAT\n");
            if (unsupported_protocol) return REQUEST_DROP;
            mapping = sr_nat_lookup_external(&sr->nat, aux_value, mapping_type);
            break;
        }
        case outgoing_pkt:
        {
            puts("Packet outgoing through NAT\n");
            char* temp = ip_to_str(ip_hdr->ip_src);
            printf("Looking up (%i, %s).\n",ntohs(aux_value),temp);
            free(temp);
            if (unsupported_protocol) return REQUEST_DROP;
            mapping = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, aux_value, mapping_type);
            break;
        }
        case not_traversing:
            puts("Packet not traversing NAT\n");
            /* We can safely allow any non-traversing packets to pass
             * unmolested */
            return DONT_REQUEST_DROP;
    }


    /* If the mapping doesn't exist, we're in a tricky spot */

    if (mapping == NULL) {
        char* temp = ip_to_str(ip_hdr->ip_src);
        printf("No mapping found. Attempting to create one for (%i, %s)\n",ntohs(aux_value),temp);
        free(temp);
        mapping = sr_generate_mapping(sr, ip_hdr, len, dir, aux_value, mapping_type);

        /* If no mapping could be generated, then we need to request to
         * drop the packet */

        if (mapping == NULL) {
            return REQUEST_DROP;
        }
        temp = ip_to_str(mapping->ip_int);
        printf("Mapping successfully created: (%i, %s)\n",ntohs(mapping->aux_int),temp);
        free(temp);
    }

    /* Do the checking for TCP connection state changes in a concurrent-safe way */

    if (ip_hdr->ip_p == ip_protocol_tcp) {
        sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)(((uint8_t*)ip_hdr)+sizeof(sr_ip_hdr_t));
        sr_tcp_note_connections(sr,ip_hdr,tcp_hdr,dir);
    }

    /* If we get here, there must be a mapping, so rewrite with it */

    sr_rewrite_packet(sr,ip_hdr,len,mapping,dir);
    free(mapping); /* Free the copy */

    /* If we got here, we rewrote a packet successfully. Forward away. */

    return DONT_REQUEST_DROP;
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    struct sr_nat *nat = (struct sr_nat*)nat_ptr;

    /* Timeout mappings */

    struct sr_nat_mapping *mapping = nat->mappings;
    while (mapping != NULL) {
        double seconds = difftime(curtime,mapping->last_updated);
        printf("Seconds since mapping was updated %f\n",seconds);

        int timedout = 0;
        switch (mapping->type) {
            case nat_mapping_icmp:
            {
                printf("ICMP mapping\n");

                if (seconds > 5) timedout = 1;
                break;
            }
            case nat_mapping_tcp:
            {
                printf("TCP mapping\n");

                /* Timeout each connection seperately for TCP */

                struct sr_nat_connection *conn = mapping->conns;
                while (conn != NULL) {
                    int transitory = 1;
                    if (conn->seen_external_syn && conn->seen_internal_syn) {
                        transitory = 0;
                    }
                    if (conn->seen_external_fin && conn->seen_internal_fin) {
                        transitory = 1;
                    }
                    double seconds = difftime(curtime,conn->last_updated);
                    printf("-> seconds since connection was updated %f\n",seconds);

                    /* timeout connection */

                    int conn_timedout = 0;

                    if (transitory) {
                        if (seconds > 2) {
                            conn_timedout = 1;
                        }
                    }
                    if (!transitory) {
                        if (seconds > 10) {
                            conn_timedout = 1;
                        }
                    }

                    /* remove connection if timed out */

                    struct sr_nat_connection *freebuf = NULL;
                    if (conn_timedout == 1) {
                        if (conn->next) {
                            conn->next->prev = conn->prev;
                        }
                        if (conn->prev) {
                            conn->prev->next = conn->next;
                        }
                        if (conn->prev == NULL) {
                            mapping->conns = conn->next;
                        }
                        freebuf = conn;
                    }
                    conn = conn->next;
                    if (freebuf != NULL) free(freebuf);
                }
                /* If all our connections are gone, timeout the mapping */
                if (mapping->conns == NULL) timedout = 1;
                break;
            }
        }

        if (timedout) {
            if (mapping->next) {
                mapping->next->prev = mapping->prev;
            }
            if (mapping->prev) {
                mapping->prev->next = mapping->next;
            }
            if (mapping->prev == NULL) {
                nat->mappings = mapping->next;
            }
        }
        mapping = mapping->next;
    }

    /* Timeout unsolicited SYN packets */

    struct sr_tcp_incoming *incoming = nat->incoming;
    while (incoming != NULL) {
        double seconds = difftime(curtime,incoming->syn_arrived);
        printf("Seconds since incoming SYN was received %f\n",seconds);
        struct sr_tcp_incoming *freebuf = NULL;
        if (seconds >= 5) {
            printf("Removing SYN and sending ICMP error\n");

            /* Send the ICMP */

            sr_try_send_ip_packet(nat->sr, incoming->ip_ext, 0,
                sr_build_icmp_t3_packet(
                    ICMP_TYPE_PORT_UNREACHABLE,
                    ICMP_CODE_PORT_UNREACHABLE,
                    (uint8_t*)incoming->data
                ),
                NULL
            );
            
            /* Remove from the chain */

            if (incoming->next) {
                incoming->next->prev = incoming->prev;
            }
            if (incoming->prev) {
                incoming->prev->next = incoming->next;
            }
            if (incoming->prev == NULL) {
                nat->incoming = incoming->next;
            }
            freebuf = incoming;
        }
        incoming = incoming->next;
        if (freebuf != NULL) free(freebuf);
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *mapping_walker = nat->mappings;
  while (mapping_walker != NULL) {
      printf("Mapping (%i), Observed (%i).\n",ntohs(mapping_walker->aux_ext),ntohs(aux_ext));
      if (mapping_walker->aux_ext == aux_ext) {
          mapping_walker->last_updated = time(NULL);
          copy = memdup(mapping_walker,sizeof(struct sr_nat_mapping));
          break;
      }
      mapping_walker = mapping_walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *mapping_walker = nat->mappings;
  while (mapping_walker != NULL) {
      char* temp_mapping = ip_to_str(mapping_walker->ip_int);
      char* temp_test = ip_to_str(ip_int);
      printf("Mapping (%i, %s), Observed (%i, %s).\n",ntohs(mapping_walker->aux_int),temp_mapping,ntohs(aux_int),temp_test);
      free(temp_mapping);
      free(temp_test);

      if (mapping_walker->aux_int == aux_int && mapping_walker->ip_int == ip_int) {
          mapping_walker->last_updated = time(NULL);
          copy = memdup(mapping_walker,sizeof(struct sr_nat_mapping));
          break;
      }
      mapping_walker = mapping_walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
