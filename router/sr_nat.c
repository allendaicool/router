
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

uint16_t cksum_tcp(sr_ip_hdr_t* ip_hdr, sr_tcp_hdr_t* tcp_hdr, uint16_t len) {

    size_t bloblen = sizeof(sr_tcp_psuedo_hdr_t)+len;

    tcp_hdr->cksum = 0;
    void* blob = malloc(bloblen);
    memset(blob,0,bloblen);

    memcpy(blob+sizeof(sr_tcp_psuedo_hdr_t),tcp_hdr,len);

    sr_tcp_psuedo_hdr_t *psuedo = (sr_tcp_psuedo_hdr_t*)blob;
    psuedo->ip_src = ip_hdr->ip_src;
    psuedo->ip_dst = ip_hdr->ip_dst;
    psuedo->reserved = 0;
    psuedo->ip_tos = ip_hdr->ip_tos;
    psuedo->tcp_len = htons(len);

    uint16_t cksum_val = cksum(blob,bloblen);
    free(blob);
    return cksum_val;
}

/* Rewrite a packet with a given mapping, heading in a given direction */

void sr_rewrite_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_hdr, unsigned int len, struct sr_nat_mapping* mapping, sr_traversal_direction dir) {

    /* Either protocol, we need to rewrite the src IP and redo IP cksum, so do that first */
    uint16_t aux_value = 0;
    /* Get an IP address to use for translation. We know eth1 will exist, so use that one */
    struct sr_if* my_interface = sr_get_interface(sr, "eth1");
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
            tcp_hdr->src_port = aux_value;
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

            /* We can just go ahead and create all outgoing requests that don't already exist */

            mapping = malloc(sizeof(struct sr_nat_mapping));
            mapping->ip_int = ip_hdr->ip_src;
            mapping->aux_int = aux_value;
            mapping->ip_ext = ip_hdr->ip_dst;
            mapping->aux_ext = sr->nat.aux_val;
            mapping->last_updated = time(NULL);

            /* Create the connection we'll be using to keep track of the TCP flow */
            if (mapping_type == nat_mapping_tcp) {
                mapping->conns = malloc(sizeof(struct sr_nat_connection));
                memset(mapping->conns,0,sizeof(struct sr_nat_connection)); /* Zero out */
            }

            /* Generate a new aux value for the next mapping */
            
            sr->nat.aux_val = (sr->nat.aux_val + 1)%65535;
            if (sr->nat.aux_val < 1024) sr->nat.aux_val = 1024;

            /* Insert into the linked list */

            mapping->next = sr->nat.mappings;
            sr->nat.mappings = mapping;

            /* Return a copy */

            mapping = memdup(mapping,sizeof(struct sr_nat_mapping));
            break;
        case incoming_pkt:

            /* If an incoming packet doesn't have a mapping, our response depends on packet type. */
            switch(mapping_type) {
                case nat_mapping_icmp:
                    break;
                case nat_mapping_tcp:
                    break;
            }
            break;
        case not_traversing:
            
            /* This should never happen */

            assert(0);
    }

    pthread_mutex_unlock(&(sr->nat.lock));

    return mapping;
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
            aux_value = tcp->src_port;
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
            if (unsupported_protocol) return REQUEST_DROP;
            mapping = sr_nat_lookup_internal(&sr->nat, aux_value, ip_hdr->ip_src, mapping_type);
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
        printf("No mapping found. Attempting to create one\n");
        mapping = sr_generate_mapping(sr, ip_hdr, len, dir, aux_value, mapping_type);

        /* If no mapping could be generated, then we need to request to
         * drop the packet */

        if (mapping == NULL) {
            return REQUEST_DROP;
        }
        printf("Mapping successfully created\n");
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

    /* handle periodic tasks here */

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
      if (mapping_walker->aux_ext == aux_ext) {
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
      if (mapping_walker->aux_int == aux_int && mapping_walker->ip_int == ip_int) {
          copy = memdup(mapping_walker,sizeof(struct sr_nat_mapping));
          break;
      }
      mapping_walker = mapping_walker->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
