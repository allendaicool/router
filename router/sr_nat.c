
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include <unistd.h>
#include <stdio.h>

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

/* Rewrites an IP packet in memory according to NAT rules */

void sr_nat_rewrite_ip_packet(void* sr_pointer, uint8_t* packet, unsigned int len) {
    assert(sr_pointer);
    assert(packet);

    struct sr_instance* sr = (struct sr_instance*)sr_pointer;
    
    /* We know the IP header is valid, cause the router checked for us */

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)packet;

    /* Check if we're traversing the interface, and if so, which direction */

    sr_network_location src_loc = sr_get_ip_network_location(sr, ntohl(ip_hdr->ip_src));
    sr_network_location dst_loc = sr_get_ip_network_location(sr, ntohl(ip_hdr->ip_dst));

    printf("\nNAT REWRITING IP PACKET!\nSRC LOC: ");
    switch (src_loc) {
        case external_interface:
            printf("External Interface");
            break;
        case my_interface:
            printf("My Interface");
            break;
        case internal_interface:
            printf("Internal Interface");
            break;
        case no_interface:
            printf("No Interface");
            break;
    }
    printf("\nDST LOC: ");
    switch (dst_loc) {
        case external_interface:
            printf("External Interface");
            break;
        case my_interface:
            printf("My Interface");
            break;
        case internal_interface:
            printf("Internal Interface");
            break;
        case no_interface:
            printf("No Interface");
            break;
    }
    printf("\n");

    /* Fork based on the type of packet */

    switch (ip_hdr->ip_p) {
        case ip_protocol_icmp:
            return;
        case ip_protocol_tcp:
            return;
    }

    /* Ignore all others */
}

void sr_nat_rewrite_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len) {
}

void sr_nat_rewrite_tcp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len) {
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
