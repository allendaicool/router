
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define ICMP_DATA_SIZE 28

typedef enum {
    nat_mapping_icmp,
    nat_mapping_tcp
    /* nat_mapping_udp, */
} sr_nat_mapping_type;


/* These values are all the state we need
 * for a TCP connection. UDP is ignored for
 * simplicity. */

struct sr_nat_connection {
    uint32_t seen_external_syn;
    uint32_t seen_internal_syn;

    uint32_t seen_external_fin;
    uint32_t seen_internal_fin;

    uint32_t seen_external_fin_ack;
    uint32_t seen_internal_fin_ack;

    uint32_t ip_dst;
    uint16_t port_dst;

    struct sr_nat_connection *next;
    struct sr_nat_connection *prev;
};

/* NAT mapping state */

struct sr_nat_mapping {
    sr_nat_mapping_type type;
    uint32_t ip_int; /* internal ip addr */
    uint32_t ip_ext; /* external ip addr */
    uint16_t aux_int; /* internal port or icmp id */
    uint16_t aux_ext; /* external port or icmp id */
    time_t last_updated; /* use to timeout mappings */
    struct sr_nat_connection *conns; /* TCP holds a connection. null for ICMP */
    struct sr_nat_mapping *next;
    struct sr_nat_mapping *prev;
};

/* Contains state on unsolicited SYN packets
 * so that we can eventually time them out and
 * return ICMP errors */

struct sr_tcp_incoming {
    uint32_t ip_ext; /* external ip addr */
    uint16_t aux_ext; /* external port */
    time_t syn_arrived; /* use to timeout and send ICMP error */
    uint8_t data[ICMP_DATA_SIZE];
    struct sr_tcp_incoming *next;
    struct sr_tcp_incoming *prev;
};

struct sr_nat {
    struct sr_nat_mapping *mappings;
    struct sr_tcp_incoming *incoming;
    uint16_t aux_val;
    struct sr_instance *sr;

    /* threading */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Rewrite the IP packet. I use a void* to avoid a cyclic import dependency. */
int sr_nat_rewrite_ip_packet(void* sr, uint8_t* packet, unsigned int len);

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
        uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
