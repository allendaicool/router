#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>

#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 

    struct sr_arpreq *req_walker = sr->cache.requests;

    while (req_walker != NULL) {
        sr_handle_arpreq(sr, req_walker);
        req_walker = req_walker->next;
    }

}

/*
 * Handle an arpreq, if the time between last update and now is greater than 1.
 * Send an ARP request, if no cache entry, and then send ICMP unreachable if necessary.
 */

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {

    assert(sr);
    assert(req);

    time_t now;
    time(&now);

    if (difftime(now, req->sent) > 1) {
        if (req->times_sent >= 5) {
            /*
               send icmp host unreachable to source addr of all pkts waiting
               on this request
            */

            char* temp_ip = ip_to_str(ntohl(req->ip));
            printf("ARP to %s expired! Sending expiration ICMPs\n",temp_ip);
            free(temp_ip);

            /* Walk through the waiting packets */

            struct sr_packet* packet_walker = req->packets;
            while (packet_walker) {

                /* Copy the newly acquired dest MAC address over */

                sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(packet_walker->buf);
                sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet_walker->buf + sizeof(sr_ethernet_hdr_t));

                struct sr_if* rebound_if = sr_get_interface(sr, packet_walker->src_iface); /* just to put in some temp values for the packet */

                /* Send out a ICMP port unreachable response */

                sr_constructed_packet_t *outgoing_icmp_packet = sr_build_eth_packet(
                    rebound_if->addr,
                    eth_hdr->ether_shost, /* This gets overwritten in send_ip_packet */
                    ethertype_ip,

                    sr_build_ip_packet(
                        rebound_if->ip,
                        ip_hdr->ip_src,
                        ip_protocol_icmp,

                        sr_build_icmp_t3_packet(
                            ICMP_TYPE_HOST_UNREACHABLE,
                            ICMP_CODE_HOST_UNREACHABLE,
                            packet_walker->buf + sizeof(sr_ethernet_hdr_t)
                        )
                    )
                );

                sr_try_send_ip_packet(sr, ntohl(ip_hdr->ip_src), (sr_ethernet_hdr_t*)outgoing_icmp_packet->buf, outgoing_icmp_packet->len, rebound_if->name, 1);
                
                /* Continue walking the linked list */

                packet_walker = packet_walker->next;
            }

            /* Free the memory associated with these requests */

            sr_arpreq_destroy(&(sr->cache),req);
        }
        else {

            /* send arp req */

            uint8_t ether_broadcast[ETHER_ADDR_LEN];
            int i;
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                ether_broadcast[i] = ~((uint8_t)0);
            }

            /* If we're processing this, then it must have packets waiting */
            assert(req->packets != 0);

            /* Broadcast our ARP request on our interface */

            char* temp_ip = ip_to_str(sr_get_interface(sr, req->packets->iface)->ip);
            printf("Send ARP on interface %s, with IP %s\n",req->packets->iface, temp_ip);

            free(temp_ip);

            sr_constructed_packet_t *arp_packet = sr_build_eth_packet(
                sr_get_interface(sr, req->packets->iface)->addr,
                ether_broadcast,
                ethertype_arp,

                sr_build_arp_packet(
                    sr_get_interface(sr, req->packets->iface)->ip,
                    req->ip,
                    sr_get_interface(sr, req->packets->iface)->addr,
                    ether_broadcast,
                    arp_op_request,
                    NULL
                )
            );

            /* All the packets looking for the same IP will be coming from
             * the same interface. Thus we only send one request, on the
             * desired interface. */

            sr_send_packet(sr,arp_packet->buf,arp_packet->len,req->packets->iface);

            req->sent = now;
            req->times_sent++;
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface,
                                       char *src_iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
		new_pkt->src_iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->src_iface, src_iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    char* temp_ip = ip_to_str(ip);
    printf("Inserting mapping %s -> %s into ARP table\n",temp_ip,mac);
    free(temp_ip);
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

