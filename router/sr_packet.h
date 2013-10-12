
#ifndef SR_PACKET
#define SR_PACKET

#include <stdlib.h>
#include <string.h>
#include "sr_protocol.h"

typedef struct sr_constructed_packet 
{
    uint16_t len;
    uint8_t* buf;
} sr_constructed_packet_t;

sr_constructed_packet_t *sr_grow_or_create_payload(sr_constructed_packet_t* payload, unsigned long size);
void sr_free_packet(sr_constructed_packet_t* payload);

#endif
