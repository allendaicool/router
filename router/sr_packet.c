/*
 * Created by Keenon Werling, Oct 9 2013,
 * 
 * a unit testing framework to interact with a mocked transport
 * layer. Include by running "make test".
 */

#include "sr_packet.h"

/* Conditionally grows a payload, leaving size free space at the *FRONT* of the packet, or
 * creates a new packet, if NULL is passed in. Either way, there is size free space at the
 * buf pointer, on the heap. Sets all new memory to 0. */

sr_constructed_packet_t *sr_grow_or_create_payload(sr_constructed_packet_t* payload, unsigned long size) {
    if (payload != NULL) {
        uint8_t *new_buf = malloc(size + payload->len);
        memcpy(new_buf + size, payload->buf, payload->len);
        free(payload->buf);
        payload->len = payload->len + size;
        payload->buf = new_buf;
        memset(payload->buf,0,size);
        return payload;
    }
    else {
        sr_constructed_packet_t* new_packet = malloc(sizeof(sr_constructed_packet_t));
        new_packet->len = size;
        new_packet->buf = malloc(size);
        memset(new_packet->buf,0,size);
        return new_packet;
    }
}

/* Frees the memory associated with a payload */

void sr_free_packet(sr_constructed_packet_t* payload) {
    free(payload->buf);
    free(payload);
}
