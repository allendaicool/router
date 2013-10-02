/*
 * Created by Keenon Werling, Sep 27 2013,
 * 
 * a unit testing framework to interact with a mocked transport
 * layer. Include by running "make test".
 */


#ifndef SR_UNIT_TEST_H
#define SR_UNIT_TEST_H

#include "sr_router.h"

/* Public */

void sr_run_unit_tests(struct sr_instance* sr /* borrowed */);

void sr_unit_test_record_sent_msg(uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */);

/* Private */

int sr_unit_test_packet(struct sr_instance* sr /* borrowed */,
        const char* test_name,
        uint8_t* src_buf, /* borrowed */
        unsigned int src_len,
        char* src_iface_name, /* borrowed */
        const int dst_desired, /* whether or not we should expect a response from the router */
        const uint8_t* dst_buf, /* borrowed */
        const unsigned int dst_len,
        const char* dst_iface_name, /* borrowed */
        const int simulate_seconds_before_response);

void sr_clear_last_unit_test();

#endif
