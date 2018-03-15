/**********************************************************************
//    Copyright (c) 2015 Henry Seurer
//
//    Permission is hereby granted, free of charge, to any person
//    obtaining a copy of this software and associated documentation
//    files (the "Software"), to deal in the Software without
//    restriction, including without limitation the rights to use,
//    copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the
//    Software is furnished to do so, subject to the following
//    conditions:
//
//    The above copyright notice and this permission notice shall be
//    included in all copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//    OTHER DEALINGS IN THE SOFTWARE.
//
**********************************************************************/

#ifndef DNS_CACHE_DNS_CACHE_H
#define DNS_CACHE_DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <stdbool.h>
#include "dns_packet.h"

typedef enum {
    ENTRY_FREE = 0,
    ENTRY_IN_PROCESS,
    ENTRY_ENABLED
} entry_state_t;

typedef struct dns_cache_entry_t {
    entry_state_t entry_state;
    dns_packet dns_packet_response;
    size_t dns_packet_response_size;
} dns_cache_entry;

dns_cache_entry dns_cache_find(transaction_context *context, dns_packet *dns_packet_to_find);

bool dns_cache_insert(transaction_context *context, dns_packet *packet, size_t size);

int dns_cache_init(transaction_context *context);

void dns_cache_stop();

void dns_cache_html_log(transaction_context *context, dns_string *response);

void dns_cache_json_log(transaction_context *context, dns_string *response);

bool dns_cache_health_check(transaction_context *context);

size_t dns_packet_a_record_create(dns_cache_entry *cache_entry, dns_string  __unused *host_name, dns_string  __unused *ip);

#endif //DNS_CACHE_DNS_CACHE_H
