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

typedef struct dns_cache_entry_struct {
    entry_state_t entry_state;
    dns_packet_t dns_packet_response;
    size_t dns_packet_response_size;
} dns_cache_entry_t;

dns_cache_entry_t dns_cache_find(context_t *context, dns_packet_t *dns_packet_to_find);

bool dns_cache_insert(context_t *context, dns_packet_t *dns_packet, size_t size);

int dns_cache_init(context_t *context);

void dns_cache_stop();

void dns_cache_http_log(context_t *context, dns_string_ptr response);

bool dns_cache_health_check(context_t *context);

#endif //DNS_CACHE_DNS_CACHE_H
