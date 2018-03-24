/**********************************************************************
//    Copyright (c) 2018 Henry Seurer
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

#ifndef DNS_ACTIVE_CACHE_SERVICE_ETCD_H
#define DNS_ACTIVE_CACHE_SERVICE_ETCD_H

#include "dns_utils.h"
#include "dns_cache.h"

typedef struct dns_etcd_cache_t {
    int refcount;
    dns_array *dns_etcd_cache_records;
} dns_etcd_cache;

dns_cache_entry dns_etcd_find(transaction_context *context, dns_packet *request);

dns_cache_entry lookup_etcd_packet(transaction_context *context, dns_packet *dns_packet_to_find);

int dns_service_etcd(transaction_context *context);

dns_etcd_cache *dns_etcd_cache_hold(dns_etcd_cache *cache);

dns_etcd_cache *dns_etcd_cache_release(dns_etcd_cache *cache);

void dns_etcd_cache_log(dns_string *response);

#endif //DNS_ACTIVE_CACHE_SERVICE_ETCD_H
