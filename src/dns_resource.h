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

#ifndef DNS_ACTIVE_CACHE_DNS_RESOURCE_H
#define DNS_ACTIVE_CACHE_DNS_RESOURCE_H

#include "dns_packet.h"

typedef void *dns_resource_handle;

dns_string *dns_resource_host(dns_packet *packet, dns_resource_handle resource);

record_type_t dns_resource_record_type(transaction_context *context, dns_resource_handle resource);

class_type_t dns_resource_class_type(transaction_context *context, dns_resource_handle resource);

uint32_t dns_resource_ttl(transaction_context *context, dns_resource_handle resource);

uint32_t dns_resource_ttl_set(transaction_context *context, dns_resource_handle resource, uint32_t new_ttl);

void dns_resource_log(transaction_context *context, dns_string *log_output, dns_packet *packet,
                      dns_resource_handle resource);

dns_resource_handle dns_packet_answer_get(transaction_context *context, dns_packet *packet, uint16_t index);

dns_resource_handle dns_packet_authority_get(transaction_context *context, dns_packet *packet, uint16_t index);

dns_resource_handle dns_packet_information_get(transaction_context *context, dns_packet *packet, uint16_t index);

dns_string *dns_resource_data_string(transaction_context *context, dns_packet *packet, dns_resource_handle resource);

uint32_t dns_resource_data_uint32(transaction_context *context, dns_resource_handle resource);

uint16_t dns_resource_data_uint16(transaction_context *context, dns_resource_handle resource);

#endif //DNS_ACTIVE_CACHE_DNS_RESOURCE_H
