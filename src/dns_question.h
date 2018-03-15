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

#ifndef DNS_ACTIVE_CACHE_DNS_QUESTION_H
#define DNS_ACTIVE_CACHE_DNS_QUESTION_H

#include "dns_packet.h"

// Because questions have variable length structure, in the end I just decided to
// hide the elements behind a "handle" and you need to reference them via functions.
//
typedef void *dns_question_handle;

dns_question_handle *dns_packet_question_index(dns_packet *packet, unsigned index);

void *dns_packet_question_skip(dns_packet *packet);

dns_string *dns_question_host(dns_question_handle question);

record_type_t dns_question_type(dns_question_handle question);

class_type_t dns_question_class(dns_question_handle question);

dns_question_handle dns_question_next(dns_question_handle question);

size_t dns_packet_question_size(transaction_context *context, dns_packet *packet);

#endif //DNS_ACTIVE_CACHE_DNS_QUESTION_H
