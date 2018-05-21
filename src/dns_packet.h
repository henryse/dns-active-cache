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

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedMacroInspection"
#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#ifndef __MACH__
#include <sys/cdefs.h>
#define _POSIX_C_SOURCE 200809L
#define __unused
#else
#include <ntsid.h>
#endif
#include <stdio.h>
#include <stdbool.h>
#include "dns_string.h"
#include "dns_utils.h"

//DNS header structure

typedef struct __attribute__((packed)) dns_header_t {
    uint16_t id;                                // identification number
    unsigned char recursion_desired :1;         // recursion desired
    unsigned char truncated_message :1;         // truncated message
    unsigned char authoritative_answer :1;      // authoritative answer
    unsigned char operation_code :4;            // purpose of message
    unsigned char query_response_flag :1;       // query/response flag
    unsigned char response_code :4;             // response code
    unsigned char checking_disabled :1;         // checking disabled
    unsigned char authenticated_data :1;        // authenticated data
    unsigned char z_reserved :1;                // its z! reserved
    unsigned char recursion_available :1;       // recursion available
    uint16_t question_count;                    // number of question entries
    uint16_t answer_count;                      // number of answer entries
    uint16_t authority_count;                   // number of authority entries
    uint16_t information_count;                 // number of information entries
} dns_header;

#define DNS_HEADER_SIZE 12
#define DNS_PACKET_SIZE 1024

typedef struct __attribute__((packed)) dns_packet_t {
    dns_header header;                              // DNS HEADER (see above)
    char body[DNS_PACKET_SIZE - DNS_HEADER_SIZE];   // Question and answers can be found in the body
} dns_packet;

#define RECORD_INVALID 0x00       /* Invalid value */
#define RECORD_A 0x01             /* '0001 (1)	 Requests the A record for the domain name */
#define RECORD_NS 0x02            /* '0002 (2)	 Requests the NS record(s) for the domain name */
#define RECORD_CNAME 0x05         /* '0005 (5)	 Requests the CNAME record(s) for the domain name */
#define RECORD_SOA 0x06           /* '0006 (6)	 Requests the SOA record(s) for the domain name */
#define RECORD_WKS 0x0B           /* '000B (11)	 Requests the WKS record(s) for the domain name */
#define RECORD_PTR 0x0C           /* '000C (12)	 Requests the PTR record(s) for the domain name */
#define RECORD_MX 0x0F            /* '000F (15)	 Requests the MX record(s) for the domain name */
#define RECORD_SRV 0x21           /* '0021 (33)	 Requests the SRV record(s) for the domain name */
#define RECORD_AAAA 0x1C          /* '001C (28)  IPv6 Address record. An IPv6 address for a host. */
#define RECORD_HINFO 0x0D         /* '000D (13)  Record intended to provide information about host CPU type and */
                                  /*             operating system. It was intended to allow protocols to optimize */
                                  /*             processing when communicating with similar peers */
#define RECORD_A6 0x26            /* '0026 (38)	 Obsolete. AAAA is the recommended IPv6 address record. Historical status */
#define RECORD_ANY 0xFF           /* '00FF (255) Requests ANY resource record (typically wants SOA, MX, NS and MX) */

typedef uint16_t record_type_t;

#define CLASS_INVALID 0           /* Invalid Class */
#define CLASS_IN 1                /* the Internet */
#define CLASS_CS 2                /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
#define CLASS_CH 3                /* the CHAOS class */
#define CLASS_HS 4                /* Hesiod [Dyer 87] */

typedef uint16_t class_type_t;

void dns_packet_log(transaction_context *context, dns_packet *packet, const char *template, ...);

uint32_t dns_packet_record_ttl_get(transaction_context *context,
                                   dns_packet *packet,
                                   record_type_t record_type);

void dns_packet_record_ttl_set(transaction_context *context,
                               dns_packet *packet,
                               record_type_t record_type,
                               uint32_t new_ttl);

const char *dns_record_type_string(uint16_t record_type);

void dns_string_to_host(const unsigned char *string, dns_string *host);

void dns_host_to_string(const char *host, char *string);

size_t dns_packet_size(dns_packet *packet);

#endif //DNS_PACKET_READ
#pragma clang diagnostic pop