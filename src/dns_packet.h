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
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
#pragma ide diagnostic ignored "OCUnusedMacroInspection"

#ifndef DNS_SERVICE_PROCESSING_H
#define DNS_SERVICE_PROCESSING_H

#include <stdio.h>
#include <stdbool.h>
#include "dns_string.h"
#include "dns_utils.h"

#pragma pack(push, 1)

//DNS header structure

typedef struct dns_header_struct {
    unsigned short id;                          // identification number
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
    unsigned short question_count;              // number of question entries
    unsigned short answer_count;                // number of answer entries
    unsigned short authority_count;             // number of authority entries
    unsigned short resource_count;              // number of resource entries
} dns_header_t;

#define DNS_HEADER_SIZE 12
#define DNS_PACKET_SIZE 1024

typedef struct dns_packet_struct {
    dns_header_t header;                              // DNS HEADER (see above)
    char body[DNS_PACKET_SIZE - DNS_HEADER_SIZE];   // Question and answers can be found in the body
} dns_packet_t;

//Constant sized fields of query structure
typedef struct question_type_struct {
    unsigned short question_type;
    unsigned short question_class;
} question_type_t;

typedef void *question_t;

#define RECORD_A 0x01             /* '0001 (1)	 Requests the A record for the domain name */
#define RECORD_NS 0x02            /* '0002 (2)	 Requests the NS record(s) for the domain name */
#define RECORD_CNAME 0x05         /* '0005 (5)	 Requests the CNAME record(s) for the domain name */
#define RECORD_SOA 0x06           /* '0006 (6)	 Requests the SOA record(s) for the domain name */
#define RECORD_WKS 0x0B           /* '000B (11)	 Requests the WKS record(s) for the domain name */
#define RECORD_PTR 0x0C           /* '000C (12)	 Requests the PTR record(s) for the domain name */
#define RECORD_MX 0x0F            /* '000F (15)	 Requests the MX record(s) for the domain name */
#define RECORD_SRV 0x21           /* '0021 (33)	 Requests the SRV record(s) for the domain name */
#define RECORD_AAAA 0x1C          /* '001C (28)  IPv6 Address record. An IPv6 address for a host. */
#define RECORD_A6 0x26            /* '0026 (38)	 Obsolete. AAAA is the recommended IPv6 address record. Historical status */
#define RECORD_ANY 0xFF           /* '00FF (255) Requests ANY resource record (typically wants SOA, MX, NS and MX) */

typedef unsigned short record_type_t;

//Constant sized fields of the resource record structure
typedef struct dns_resource_header_struct {
    unsigned short record_type;         // The RR type, for example, RECORD_A or RECORD_AAAA (see above)
    unsigned short record_class;        // A 16 bit value which defines the protocol family or an
    // instance of the protocol. The normal value is IN = Internet protocol
    // (other values are HS and CH both historic MIT protocols).
    unsigned int record_ttl;            // 32 bit value. The Time to Live in seconds (range is 1 to 2147483647)
    // and indicates how long the RR may be cached. The value zero indicates
    // the data should not be cached.
    unsigned short record_data_len;     // The length of RR specific data in octets, for example, 27
} dns_resource_header_t;

typedef void *resource_resource_t;

//Constant sized fields of the resource record structure
typedef struct dns_additional_record_struct {
    //   +------------------+------------------------------------------------+
    //   |  Identifier Type | Identifier                                     |
    //   |       Code       |                                                |
    //   +------------------+------------------------------------------------+
    //   |      0x0000      | The 1-octet 'htype' followed by 'hlen' octets  |
    //   |                  | of 'chaddr' from a DHCPv4 client's DHCPREQUEST |
    //   |                  | [7].                                           |
    //   |      0x0001      | The data octets (i.e., the Type and            |
    //   |                  | Client-Identifier fields) from a DHCPv4        |
    //   |                  | client's Client Identifier option [10].        |
    //   |      0x0002      | The client's DUID (i.e., the data octets of a  |
    //   |                  | DHCPv6 client's Client Identifier option [11]  |
    //   |                  | or the DUID field from a DHCPv4 client's       |
    //   |                  | Client Identifier option [6]).                 |
    //   |  0x0003 - 0xfffe | Undefined; available to be assigned by IANA.   |
    //   |      0xffff      | Undefined; RESERVED.                           |
    //   +------------------+------------------------------------------------+
    unsigned short identifier_type_code;
    // NOTES: Need to create a union to break these up, based on the identifier_type_code
    // unsigned htype;
    // unsigned hlen;
} dns_additional_record_t;

typedef void *additional_records_t;

#pragma pack(pop)

void dns_packet_log(context_t *context, dns_packet_t *dns_packet, const char *template, ...);

question_t *dns_packet_get_question(dns_packet_t *dns_packet, unsigned index);

question_type_t *dns_question_type(question_t *question);

void dns_question_to_host(dns_packet_t *dns_packet, question_t *question, dns_string_ptr host);

size_t dns_packet_question_size(context_t *context, dns_packet_t *dns_packet);

unsigned int dns_packet_record_ttl_get(dns_packet_t *dns_packet, record_type_t record_type);

void dns_packet_record_ttl_set(dns_packet_t *dns_packet, record_type_t record_type, unsigned int new_ttl);

resource_resource_t *dns_packet_get_answer(dns_packet_t *dns_packet, unsigned int index);

void dns_resource_to_host(dns_packet_t *dns_packet, resource_resource_t *resource_record, dns_string_ptr host_name);

dns_resource_header_t *dns_resource_header_get(resource_resource_t *resource_record);

const char *dns_get_record_type_string(unsigned short record_type);

unsigned char *dns_get_resource_data(resource_resource_t *resource_record);

void dns_convert_to_host(dns_packet_t *dns_packet, const unsigned char *dns_host_string, dns_string_ptr host);

#endif //DNS_SERVICE_PROCESSING_H

#pragma clang diagnostic pop