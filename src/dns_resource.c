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

#include <arpa/inet.h>
#include "dns_packet.h"
#include "dns_resource.h"
#include "dns_question.h"

//Constant sized fields of the resource record structure
typedef struct dns_resource_t {
    record_type_t record_type;          // The RR type, for example, RECORD_A or RECORD_AAAA (see above)
    class_type_t record_class;          // A 16 bit value which defines the protocol family or an
    // instance of the protocol. The normal value is IN = Internet protocol
    // (other values are HS and CH both historic MIT protocols).
    uint32_t record_ttl;            // 32 bit value. The Time to Live in seconds (range is 1 to 2147483647)
    // and indicates how long the RR may be cached. The value zero indicates
    // the data should not be cached.
    uint16_t record_data_len;     // The length of RR specific data in octets, for example, 27
    char __unused record_data[];
} dns_resource_header;

bool dns_resource_name_is_pointer(dns_resource_handle resource) {
    if (NULL == resource)
        return false;

    //    The pointer takes the form of a two octet sequence:
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    | 1  1|                OFFSET                   |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    //    The first two bits are ones.  This allows a pointer to be distinguished
    //    from a label, since the label must begin with two zero bits because
    //    labels are restricted to 63 octets or less.  (The 10 and 01 combinations
    //    are reserved for future use.)  The OFFSET field specifies an offset from
    //    the start of the message (i.e., the first octet of the ID field in the
    //    domain header).  A zero offset specifies the first byte of the ID field,
    //    etc.
    return *((char *) resource) & 0xC0 ? true : false;
}

uint16_t dns_resource_pointer_offset(dns_resource_handle resource) {
    uint16_t value = 0;

    if (dns_resource_name_is_pointer(resource)) {
        //    The pointer takes the form of a two octet sequence:
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    | 1  1|                OFFSET                   |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        //    The first two bits are ones.  This allows a pointer to be distinguished
        //    from a label, since the label must begin with two zero bits because
        //    labels are restricted to 63 octets or less.  (The 10 and 01 combinations
        //    are reserved for future use.)  The OFFSET field specifies an offset from
        //    the start of the message (i.e., the first octet of the ID field in the
        //    domain header).  A zero offset specifies the first byte of the ID field,
        //    etc.
        uint16_t offset = *(uint16_t *) resource;
        value = ntohs(offset) & (uint16_t) 0x3FFF;
    }

    return value;
}

dns_resource_header *dns_resource_header_get(dns_resource_handle resource) {
    dns_resource_header *record_header = NULL;

    if (resource) {
        unsigned char *ptr = (unsigned char *) resource;
        if (dns_resource_name_is_pointer(resource)) {
            // Skip over pointer...
            ptr += sizeof(uint16_t);
        } else {
            // Skip over name...
            while (*ptr) {
                ptr += (*ptr + 1);
            }

            ptr++;
        }

        record_header = (dns_resource_header *) ptr;
    }

    return record_header;
}

dns_string *dns_resource_host(dns_packet *packet,
                                     dns_resource_handle resource) {
    unsigned char *string = (unsigned char *) resource;

    if (dns_resource_name_is_pointer(resource)) {
        string = (unsigned char *) packet + dns_resource_pointer_offset(resource);
    }

    dns_string *host = dns_string_new_empty();

    dns_string_to_host((const unsigned char *) string, host);

    return host;
}

dns_string *dns_resource_data_string(dns_packet *packet, dns_resource_handle resource){
    dns_string *string = NULL;

    if (resource != NULL && packet != NULL) {
        string = dns_string_new_empty();

        switch (dns_resource_record_type(resource)) {
            case RECORD_A:
            {
                struct sockaddr_in sa;
                char str[INET_ADDRSTRLEN];
                sa.sin_addr.s_addr = dns_resource_data_uint32(resource);
                inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
                dns_string_append_str(string, str);
            }
                break;
            case RECORD_NS:
                break;
            case RECORD_CNAME:
                break;
            case RECORD_SOA:
                break;
            case RECORD_WKS:
                break;
            case RECORD_PTR:
                break;
            case RECORD_MX:
            {
                uint16_t value = dns_resource_data_uint16(resource);
                dns_string_sprintf(string, "%d", value);
            }
                break;
            case RECORD_SRV:
                break;
            case RECORD_A6:
                break;
            case RECORD_AAAA:
                break;
            default:
                break;
        }
    }

    return string;
}

uint16_t dns_resource_data_uint16(dns_resource_handle resource){
    uint16_t value = 0;

    switch (dns_resource_record_type(resource)) {
        case RECORD_MX:
            ASSERT(NULL, dns_resource_header_get(resource)->record_data_len == 2);
            value = ntohs(*(uint16_t *)&dns_resource_header_get(resource)->record_data);
            break;
        default:
            DEBUG_LOG(NULL, "Invalid dns_resource_data_uint16");
            break;
    }

    return value;
}

uint32_t dns_resource_data_uint32(dns_resource_handle resource){
    uint32_t value = 0;

    ASSERT(NULL, dns_resource_header_get(resource)->record_data_len == 4);
    switch (dns_resource_record_type(resource)) {
        case RECORD_A:
            value = ntohl(*(uint32_t *)&dns_resource_header_get(resource)->record_data);
            break;
        case RECORD_SOA:
            // TODO: need to do a check on SOA to see if this is a 32 bit value.
            value = ntohl(*(uint32_t *)&dns_resource_header_get(resource)->record_data);
            break;
        default:
            DEBUG_LOG(NULL, "Invalid dns_resource_data_uint32");
            break;
    }

    return value;
}

record_type_t dns_resource_record_type(dns_resource_handle resource){
    if (resource == NULL){
        return RECORD_INVALID;
    }

    record_type_t type = ntohs(dns_resource_header_get(resource)->record_type);

    ASSERT(NULL, type > 0);

    return type;
}

class_type_t dns_resource_class_type(dns_resource_handle resource){
    if (resource == NULL){
        return CLASS_INVALID;
    }

    class_type_t class = ntohs(dns_resource_header_get(resource)->record_class);

    ASSERT(NULL, class > 0 && class < 5);

    return class;
}

uint32_t dns_resource_ttl(dns_resource_handle resource){
    if (resource == NULL){
        return 0;
    }

    uint32_t ttl = ntohl(dns_resource_header_get(resource)->record_ttl);

    ASSERT(NULL, ttl > 0);

    return ttl;
}

uint32_t dns_resource_ttl_set(dns_resource_handle resource, uint32_t new_ttl){
    if (resource == NULL){
        return 0;
    }

    uint32_t old_ttl = dns_resource_ttl(resource);

    dns_resource_header_get(resource)->record_ttl = htonl(new_ttl);

    return old_ttl;
}

uint32_t dns_resource_data_len(dns_resource_handle resource){
    if (resource == NULL){
        return 0;
    }

   return ntohs(dns_resource_header_get(resource)->record_data_len);
}

dns_resource_handle dns_resource_next(dns_resource_handle resource) {
    dns_resource_handle next_resource = NULL;

    if (resource) {

        dns_resource_header *record_header = dns_resource_header_get(resource);

        if (record_header) {
            next_resource = (dns_resource_handle) ((char *) record_header
                                                   + sizeof(dns_resource_header)
                                                   + ntohs(record_header->record_data_len));
        }
    }

    return next_resource;
}

dns_resource_handle dns_packet_resource_index(dns_packet *packet, uint16_t index) {

    dns_resource_handle resource_record = NULL;

    if (packet) {
        uint32_t resource_count = ntohs(packet->header.authority_count) +
                                      ntohs(packet->header.answer_count) +
                                      ntohs(packet->header.information_count);

        if (index < resource_count) {
            resource_record = (dns_resource_handle) dns_packet_question_skip(packet);

            for (unsigned count = 0; count < index; count++) {
                resource_record = dns_resource_next(resource_record);
            }
        }
    }

    return resource_record;
}


void dns_resource_log(dns_string *log_output,
                      dns_packet *packet,
                      dns_resource_handle resource) {
    if (resource && packet) {
        dns_string *host_name = dns_resource_host(packet, resource);

        dns_string *data_string = dns_resource_data_string(packet, resource);

        dns_string_sprintf(log_output, "    name: %s, type: 0x%X, class: 0x%X, ttl: %d, data length: %d, data: %s",
                           dns_string_c_str(host_name),
                           dns_resource_record_type(resource),
                           dns_resource_class_type(resource),
                           dns_resource_ttl(resource),
                           dns_resource_data_len(resource),
                           data_string);

        dns_string_free(data_string, true);
        dns_string_free(host_name, true);
    }
}

dns_resource_handle dns_packet_answer_get(dns_packet *packet, uint16_t index) {
    dns_resource_handle resource = NULL;

    if (packet){
        uint16_t answer_count = ntohs(packet->header.answer_count);

        if (index <= answer_count) {
            resource = dns_packet_resource_index(packet, index);
        }
    }

    return resource;
}

dns_resource_handle dns_packet_authority_get(dns_packet *packet, uint16_t index) {
    dns_resource_handle resource = NULL;

    if (packet){
        uint16_t authority_count = ntohs(packet->header.authority_count);

        if (index <= authority_count) {
            uint16_t resource_index = ntohs(packet->header.answer_count)
                                          +index;

            resource = dns_packet_resource_index(packet, resource_index);
        }
    }

    return resource;
}

dns_resource_handle dns_packet_information_get(dns_packet *packet, uint16_t index) {
    dns_resource_handle resource = NULL;

    if (packet) {
        uint16_t information_count = ntohs(packet->header.information_count);

        if (index < information_count) {
            uint16_t resource_index = ntohs(packet->header.answer_count) +
                                            ntohs(packet->header.authority_count)
                                            + index;
            resource = dns_packet_resource_index(packet, resource_index);
        }
    }

    return resource;
}


//
//dns_resource_header *dns_resource_header_get(dns_resource_header *resource_record) {
//    dns_resource_header *record_data = NULL;
//
//    if (resource_record) {
//
//        unsigned char *ptr = (unsigned char *) resource_record;
//        if (dns_resource_name_is_pointer(resource_record)) {
//            // Skip over pointer...
//            ptr += sizeof(uint16_t);
//        } else {
//            // Skip over name...
//            while (*ptr) {
//                ptr += (*ptr + 1);
//            }
//
//            ptr++;
//        }
//
//        record_data = (dns_resource_header *) ptr;
//    }
//
//    return record_data;
//}
//
//dns_resource_header *dns_resource_next(dns_resource_header *resource_record) {
//    dns_resource_header *next_resource = NULL;
//
//    if (resource_record) {
//
//        dns_resource_header *record_data = dns_resource_header_get(resource_record);
//
//        if (record_data) {
//            next_resource = (dns_resource_header *) ((char *) record_data + sizeof(dns_resource_header) +
//                                              ntohs(record_data->record_data_len));
//        }
//    }
//
//    return next_resource;
//}
//
//unsigned char *dns_resource_data_get(dns_resource_header *resource_record) {
//
//    if (resource_record) {
//
//        unsigned char *ptr = (unsigned char *) resource_record;
//        if (dns_resource_name_is_pointer(resource_record)) {
//            // Skip over pointer...
//            ptr += sizeof(uint16_t);
//        } else {
//
//            // Skip over name...
//            while (*ptr) {
//                ptr += (*ptr + 1);
//            }
//
//            ptr++;
//        }
//        return &ptr[sizeof(dns_resource_header)];
//    }
//
//    return NULL;
//}
//
//dns_resource_header *dns_packet_resource_index(dns_packet *packet, uint32_t index) {
//
//    dns_resource_header *resource_record = NULL;
//
//    if (packet) {
//        uint32_t information_count = ntohs(packet->header.authority_count) +
//                                      ntohs(packet->header.answer_count) +
//                                      ntohs(packet->header.information_count);
//
//        if (index < information_count) {
//            // Find the resource
//            //
//            resource_record = (dns_resource_header *)  dns_packet_question_skip(packet);
//            for (unsigned count = 0; count < index; count++) {
//                resource_record = dns_resource_next(resource_record);
//            }
//        }
//    }
//
//    return resource_record;
//}
//
//dns_resource_header *dns_packet_answer_get(dns_packet *packet, uint32_t index) {
//    dns_resource_header *resource_record = NULL;
//
//    if (index <= ntohs(packet->header.answer_count)) {
//        resource_record = dns_packet_resource_index(packet, index);
//    }
//
//    return resource_record;
//}
//
//
//dns_resource_header *dns_packet_authority_get(dns_packet *packet, uint32_t index) {
//    dns_resource_header *resource_record = NULL;
//
//    uint16_t authority_count = ntohs(packet->header.authority_count);
//    if (index <= authority_count) {
//        resource_record = dns_packet_resource_index(packet, index + ntohs(packet->header.answer_count));
//    }
//
//    return resource_record;
//}
//
//void dns_packet_resource_to_host(dns_packet *packet, dns_resource_header *resource_record,
//                                 dns_string *host_name) {
//    unsigned char *offset = (unsigned char *) resource_record;
//
//    if (dns_resource_name_is_pointer(resource_record)) {
//        offset = (unsigned char *) packet + dns_resource_pointer_offset(resource_record);
//    }
//
//    dns_packet_convert_to_host(packet, (const unsigned char *) offset, host_name);
//}
//
//void dns_resource_log(dns_string *log_output,
//                      dns_packet *packet,
//                      dns_resource_header *resource_record) {
//    if (resource_record) {
//        dns_string *host_name = dns_string_new(256);
//
//        dns_packet_resource_to_host(packet, resource_record, host_name);
//        if (dns_string_length(host_name) == 0) {
//            dns_packet_convert_to_host(packet, (const unsigned char *) packet->body, host_name);
//        }
//        dns_resource_header *record_data = dns_resource_header_get(resource_record);
//        if (record_data) {
//            dns_string_sprintf(log_output, "    name: %s, type: 0x%X, class: 0x%X, ttl: %d, data length: %d",
//                               dns_string_c_str(host_name),
//                               ntohs(record_data->record_type),
//                               ntohs(record_data->record_class),
//                               ntohs(record_data->record_ttl),
//                               ntohs(record_data->record_data_len));
//        }
//
//        dns_string_free(host_name, true);
//    }
//}