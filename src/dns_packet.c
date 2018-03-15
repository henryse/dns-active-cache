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

#define _GNU_SOURCE

#include <stdio.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include "dns_packet.h"
#include "dns_settings.h"
#include "dns_question.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"

// Converts names from: 3www7hotwire3com format to www.hotwire.com
//
void dns_packet_convert_to_host(dns_packet *packet, const unsigned char *dns_host_string, dns_string *host) {

    if (host != NULL) {

        dns_string_reset(host);

        if (packet != NULL && dns_host_string != NULL) {

            // Scan through the name, one character at a time. We need to look at
            // each character to look for values we can't print in order to allocate
            // extra space for escaping them.  'next_position' is the next_position to look
            // for a compression jump or name end.
            // It's possible that there are endless loops in the name. Our protection
            // against this is to make sure we don't read more bytes in this process
            // than twice the length of the data.  Names that take that many steps to
            // read in should be impossible.
            //
            size_t steps = 0;
            size_t position = (size_t) dns_host_string - (size_t) packet->body;
            size_t length = DNS_PACKET_SIZE;
            unsigned char *packet_body = (unsigned char *) packet->body;

            size_t next_position = position;
            while (position < length && !(next_position == position && packet_body[position] == 0) && steps < length * 2) {
                unsigned char c = packet_body[position];
                steps++;
                if (next_position == position) {
                    // Handle message compression.
                    // If the length byte starts with the bits 11(0xc0), then the rest of
                    // this byte and the next_position form the offset from the dns proto start
                    // to the start of the remainder of the name.
                    //
                    if ((c & 0xc0) == 0xc0) {
                        if (position + 1 >= length) {
                            ERROR_LOG(NULL, "Malformed DNS Packet");
                            return;
                        }

                        position = ((size_t) (((c & 0x3f) << 8) + packet_body[position + 1])) - sizeof(dns_header);

                        if (position >= length) {
                            ERROR_LOG(NULL, "Malformed DNS Packet, jumped off the end.");
                            return;
                        }

                        next_position = position;
                    } else {
                        position++;
                        next_position = next_position + c + 1;
                    }
                } else {
                    position++;
                }
            }

            // Due to the nature of DNS name compression, it's possible to get a
            // name that is infinitely long. Return an error in that case.
            // We use the len of the packet as the limit, because it shouldn't
            // be possible for the name to be that long.
            //
            if (steps >= 2 * length || position >= length) {
                ERROR_LOG(NULL, "DNS Name has to many steps or is to long: length: %d steps: %d", length, steps);
                return;
            }

            position = (size_t) dns_host_string - (size_t) packet->body;

            // Now actually assemble the name.
            // We've already made sure that we don't exceed the packet_body length, so
            // we don't need to make those checks anymore.
            // Non-printable and whitespace characters are replaced with a question
            // mark. They shouldn't be allowed under any circumstances anyway.
            // Other non-allowed characters are kept as is, as they appear sometimes
            // regardless.
            // This shouldn't interfere with IDNA (international domain names), as those are ascii encoded.
            //
            next_position = position;
            size_t i = 0;
            while (next_position != position || packet_body[position] != 0) {
                if (position == next_position) {
                    if ((packet_body[position] & 0xc0) == 0xc0) {
                        position = ((size_t) (((packet_body[position] & 0x3f) << 8) + packet_body[position + 1])) -
                                   sizeof(dns_header);
                        next_position = position;
                    } else {
                        // Add a period except for the first time.
                        if (i != 0) {
                            dns_string_append_char(host, '.');
                        }
                        next_position = position + packet_body[position] + 1;
                        position++;
                    }
                } else {
                    uint8_t c = packet_body[position];
                    if (c >= '!' && c <= '~' && c != '\\') {
                        dns_string_append_char(host, packet_body[position]);
                        i++;
                        position++;
                    } else {

                        dns_string_append_char(host, '\\');
                        dns_string_append_char(host, 'x');
                        char value = (const char) (c / 16 + 0x30);
                        if (value > 0x39) {
                            value += 0x27;
                        }
                        dns_string_append_char(host, value);

                        value = (const char) (c % 16 + 0x30);
                        if (value > 0x39) {
                            value += 0x27;
                        }
                        dns_string_append_char(host, value);
                        i += 4;
                        position++;
                    }
                }
            }
        }
    }
}

#pragma clang diagnostic pop

bool dns_resource_name_is_pointer(dns_resource *resource_record) {
    if (NULL == resource_record)
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
    return *((char *) resource_record) & 0xC0 ? true : false;

}

unsigned short dns_resource_pointer_offset(dns_resource *resource_record) {
    unsigned short value = 0;

    if (dns_resource_name_is_pointer(resource_record)) {
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
        unsigned short offset = *(unsigned short *) resource_record;
        value = ntohs(offset) & (unsigned short) 0x3FFF;
    }

    return value;
}

dns_resource *dns_resource_header_get(dns_resource *resource_record) {
    dns_resource *record_data = NULL;

    if (resource_record) {

        unsigned char *ptr = (unsigned char *) resource_record;
        if (dns_resource_name_is_pointer(resource_record)) {
            // Skip over pointer...
            ptr += sizeof(unsigned short);
        } else {
            // Skip over name...
            while (*ptr) {
                ptr += (*ptr + 1);
            }

            ptr++;
        }

        record_data = (dns_resource *) ptr;
    }

    return record_data;
}

dns_resource *dns_resource_next(dns_resource *resource_record) {
    dns_resource *next_resource = NULL;

    if (resource_record) {

        dns_resource *record_data = dns_resource_header_get(resource_record);

        if (record_data) {
            next_resource = (dns_resource *) ((char *) record_data + sizeof(dns_resource) +
                                                     ntohs(record_data->record_data_len));
        }
    }

    return next_resource;
}

unsigned char *dns_resource_data_get(dns_resource *resource_record) {

    if (resource_record) {

        unsigned char *ptr = (unsigned char *) resource_record;
        if (dns_resource_name_is_pointer(resource_record)) {
            // Skip over pointer...
            ptr += sizeof(unsigned short);
        } else {

            // Skip over name...
            while (*ptr) {
                ptr += (*ptr + 1);
            }

            ptr++;
        }
        return &ptr[sizeof(dns_resource)];
    }

    return NULL;
}

dns_resource *dns_packet_get_resource(dns_packet *packet, unsigned int index) {

    dns_resource *resource_record = NULL;

    if (packet) {
        unsigned int resource_count = ntohs(packet->header.authority_count) +
                                      ntohs(packet->header.answer_count) +
                                      ntohs(packet->header.resource_count);

        if (index < resource_count) {
            // Find the resource
            //
            resource_record = (dns_resource *)  dns_packet_question_skip(packet);
            for (unsigned count = 0; count < index; count++) {
                resource_record = dns_resource_next(resource_record);
            }
        }
    }

    return resource_record;
}

dns_resource *dns_packet_get_answer(dns_packet *packet, unsigned int index) {
    dns_resource *resource_record = NULL;

    if (index <= ntohs(packet->header.answer_count)) {
        resource_record = dns_packet_get_resource(packet, index);
    }

    return resource_record;
}


dns_resource *dns_packet_get_authority(dns_packet *packet, unsigned int index) {
    dns_resource *resource_record = NULL;

    unsigned short authority_count = ntohs(packet->header.authority_count);
    if (index <= authority_count) {
        resource_record = dns_packet_get_resource(packet, index + ntohs(packet->header.answer_count));
    }

    return resource_record;
}

void dns_packet_resource_to_host(dns_packet *packet, dns_resource *resource_record,
                                 dns_string *host_name) {
    unsigned char *offset = (unsigned char *) resource_record;

    if (dns_resource_name_is_pointer(resource_record)) {
        offset = (unsigned char *) packet + dns_resource_pointer_offset(resource_record);
    }

    dns_packet_convert_to_host(packet, (const unsigned char *) offset, host_name);
}

void dns_resource_log(dns_string *log_output,
                      dns_packet *packet,
                      dns_resource *resource_record) {
    if (resource_record) {
        dns_string *host_name = dns_string_new(256);

        dns_packet_resource_to_host(packet, resource_record, host_name);
        if (dns_string_length(host_name) == 0) {
            dns_packet_convert_to_host(packet, (const unsigned char *) packet->body, host_name);
        }
        dns_resource *record_data = dns_resource_header_get(resource_record);
        if (record_data) {
            dns_string_sprintf(log_output, "    name: %s, type: 0x%X, class: 0x%X, ttl: %d, data length: %d",
                               dns_string_c_str(host_name),
                               ntohs(record_data->record_type),
                               ntohs(record_data->record_class),
                               ntohs(record_data->record_ttl),
                               ntohs(record_data->record_data_len));
        }

        dns_string_free(host_name, true);
    }
}

void dns_packet_log(transaction_context *context, dns_packet *packet, const char *template, ...) {
    if (dns_get_debug_mode() && packet != NULL) {
        dns_header *header = &packet->header;

        dns_string *log_output = dns_string_new(4096);

        char *str;
        va_list arg_list;

        va_start(arg_list, template);
        vasprintf(&str, template, arg_list);
        va_end(arg_list);

        if (!str) {
            ERROR_LOG(context, "Failed to allocate logging string, out of memory?"
                    "  This is either a bug or an issue with the server.");
            dns_string_free(log_output, true);
            return;
        }

        dns_string_append_str(log_output, str);
        free(str);

        unsigned short answer_count = ntohs(packet->header.answer_count);
        unsigned short authority_count = ntohs(packet->header.authority_count);
        unsigned short resource_count = ntohs(packet->header.resource_count);
        unsigned short question_count = ntohs(packet->header.question_count);

        dns_string_sprintf(log_output, "  Identification number(id): %d\n", header->id);
        dns_string_sprintf(log_output, "  Recursion desired(recursion_desired): %d\n", header->recursion_desired);
        dns_string_sprintf(log_output, "  Truncated message(truncated_message): %d\n", header->truncated_message);
        dns_string_sprintf(log_output, "  Authoritative answer(authoritative_answer): %d\n", header->authoritative_answer);
        dns_string_sprintf(log_output, "  Purpose of message(operation_code): %d\n", header->operation_code);
        dns_string_sprintf(log_output, "  Query/response flag(query_response_flag): %d\n", header->query_response_flag);
        dns_string_sprintf(log_output, "  Response code(response_code): %d\n", header->response_code);
        dns_string_sprintf(log_output, "  Checking disabled(checking_disabled): %d\n", header->checking_disabled);
        dns_string_sprintf(log_output, "  Authenticated data(authenticated_data): %d\n", header->authenticated_data);
        dns_string_sprintf(log_output, "  Z Reserved(z_reserved): %d\n", header->z_reserved);
        dns_string_sprintf(log_output, "  Recursion available(recursion_available): %d\n", header->recursion_available);
        dns_string_sprintf(log_output, "  %d Questions(question_count).\n", question_count);
        dns_string_sprintf(log_output, "  %d Answers(answer_count).\n", answer_count);
        dns_string_sprintf(log_output, "  %d Authoritative Servers(authority_count).\n", authority_count);
        dns_string_sprintf(log_output, "  %d Additional records(resource_count).\n", resource_count);

        if (question_count) {
            dns_string_sprintf(log_output, "  Questions : \n");
            for (unsigned question_index = 0;
                 question_index < question_count;
                 question_index++) {

                dns_question_handle question = dns_packet_question_index(packet, question_index);

                if (question) {
                    dns_string *host_name = dns_question_host(question);

                    dns_string_sprintf(log_output, "    host: %s, question_header: %d, class: %d \n",
                                       dns_string_c_str(host_name),
                                       dns_question_type(question),
                                       dns_question_class(question));

                    dns_string_free(host_name, true);
                }
            }
        }

        if (answer_count) {
            dns_string_sprintf(log_output, "  Answers : \n");
            for (unsigned answer_index = 0; answer_index < answer_count; answer_index++) {
                dns_resource *answer = dns_packet_get_answer(packet, answer_index);
                dns_resource_log(log_output, packet, answer);
            }
        }

        if (authority_count) {
            dns_string_sprintf(log_output, "  Authority : \n");
            for (unsigned answer_index = 0;
                 answer_index < authority_count; answer_index++) {
                dns_resource *answer = dns_packet_get_authority(packet, answer_index);
                dns_resource_log(log_output, packet, answer);
            }
        }

        if (resource_count) {
            dns_string_sprintf(log_output, "\n  Resources : \n");
            for (unsigned resource_index = 0; resource_index < resource_count; resource_index++) {
                dns_resource *resource_records =  dns_packet_get_resource(packet, resource_index);
                dns_resource_log(log_output, packet, resource_records);
            }
        }

        DEBUG_LOG(context, "Packet Information: \n\n%s\n", dns_string_c_str(log_output));

        dns_string_free(log_output, true);
    }
}

unsigned int dns_packet_record_ttl_get(dns_packet *packet, record_type_t record_type) {

    unsigned int ttl_seconds = UINT_MAX;
    unsigned short answer_count = ntohs(packet->header.answer_count);

    if (answer_count) {

        for (unsigned answer_index = 0; answer_index < answer_count; answer_index++) {

            dns_resource *resource_record = dns_packet_get_answer(packet, answer_index);

            if (resource_record) {
                dns_string *host_name = dns_string_new(256);

                dns_packet_resource_to_host(packet, resource_record, host_name);

                dns_resource *record_data = dns_resource_header_get(resource_record);

                if (record_data && (ntohs(record_data->record_type) == record_type)) {
                    unsigned int record_ttl = ntohl(record_data->record_ttl);
                    ttl_seconds = min(ttl_seconds, record_ttl);
                }

                dns_string_free(host_name, true);
            }
        }
    }

    if (ttl_seconds == UINT_MAX) {
        ttl_seconds = dns_get_cache_polling_interval();
    }

    return ttl_seconds;
}

void dns_packet_record_ttl_set(dns_packet *packet, record_type_t record_type, unsigned int new_ttl) {

    unsigned short answer_count = ntohs(packet->header.answer_count);

    if (answer_count) {

        for (unsigned answer_index = 0; answer_index < answer_count; answer_index++) {

            dns_resource *resource_record = dns_packet_get_answer(packet, answer_index);

            if (resource_record) {
                dns_string *host_name = dns_string_new(256);

                dns_packet_resource_to_host(packet, resource_record, host_name);

                dns_resource *record_data = dns_resource_header_get(resource_record);

                if (record_data && (ntohs(record_data->record_type) == record_type)) {
                    record_data->record_ttl = htonl(new_ttl);
                }

                dns_string_free(host_name, true);
            }
        }
    }
}


const char *dns_record_type_string(unsigned short record_type) {
    switch (ntohs(record_type)) {
        case RECORD_A:
            return "A";
        case RECORD_NS:
            return "NS";
        case RECORD_CNAME:
            return "CNAME";
        case RECORD_SOA:
            return "SOA";
        case RECORD_WKS:
            return "WKS";
        case RECORD_PTR:
            return "RECORD";
        case RECORD_MX:
            return "MX";
        case RECORD_SRV:
            return "SRV";
        case RECORD_A6:
            return "A6";
        case RECORD_AAAA:
            return "AAAA";
        case RECORD_ANY:
            return "ANY";
        default:
            // Falls out to teh value below.
            break;
    }

    return "UNKNOWN";
}

#pragma clang diagnostic pop