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
#include "dns_resource.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"

// Converts names from: 3www7hotwire3com format to www.hotwire.com
//
void dns_string_to_host(const unsigned char *string, dns_string *host) {

    if (host != NULL) {

        dns_string_reset(host);

        if (string != NULL) {

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
            size_t position = 0;
            size_t length = DNS_PACKET_SIZE;
            const unsigned char *packet_body = string;

            size_t next_position = position;
            while (position < length && !(next_position == position && packet_body[position] == 0) &&
                   steps < length * 2) {
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

            position = 0;

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

        uint16_t answer_count = ntohs(packet->header.answer_count);
        uint16_t authority_count = ntohs(packet->header.authority_count);
        uint16_t information_count = ntohs(packet->header.information_count);
        uint16_t question_count = ntohs(packet->header.question_count);

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
        dns_string_sprintf(log_output, "  %d Additional records(information_count).\n", information_count);

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
            for (uint16_t answer_index = 0; answer_index < answer_count; answer_index++) {
                dns_resource_log(log_output, packet, dns_packet_answer_get(packet, answer_index));
            }
        }

        if (authority_count) {
            dns_string_sprintf(log_output, "  Authority : \n");
            for (uint16_t authority_index = 0; authority_index < authority_count; authority_index++) {
                dns_resource_log(log_output, packet, dns_packet_authority_get(packet, authority_index));
            }
        }

        if (information_count) {
            dns_string_sprintf(log_output, "\n  Resources : \n");
            for (uint16_t information_index = 0; information_index < information_count; information_index++) {
                dns_resource_log(log_output, packet, dns_packet_information_get(packet, information_index));
            }
        }

        DEBUG_LOG(context, "Packet Information: \n\n%s\n", dns_string_c_str(log_output));

        dns_string_free(log_output, true);
    }
}

uint32_t dns_packet_record_ttl_get(dns_packet *packet, record_type_t record_type) {

    uint32_t ttl_seconds = UINT_MAX;
    uint16_t answer_count = ntohs(packet->header.answer_count);

    if (answer_count) {

        for (uint16_t answer_index = 0; answer_index < answer_count; answer_index++) {

            dns_resource_handle resource = dns_packet_answer_get(packet, answer_index);

            if (resource) {
                if (dns_resource_record_type(resource) == record_type) {
                    uint32_t record_ttl = dns_resource_ttl(resource);
                    ttl_seconds = min(ttl_seconds, record_ttl);
                }
            }
        }
    }

    if (ttl_seconds == UINT_MAX) {
        ttl_seconds = dns_get_cache_polling_interval();
    }

    return ttl_seconds;
}

void dns_packet_record_ttl_set(dns_packet *packet, record_type_t record_type, uint32_t new_ttl) {

    uint16_t answer_count = ntohs(packet->header.answer_count);

    if (answer_count) {

        for (uint16_t answer_index = 0; answer_index < answer_count; answer_index++) {

            dns_resource_handle resource = dns_packet_answer_get(packet, answer_index);

            if (resource) {
                if (dns_resource_record_type(resource) == record_type) {
                    dns_resource_ttl_set(resource, new_ttl);
                }
            }
        }
    }
}


const char *dns_record_type_string(uint16_t record_type) {
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