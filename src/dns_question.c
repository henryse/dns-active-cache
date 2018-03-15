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

#include "dns_question.h"

typedef struct question_header_t {
    record_type_t question_type;
    class_type_t question_class;
} dns_question_header;

dns_question_handle *dns_packet_question_index(dns_packet *packet, unsigned index) {
    dns_question_handle *question = NULL;

    if (packet && index < ntohs(packet->header.question_count)) {
        question = (dns_question_handle *) packet->body;

        if (index) {
            for (unsigned count = 0; count < index; count++) {
                question = dns_question_next(question);
            }
        }
    }

    return question;
}

void *dns_packet_question_skip(dns_packet *packet) {
    if (packet == NULL) {
        return NULL;
    }

    // skip past the questions.
    //
    dns_question_handle question = (dns_question_handle *) packet->body;

    unsigned question_count = ntohs(packet->header.question_count);
    if (question_count) {
        for (unsigned count = 0; count < question_count; count++) {
            question = dns_question_next(question);
        }
    }

    return question;
}

// Converts names from: 3www7hotwire3com format to www.hotwire.com
//
void dns_question_convert_to_host(const unsigned char *qname, dns_string *host) {

    if (host != NULL) {

        dns_string_reset(host);

        if (qname != NULL) {

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
            const unsigned char *packet_body = qname;

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

dns_string *dns_question_host(dns_question_handle question) {
    if (question == NULL) {
        return NULL;
    }

    dns_string *host = dns_string_new_empty();

    dns_question_convert_to_host((const unsigned char *) question, host);

    return host;
}

dns_question_header *dns_question_header_get(dns_question_handle question) {
    // Skip past the strings.
    //
    unsigned char *count = (unsigned char *) question;

    while (*count) {
        count += (*count + 1);
    }

    count++;

    return (dns_question_header *) count;
}

record_type_t dns_question_type(dns_question_handle question) {
    if (question == NULL) {
        return RECORD_INVALID;
    }

    record_type_t type = ntohs(dns_question_header_get(question)->question_type);

    ASSERT(NULL, type != 0);

    return type;
}

class_type_t dns_question_class(dns_question_handle question) {
    if (question == NULL) {
        return RECORD_INVALID;
    }

    class_type_t class = ntohs(dns_question_header_get(question)->question_class);

    ASSERT(NULL, class > 0 && class < 5);

    return class;
}

dns_question_handle dns_question_next(dns_question_handle question) {
    dns_question_header *next_question = NULL;

    if (question) {
        unsigned char *count = (unsigned char *) question;

        while (*count) {
            count += (*count + 1);
        }

        count++;

        next_question = (dns_question_header *) (count + sizeof(dns_question_header));
    }

    return next_question;
}

size_t dns_packet_question_size(transaction_context *context, dns_packet *packet) {
    ASSERT(context, packet);

    if (packet) {
        dns_question_handle question = (dns_question_handle) packet->body;

        for (int index = 0; index < ntohs(packet->header.question_count); index++) {
            question = dns_question_next(question);
        }

        return (unsigned char *) question - (unsigned char *) packet;
    }

    return 0;
}
