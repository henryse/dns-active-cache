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

typedef struct __attribute__((packed)) question_header_t {
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


dns_string *dns_question_host(dns_question_handle question) {
    if (question == NULL) {
        return NULL;
    }

    dns_string *host = dns_string_new_empty();

    dns_string_to_host((const unsigned char *) question, host);

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
        return CLASS_INVALID;
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

dns_question_handle dns_question_name_set(dns_packet *packet, const char *host_name){
    dns_host_to_string(host_name, (char *) &packet->body);
    return &packet->body;
}

void dns_question_type_set(dns_question_handle question, record_type_t type){
    if (question){
        dns_question_header_get(question)->question_type = htons(type);
    }
}

void dns_question_class_set(dns_question_handle question, class_type_t class){
    if (question){
        dns_question_header_get(question)->question_class = htons(class);
    }
}
