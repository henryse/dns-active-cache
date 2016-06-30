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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "dns_string.h"
#include "dns_utils.h"

dns_string_ptr dns_string_new(size_t size) {
    dns_string_ptr dns_string = (dns_string_ptr ) malloc(sizeof(dns_string_t));
    if (dns_string) {
        memory_clear(dns_string, sizeof(dns_string_t));

        dns_string->size = size;
        dns_string->c_string = (char *) malloc(size);
        memory_clear(dns_string->c_string, size);

        dns_string->position = 0;
    }

    return dns_string;
}

void dns_string_reset(dns_string_ptr dns_string) {
    dns_string->position = 0;
    memory_clear(dns_string->c_string, dns_string->size);
}

void dns_string_delete(dns_string_ptr dns_string, bool free_string) {

    if (free_string) {
        memory_clear(dns_string->c_string, dns_string->size);
        free(dns_string->c_string);
    }

    memory_clear(dns_string, sizeof(dns_string_t));
    free(dns_string);
}

bool string_buffer_resize(dns_string_ptr dns_string, const size_t new_size) {
    char *old_c_string = dns_string->c_string;

    dns_string->c_string = (char *) realloc(dns_string->c_string, new_size);
    if (dns_string->c_string == NULL) {
        dns_string->c_string = old_c_string;
        return false;
    }
    memory_clear(dns_string->c_string + dns_string->position, new_size - dns_string->position);

    dns_string->size = new_size;
    return true;
}

int string_buffer_double_size(dns_string_ptr dns_string) {
    return string_buffer_resize(dns_string, dns_string->size * 2);
}

void dns_string_append_char(dns_string_ptr dns_string, const char ch) {
    if (dns_string->position == dns_string->size) {
        string_buffer_double_size(dns_string);
    }

    dns_string->c_string[dns_string->position++] = ch;
}

void dns_string_append_str_length(dns_string_ptr dns_string, const char *src, size_t length) {
    size_t chars_remaining;
    size_t chars_required;
    size_t new_size;

    // <buffer size> - <zero based index of next char to write> - <space for null terminator>
    chars_remaining = dns_string->size - dns_string->position - 1;
    if (chars_remaining < length) {
        chars_required = length - chars_remaining;
        new_size = dns_string->size;
        do {
            new_size = new_size * 2;
        } while (new_size < (dns_string->size + chars_required));
        string_buffer_resize(dns_string, new_size);
    }

    memcpy(dns_string->c_string + dns_string->position, src, length);
    dns_string->position += length;
}

void dns_string_append_str(dns_string_ptr dns_string, const char *src) {
    dns_string_append_str_length(dns_string, src, strlen(src));
}

void dns_string_sprintf(dns_string_ptr dns_string, const char *template, ...) {
    char *str;
    va_list arg_list;

    va_start(arg_list, template);
    vasprintf(&str, template, arg_list);
    va_end(arg_list);

    if (!str) {
        return;
    }

    dns_string_append_str(dns_string, str);
    free(str);
}

int dns_string_strcmp(dns_string_ptr string_buffer_1, dns_string_ptr string_buffer_2) {
    // If they are both NULL then I guess they are "equal"
    //
    if (string_buffer_1 == NULL && string_buffer_2 == NULL) {
        return 0;
    }

    // If they are one is NULL then I guess they are "not equal"
    //
    if (string_buffer_1 == NULL) {
        return -1;
    }

    if (string_buffer_2 == NULL) {
        return 1;
    }

    return strncmp(dns_string_c_string(string_buffer_1),
                   dns_string_c_string(string_buffer_2),
                   max(dns_string_c_string_length(string_buffer_1),
                       dns_string_c_string_length(string_buffer_2)));
}
#pragma clang diagnostic pop