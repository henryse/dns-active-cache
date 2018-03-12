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
#ifndef DNS_ACTIVE_CACHE_STRING_H
#define DNS_ACTIVE_CACHE_STRING_H

#include <stdbool.h>
#include "dns_array.h"

typedef struct dns_string_t {
    size_t position;        // Position of end of the string
    size_t size;            // Buffer Size, position must be less than size
    char *c_string;         // Data buffer
} dns_string;

typedef dns_array dns_string_array;

typedef dns_string_array *dns_string_array_ptr;

dns_string *dns_string_new(size_t size);

dns_string *dns_string_new_empty();

dns_string *dns_string_new_c_string(size_t size, const char *string);

dns_string *dns_string_new_str(dns_string *source);

void dns_string_free(dns_string *target, bool free_string);

void dns_string_reset(dns_string *target);

void dns_string_trim(dns_string *target, size_t length);

void dns_string_append_char(dns_string *target, char ch);

void dns_string_append_str_length(dns_string *target, const char *source, size_t length);

void dns_string_append_str(dns_string *target, const char *source);

dns_string *dns_string_sprintf(dns_string *target, const char *fmt, ...);

int dns_string_strcmp(dns_string *string_1, dns_string *string_2);

char *dns_string_c_str(dns_string *target);

size_t dns_string_length(dns_string *target);

dns_string_array_ptr dns_string_split_length(dns_string *target, const char *separator, size_t *count);

dns_string_array_ptr dns_string_array_new(size_t size);

void dns_string_array_destroy(dns_string_array_ptr string_array);

void dns_string_array_delete(dns_string_array_ptr string_array);

void dns_string_tolower(dns_string *target);

void dns_string_toupper(dns_string *target);

#endif //DNS_ACTIVE_CACHE_STRING_H
#pragma clang diagnostic pop