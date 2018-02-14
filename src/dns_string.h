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

#ifndef DNS_ACTIVE_CACHE_STRING_H
#define DNS_ACTIVE_CACHE_STRING_H

#include <stdbool.h>

typedef struct dns_string_struct {
    char *c_string;         // Data buffer
    size_t position;        // Position of end of the string
    size_t size;            // Buffer Size, position must be less than size
} dns_string_t;

typedef dns_string_t *dns_string_ptr;

dns_string_ptr dns_string_new(size_t size);

void dns_string_delete(dns_string_ptr dns_string, bool free_string);

void dns_string_reset(dns_string_ptr dns_string);

void dns_string_trim(dns_string_ptr dns_string, size_t length);

void dns_string_append_char(dns_string_ptr dns_string, char ch);

void dns_string_append_str_length(dns_string_ptr dns_string, const char *src, size_t length);

void dns_string_append_str(dns_string_ptr dns_string, const char *src);

void dns_string_sprintf(dns_string_ptr dns_string, const char *fmt, ...);

int dns_string_strcmp(dns_string_ptr string_buffer_1, dns_string_ptr string_buffer_2);

#define dns_string_c_string(dns_string) ((dns_string)->c_string)

#define dns_string_c_string_length(dns_string) ((dns_string)->position)

#endif //DNS_ACTIVE_CACHE_STRING_H