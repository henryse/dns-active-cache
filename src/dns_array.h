/**********************************************************************
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
//    This file is derived from: https://github.com/shafreeck/cetcd
//
**********************************************************************/

#ifndef DNS_ACTIVE_CACHE_DNS_ARRAY_H
#define DNS_ACTIVE_CACHE_DNS_ARRAY_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct dns_array_t {
    uintptr_t *entries;
    size_t count;
    size_t cap;
} dns_array;

size_t dns_array_size(dns_array *array);
// size_t etcd_array_cap(dns_array *ca);

dns_array *dns_array_create(size_t cap);

void dns_array_free(dns_array *array);

int dns_array_init(dns_array *array, size_t cap);

int dns_array_elements_free(dns_array *array);

int dns_array_push(dns_array *array, uintptr_t entry);

uintptr_t dns_array_get(dns_array *array, size_t index);

int dns_array_set(dns_array *array, size_t index, uintptr_t entry);

uintptr_t dns_array_top(dns_array *array);

uintptr_t dns_array_pop(dns_array *array);

dns_array *dns_array_shuffle(dns_array *cards);

#endif //DNS_ACTIVE_CACHE_DNS_ARRAY_H
