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

#include <stdlib.h>
#include <time.h>

#ifndef __MACH__
#define _POSIX_C_SOURCE 200809L
#define __unused
#include <strings.h>
#include <stdint.h>
#else

#include <ntsid.h>

#endif

#include "dns_array.h"
#include "dns_utils.h"

dns_array *dns_array_create(size_t cap) {
    dns_array *ca = memory_alloc(sizeof(dns_array));
    dns_array_init(ca, cap);
    return ca;
}

void dns_array_free(dns_array *array) {
    if (array) {
        dns_array_elements_free(array);
        free(array);
    }
}

int dns_array_elements_free(dns_array *array) {
    if (array->entries != NULL && array->cap != 0) {
        free(array->entries);
        array->entries = NULL;
    }
    array->count = 0;
    array->cap = 0;
    return 0;
}

int dns_array_init(dns_array *array, size_t cap) {
    array->count = 0;
    array->cap = cap;
    array->entries = NULL;

    array->entries = memory_alloc(sizeof(uintptr_t) * array->cap);
    if (array->entries == NULL) {
        return -1;
    }
    return 0;
}

int dns_array_set(dns_array *array, size_t index, uintptr_t entry) {
    if (index > array->count) {
        return -1;
    }
    array->entries[index] = entry;
    return 0;
}

int dns_array_push(dns_array *array, uintptr_t entry) {
    size_t left;

    left = array->cap - array->count;
    /* The array is full, resize it by power 2*/
    if (left == 0) {
        array->cap = array->cap * 2;
        array->entries = realloc(array->entries, sizeof(uintptr_t) * array->cap);
        if (array->entries == NULL) {
            return -1;
        }
    }

    array->entries[array->count] = entry;
    array->count++;
    return 0;
}

uintptr_t dns_array_top(dns_array *array) {
    return dns_array_get(array, dns_array_size(array) - 1);
}

uintptr_t dns_array_pop(dns_array *array) {
    uintptr_t e = 0;
    if (dns_array_size(array) > 0) {
        e = dns_array_get(array, dns_array_size(array) - 1);
        --array->count;
    }
    return e;
}

uintptr_t dns_array_get(dns_array *array, size_t index) {
    if (index > array->count) {
        return 0;
    }
    return array->entries[index];
}

size_t dns_array_size(dns_array *array) {
    return array->count;
}

//size_t etcd_array_cap(dns_array *ca) {
//    return ca->cap;
//}

dns_array *dns_array_shuffle(dns_array *cards) {
    size_t i, j, count;
    uintptr_t source, destination;

    srand((uint32_t) time(0));
    count = dns_array_size(cards);
    if (count <= 1) {
        return cards;
    }
    for (i = count - 1; i > 0; --i) {
        j = rand() % (i + 1); // NOLINT
        if (i != j) {
            source = dns_array_get(cards, i);
            destination = dns_array_get(cards, j);
            dns_array_set(cards, i, destination);
            dns_array_set(cards, j, source);
        }
    }

    return cards;
}