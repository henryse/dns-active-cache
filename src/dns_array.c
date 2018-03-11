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

#include "dns_array.h"
#include "dns_utils.h"

dns_array *dns_array_create(size_t cap) {
    dns_array *ca = memory_alloc(sizeof(dns_array));
    dns_array_init(ca, cap);
    return ca;
}

void dns_array_release(dns_array *ca) {
    if (ca) {
        dns_array_destroy(ca);
        free(ca);
    }
}

int dns_array_init(dns_array *ca, size_t cap) {
    ca->count = 0;
    ca->cap = cap;
    ca->elem = NULL;

    ca->elem = malloc(sizeof(void *) * ca->cap);
    if (ca->elem == NULL) {
        return -1;
    }
    return 0;
}

int dns_array_set(dns_array *ca, size_t index, void *p) {
    if (index > ca->count) {
        return -1;
    }
    ca->elem[index] = p;
    return 0;
}

int dns_array_append(dns_array *ca, void *p) {
    size_t left;

    left = ca->cap - ca->count;
    /* The array is full, resize it by power 2*/
    if (left == 0) {
        ca->cap = ca->cap * 2;
        ca->elem = realloc(ca->elem, sizeof(void *) * ca->cap);
        if (ca->elem == NULL) {
            return -1;
        }
    }

    ca->elem[ca->count] = p;
    ca->count++;
    return 0;
}

void *dns_array_top(dns_array *ca) {
    return dns_array_get(ca, dns_array_size(ca) - 1);
}

void *dns_array_pop(dns_array *ca) {
    void *e = NULL;
    if (dns_array_size(ca) > 0) {
        e = dns_array_get(ca, dns_array_size(ca) - 1);
        --ca->count;
    }
    return e;
}

int dns_array_destroy(dns_array *ca) {
    if (ca->elem != NULL && ca->cap != 0) {
        free(ca->elem);
        ca->elem = NULL;
    }
    ca->count = 0;
    ca->cap = 0;
    return 0;
}

void *dns_array_get(dns_array *ca, size_t index) {
    if (index > ca->count) {
        return NULL;
    }
    return ca->elem[index];
}

size_t dns_array_size(dns_array *ca) {
    return ca->count;
}

//size_t etcd_array_cap(dns_array *ca) {
//    return ca->cap;
//}

dns_array *dns_array_shuffle(dns_array *cards) {
    size_t i, j, count;
    void *src, *dst;

    srand((unsigned int) time(0));
    count = dns_array_size(cards);
    if (count <= 1) {
        return cards;
    }
    for (i = count - 1; i > 0; --i) {
        j = rand() % (i + 1); // NOLINT
        if (i != j) {
            src = dns_array_get(cards, i);
            dst = dns_array_get(cards, j);
            dns_array_set(cards, i, dst);
            dns_array_set(cards, j, src);
        }
    }

    return cards;
}