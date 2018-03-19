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
#pragma ide diagnostic ignored "OCUnusedMacroInspection"

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "dns_string.h"
#include "dns_utils.h"

dns_string *dns_string_new(size_t size) {
    dns_string *new_string = (dns_string *) memory_alloc(sizeof(dns_string));
    if (new_string) {
        size = max(size, 4);

        new_string->size = size;
        new_string->c_string = (char *) memory_alloc(size);
        new_string->position = 0;
    }

    return new_string;
}

dns_string *dns_string_new_empty() {
    return dns_string_new(16);
}

dns_string *dns_string_new_c(size_t size, const char *string) {
    size_t computed_size = max(size, strlen(string));
    dns_string *new_string = dns_string_new(computed_size);
    dns_string_append_str_length(new_string, string, computed_size);
    return new_string;
}

dns_string *dns_string_new_fixed(size_t size, const char *string) {
    dns_string *new_string = dns_string_new(size);
    dns_string_append_str_length(new_string, string, size);
    return new_string;
}

dns_string *dns_string_new_str(dns_string *source) {
    dns_string *new_string = dns_string_new(dns_string_length(source));
    dns_string_append_str(new_string, dns_string_c_str(source));

    return new_string;
}

void dns_string_reset(dns_string *target) {
    if (NULL != target) {
        target->position = 0;
        memory_clear(target->c_string, target->size);
    }
}

void dns_string_free(dns_string *target, bool free_string) {

    if (target) {
        if (free_string) {
            memory_clear(target->c_string, target->size);
            free(target->c_string);
            target->c_string = NULL;
        }

        memory_clear(target, sizeof(dns_string));
        free(target);
    }
}

bool string_buffer_realloc(dns_string *target, const size_t new_size) {

    if (NULL == target) {
        return false;
    }

    char *old_c_string = target->c_string;

    target->c_string = (char *) realloc(target->c_string, new_size);
    if (target->c_string == NULL) {
        target->c_string = old_c_string;
        return false;
    }
    memory_clear(target->c_string + target->position, new_size - target->position);

    target->size = new_size;
    return true;
}

int string_buffer_double_size(dns_string *target) {
    return string_buffer_realloc(target, target->size * 2);
}

void dns_string_trim(dns_string *target, size_t length) {
    if (NULL == target) {
        return;
    }

    if (length >= target->position) {
        target->position = 0;
    } else {
        target->position = target->position - length;
    }
}

void dns_string_append_char(dns_string *target, char ch) {
    if (NULL == target) {
        return;
    }

    if (target->position == target->size - 1) {
        string_buffer_double_size(target);
    }

    target->c_string[target->position++] = ch;
}

void dns_string_append_str_length(dns_string *target, const char *source, size_t length) {

    if (NULL == target || NULL == source) {
        return;
    }

    size_t chars_remaining;
    size_t chars_required;
    size_t new_size;

    // <buffer size> - <zero based index of next char to write> - <space for null terminator>
    chars_remaining = target->size - target->position - 1;
    if (chars_remaining < length) {
        chars_required = length - chars_remaining;
        new_size = target->size;
        do {
            new_size = new_size * 2;
        } while (new_size < (target->size + chars_required));
        string_buffer_realloc(target, new_size);
    }

    memcpy(target->c_string + target->position, source, length);
    target->position += length;
}

void dns_string_append_str(dns_string *target, const char *source) {
    dns_string_append_str_length(target, source, strlen(source));
}

dns_string *dns_string_sprintf(dns_string *target, const char *template, ...) {
    if (NULL == target) {
        return target;
    }

    char *str;
    va_list arg_list;

    va_start(arg_list, template);
    vasprintf(&str, template, arg_list);
    va_end(arg_list);

    if (!str) {
        return NULL;
    }

    dns_string_append_str(target, str);
    memory_clear(str, strlen(str));
    free(str);

    return target;
}

int dns_string_strcmp(dns_string *string_1, dns_string *string_2) {
    // If they are both NULL then I guess they are "equal"
    //
    if (string_1 == NULL && string_2 == NULL) {
        return 0;
    }

    // If they are one is NULL then I guess they are "not equal"
    //
    if (string_1 == NULL) {
        return -1;
    }

    if (string_2 == NULL) {
        return 1;
    }

    return strncmp(dns_string_c_str(string_1),
                   dns_string_c_str(string_2),
                   max(dns_string_length(string_1),
                       dns_string_length(string_2)));
}

size_t dns_string_token_count(dns_string *string, const char *sep) {
    char *str = alloca(dns_string_length(string));

    strcpy(str, dns_string_c_str(string));

    char *pch = strtok(str, sep);
    size_t count = 0;

    while (pch != NULL) {
        pch = strtok(NULL, sep);
        count++;
    }
    return count;
}

char *g_empty_string = "";

char *dns_string_c_str(dns_string *target) {
    if (target == NULL) {
        return g_empty_string;
    }

    return target->c_string;
}

size_t dns_string_length(dns_string *target) {
    if (target == NULL) {
        return 0;
    }

    return target->position;

}

dns_string_array *dns_string_array_new(size_t size) {
    return dns_array_create(size);
}

void dns_string_array_destroy(dns_string_array *string_array) {
    size_t count = dns_array_size(string_array);

    for (size_t index = 0; index < count; index++) {
        dns_string_free(dns_array_get(string_array, index), true);
        dns_array_set(string_array, index, NULL);
    }
    dns_array_destroy(string_array);
}

void dns_string_array_delete(dns_string_array *string_array) {

    if (string_array) {
        dns_string_array_destroy(string_array);
        free(string_array);
    }
}

dns_string_array *dns_string_split_length(dns_string *target, const char *separator, size_t *count) {

    if (target == NULL || separator == NULL || *dns_string_c_str(target) == '\0' || *separator == '\0') {
        return NULL;
    }

    size_t token_count = dns_string_token_count(target, separator);

    if (count) {
        *count = token_count;
    }

    // Allocate the array to return.
    //
    dns_string_array *string_array = dns_string_array_new(token_count);

    // Create a temp location for strtok to use.
    //
    char *str = alloca(dns_string_length(target));
    strcpy(str, dns_string_c_str(target));
    char *pch = strtok(str, separator);

    // Loop through and break it up.
    //
    size_t item_count = 0;
    while (pch != NULL && item_count < token_count) {
        dns_array_append(string_array, dns_string_new_c(strlen(pch), pch));
        pch = strtok(NULL, separator);
        item_count++;
    }

    return string_array;
}


void dns_string_tolower(dns_string *target) {
    if (target && target->position) {
        size_t len = dns_string_length(target);

        for (int index = 0; index < len; index++) {
            target->c_string[index] = (char) tolower(target->c_string[index]);
        }
    }
}

void dns_string_toupper(dns_string *target) {
    if (target && target->position) {
        size_t len = dns_string_length(target);

        for (int index = 0; index < len; index++) {
            target->c_string[index] = (char) toupper(target->c_string[index]);
        }
    }
}

#pragma clang diagnostic pop