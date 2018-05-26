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
#ifndef DNS_SERVICE_UTILS_H
#define DNS_SERVICE_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <sys/syslog.h>

#ifndef _UUID_STRING_T
#define _UUID_STRING_T
typedef	char	uuid_string_t[37];
#endif

char *malloc_string(size_t size);

void free_string(char *);

char **malloc_string_array(size_t count);

void free_string_array(char **resolvers, size_t count);

void *memory_alloc(size_t n);

void *memory_clear(void *p, size_t n);

typedef struct context_t {
    uuid_t origination_uuid;
    long long start_time;
} transaction_context;

transaction_context context_create();

#if !defined(NDEBUG)
#define ASSERT(context, x)  {if (!(x)){log_message(LOG_ALERT, __FUNCTION__, __FILE__, __LINE__, context, "Assert Fired" );}}
#else
#define ASSERT(context, x) ((void)0)
#endif

#define ERROR_LOG(context, ...) log_message(LOG_CRIT, __FUNCTION__, __FILE__, __LINE__, context, __VA_ARGS__ )
#define DEBUG_LOG(context, ...) log_message(LOG_DEBUG, __FUNCTION__, __FILE__, __LINE__, context, __VA_ARGS__ )
#define INFO_LOG(context, ...) log_message(LOG_INFO, __FUNCTION__, __FILE__, __LINE__, context, __VA_ARGS__ )

void log_message(int log_level, const char *function, const char *file, int line, transaction_context *context,
                 const char *template, ...);

struct timespec timer_start();

long long timer_end(struct timespec start_time);

void create_logs(transaction_context *context);

void close_logs(transaction_context *context);

#define min(a, b) \
       ({ \
            __typeof__ (a) _a = (a); \
            __typeof__ (b) _b = (b); \
            _a < _b ? _a : _b; \
        })

#define max(a, b) \
       ({ \
            __typeof__ (a) _a = (a); \
            __typeof__ (b) _b = (b); \
            _a > _b ? _a : _b; \
        })

#endif //DNS_SERVICE_UTILS_H
