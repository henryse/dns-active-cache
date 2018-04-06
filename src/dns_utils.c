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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <uuid/uuid.h>

#ifdef __MACH__

#include <mach/clock.h>
#include <mach/mach.h>

#endif

#include "dns_utils.h"
#include "dns_settings.h"
#include "dns_string.h"

char *malloc_string(size_t size) {
    char *string = malloc(size + 1);
    if (string) {
        memset(string, 0, size + 1);
    }
    return string;
}

void free_string(char *string) {
    if (string != NULL) {
        memory_clear(string, strlen(string));
        free(string);
    }
}

char **malloc_string_array(size_t count) {
    size_t size = count * sizeof(char *);

    void *buffer = malloc(size);

    if (buffer) {
        memset(buffer, 0, size);
    }

    return buffer;
}

void free_string_array(char **resolvers, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free_string(resolvers[i]);
    }
}

void *memory_alloc(size_t n) {
    void *p = malloc(n);
    if (p) {
        memory_clear(p, n);
    }
    return p;
}

void *memory_clear(void *p, size_t n) {
    if (NULL != p) {
        memset(p, 0, n);
    }

    return p;
}

void current_utc_time(struct timespec *ts) {

    memory_clear(ts, sizeof(struct timespec));

#ifdef __MACH__
    // OS X does not have clock_gettime, use clock_get_time
    //
    clock_serv_t c_clock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &c_clock);
    clock_get_time(c_clock, &mts);
    mach_port_deallocate(mach_task_self(), c_clock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    // How everyone else does it.
    //
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

// call this function to start a nanosecond-resolution timer
//
struct timespec timer_start() {
    struct timespec start_time;
    current_utc_time(&start_time);
    return start_time;
}

static const long long kNsPerSec = 1000000000;

// Convert timespec to nanoseconds
//
long long timespec_to_ns(const struct timespec *ts) {
    long long base_ns = (long long) (ts->tv_sec) * kNsPerSec;
    return base_ns + (long long) (ts->tv_nsec);
}

// call this function to end a timer, returning nanoseconds elapsed as a long
//
long long timer_end(struct timespec start_time) {
    struct timespec end_time;
    current_utc_time(&end_time);

    return timespec_to_ns(&end_time) - timespec_to_ns(&start_time);
}

transaction_context create_context() {
    transaction_context context;
    memory_clear(&context, sizeof context);

    uuid_generate(context.origination_uuid);
    struct timespec now = timer_start();

    context.start_time = timespec_to_ns(&now);
    return context;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wuninitialized"

void create_output_header(dns_string *output, const char *status, const char *function, const char *file,
                          int line, transaction_context *context) {

    // Build Context ID
    //
    uuid_string_t context_uuid_string;
    memory_clear(context_uuid_string, sizeof(context_uuid_string));

    long long time_diff = 0;
    if (context) {
        uuid_unparse(context->origination_uuid, context_uuid_string);
        struct timespec now = timer_start();
        time_diff = timespec_to_ns(&now) - context->start_time;
    }

    // Output the common header
    //
    dns_string_sprintf(output,
                       "service=dns_active_cache;context=%s;timediff=%lld;status=%s;location=%s:%d;function=%s;message=",
                       context_uuid_string,
                       time_diff,
                       status,
                       file,
                       line,
                       function);
}

#pragma clang diagnostic pop

void log_message(int log_level,
                 const char *function,
                 const char *file,
                 int line,
                 transaction_context *context,
                 const char *template, ...) {

    char *message_type = NULL;
    bool log_message;

    switch (log_level) {
        case LOG_EMERG:
        case LOG_ALERT:
        case LOG_CRIT:
        case LOG_ERR:
        case LOG_WARNING:
            message_type = "ERROR";
            log_message = true;
            break;
        case LOG_NOTICE:
        case LOG_INFO:
            message_type = "INFO";
            log_message = dns_log_mode_get();
            break;

        case LOG_DEBUG:
        default:
            message_type = "DEBUG";
            log_message = dns_log_mode_get();
            break;
    }

    if (log_message) {
        dns_string *output = dns_string_new(1024);

        create_output_header(output, message_type, function, file, line, context);

        char *str = NULL;
        va_list arg_list;

        va_start(arg_list, template);
        vasprintf(&str, template, arg_list);
        va_end(arg_list);

        if (str) {
            dns_string_append_str(output, str);
            memory_clear(str, strlen(str));
            free(str);
        }

        syslog(log_level, "%s", dns_string_c_str(output));

        dns_string_free(output, true);
    }
}

void create_logs() {
    setlogmask(LOG_UPTO (LOG_DEBUG));
    openlog("dns_active_cache", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0);
}

void close_logs() {
    closelog();
}

#pragma clang diagnostic pop