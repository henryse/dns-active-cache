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

#include <sys/cdefs.h>

#ifndef __MACH__
#define _POSIX_C_SOURCE 200809L
#define __unused
#endif

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dns_cache.h"
#include "dns_service.h"
#include "dns_settings.h"

// Internal cache structure, it is never passed outside
// of this area, copies of the dns_cache_entry can be
// returned to the caller but never this structure.
//
typedef struct dns_cache_record_struct {
    struct dns_cache_record_struct *next;   // Next record in the list.
    long reference_count;                   // Reference count, may be able to get rid of this...
    unsigned int expired_time_stamp;        // Timestamp to expire record
    unsigned int created_time_stamp;        // Timestamp record was created

    dns_cache_entry_t dns_cache_entry;      // Entry to return the caller.
} dns_cache_record_t;

dns_cache_record_t *g_head = NULL;
dns_cache_record_t *g_records = NULL;
size_t g_record_used_count = 0;

bool g_dns_refresh_cache_loop = true;
pthread_t g_dns_cache_thread_id = 0;

int g_dns_cache_socket = 0;

unsigned int dns_get_timestamp_now() {
    // Setup the entry
    //
    struct timespec time_now = timer_start();

    // expired_time_stamp in seconds
    //
    long seconds = time_now.tv_sec + (time_now.tv_nsec / 1000000000);

    return (unsigned int) seconds;
}

void dns_cache_record_hold(context_t *context, dns_cache_record_t *dns_cache_record) {
    ASSERT(context, dns_cache_record);

    if (dns_cache_record) {
        __sync_fetch_and_add(&dns_cache_record->reference_count, 1);
        ASSERT(context, dns_cache_record->reference_count < 4);
    }
}

void dns_cache_record_release(context_t *context, dns_cache_record_t *dns_cache_record) {
    ASSERT(context, dns_cache_record);

    if (dns_cache_record) {
        __sync_fetch_and_sub(&dns_cache_record->reference_count, 1);
        ASSERT(context, dns_cache_record->reference_count >= 0);
    }
}

// The lock used to secure the volatile head of the list.
// only dns_cache_acquire_head and dns_cache_release_head should
// use this global variable.
//
int g_dns_head_lock = 0;

dns_cache_record_t *dns_cache_acquire_head() {
    while (__sync_lock_test_and_set(&g_dns_head_lock, 1)) while (g_dns_head_lock);
    return g_head;
}

void dns_cache_release_head() {
    __sync_lock_release(&g_dns_head_lock);
}

dns_cache_record_t *dns_get_head(context_t *context) {

    ASSERT(context, context);

    dns_cache_record_t *head = dns_cache_acquire_head();

    if (head) {
        dns_cache_record_hold(context, head);
    }

    dns_cache_release_head();

    return head;
}

dns_cache_record_t *dns_get_next_record(context_t *context, dns_cache_record_t *dns_cache_record) {

    dns_cache_record_t *dns_record_next = NULL;

    if (dns_cache_record) {
        ASSERT(context, dns_cache_record->dns_cache_entry.entry_state == ENTRY_ENABLED);

        if (dns_cache_record->next) {
            dns_record_next = dns_cache_record->next;
            dns_cache_record_hold(context, dns_record_next);
        }

        dns_cache_record_release(context, dns_cache_record);
    }

    return dns_record_next;
}

void dns_cache_log(context_t *context) {
    if (dns_get_debug_mode()) {
        dns_cache_record_t *record = dns_get_head(context);

        if (record) {
            dns_string_ptr log_data = dns_string_new(1024);

            dns_string_sprintf(log_data, "\nquestion, expired_time_stamp, reference_count, entry_state\n");

            while (record) {
                question_t *question = dns_packet_get_question(&record->dns_cache_entry.dns_packet_response, 0);

                dns_string_ptr host_name = dns_string_new(64);

                dns_question_to_host(&record->dns_cache_entry.dns_packet_response, question, host_name);

                dns_string_sprintf(log_data, "%s: %ld, %ld, %d \n",
                                   dns_string_c_string(host_name),
                                   record->expired_time_stamp - dns_get_timestamp_now(),
                                   record->reference_count,
                                   record->dns_cache_entry.entry_state);

                dns_string_delete(host_name, true);

                record = dns_get_next_record(context, record);
            }

            DEBUG_LOG(context, dns_string_c_string(log_data));

            dns_string_delete(log_data, true);
        }

    }
}

void dns_cache_http_answers(dns_cache_record_t *record, dns_string_ptr response) {

    if (record && record->dns_cache_entry.dns_packet_response_size) {
        dns_packet_t *dns_packet = &record->dns_cache_entry.dns_packet_response;

        dns_string_ptr host_name = dns_string_new(64);
        dns_string_ptr resource_information = dns_string_new(64);

        unsigned short answer_count = ntohs(dns_packet->header.answer_count);
        if (answer_count) {
            for (unsigned answer_index = 0; answer_index < answer_count; answer_index++) {
                resource_resource_t *answer = dns_packet_get_answer(dns_packet, answer_index);

                if (answer) {
                    dns_resource_to_host(dns_packet, answer, host_name);
                    dns_resource_header_t *record_header = dns_resource_header_get(answer);
                    if (record_header) {

                        if (ntohs(record_header->record_type) == RECORD_CNAME) {
                            dns_convert_to_host(dns_packet, dns_get_resource_data(answer), resource_information);
                        }
                        else if (ntohs(record_header->record_type) == RECORD_A) {
                            long *ptr_address = (long *) dns_get_resource_data(answer);
                            struct sockaddr_in address;
                            address.sin_addr.s_addr = (in_addr_t) (*ptr_address);
                            dns_string_reset(resource_information);
                            dns_string_sprintf(resource_information, "%s", inet_ntoa(address.sin_addr));
                        }
                        else {
                            dns_string_reset(resource_information);
                            dns_string_sprintf(resource_information, "Not implemented for %s",
                                               dns_get_record_type_string(record_header->record_type));
                        }

                        dns_string_sprintf(response, "<P>%s, %s, %s</P>",
                                           dns_string_c_string(host_name),
                                           dns_get_record_type_string(record_header->record_type),
                                           dns_string_c_string(resource_information));
                    }
                }
            }
        }

        dns_string_delete(resource_information, true);
        dns_string_delete(host_name, true);
    }
}

char *dns_cache_http_entry_state(entry_state_t entry_state) {
    switch (entry_state) {
        case ENTRY_FREE:
            return "Free";
        case ENTRY_IN_PROCESS:
            return "In process";
        case ENTRY_ENABLED:
            return "Enabled";
        default:
            return "Undefined";
    }
}

bool dns_cache_health_check(context_t *context) {
    // Check to see the "clean" up thread is running.
    //
    if (0 != pthread_kill(g_dns_cache_thread_id, 0)) {
        return false;
    }

    // Look through the table and see if w have any "odd" entries:
    //

    dns_cache_record_t *record = dns_get_head(context);

    if (record) {

        while (record) {

            dns_packet_t *packet = &record->dns_cache_entry.dns_packet_response;

            for (unsigned question_index = 0;
                 question_index < ntohs(packet->header.question_count);
                 question_index++) {

                question_t *question = dns_packet_get_question(packet, question_index);

                if (question) {

                    // We should "not" have a timeout longer than dns_get_max_ttl.
                    //
                    if (record->expired_time_stamp - dns_get_timestamp_now() >= dns_get_max_ttl()) {
                        return false;
                    }
                }
            }

            record = dns_get_next_record(context, record);
        }
    }

    return true;
}

void dns_cache_http_log(context_t *context, dns_string_ptr response) {
    dns_cache_record_t *record = dns_get_head(context);

    dns_string_sprintf(response, "<P>Cache Sleep Time(timestamp next, now: %d, %d): <B>%d</B><P>",
                       dns_get_cache_timestamp_next(),
                       dns_get_timestamp_now(),
                       dns_get_cache_timestamp_next() - dns_get_timestamp_now());

    dns_string_sprintf(response,
                       "<style type=\"text/css\">table.dnsdata {background-color:transparent;border-collapse:collapse;width:100%%;}"
                               "table.dnsdata th, table.dnsdata td {text-align:center;border:1px solid black;padding:5px;}"
                               "table.dnsdata th {background-color:AntiqueWhite;}"
                               "table.dnsdata td:first-child {width:20%%;}"
                               "</style>"
                               "<table class=\"dnsdata\">");

    dns_string_sprintf(response,
                       "<tr><th>Question</th><th>Time Stamp</th><th>Time Remaining (seconds)</th><th>Reference Count</th><th>Entry State</th><th>Answers</th></tr>");

    if (record) {

        dns_string_ptr host_name = dns_string_new(64);

        while (record) {

            dns_packet_t *packet = &record->dns_cache_entry.dns_packet_response;

            for (unsigned question_index = 0;
                 question_index < ntohs(packet->header.question_count);
                 question_index++) {

                question_t *question = dns_packet_get_question(packet, question_index);

                if (question) {
                    dns_question_to_host(packet, question, host_name);
                    dns_string_sprintf(response,
                                       "<tr><td>%s</td><td>%ld</td><td>%ld</td><td>%ld</td><td>%s</td><td>",
                                       dns_string_c_string(host_name),
                                       record->expired_time_stamp,
                                       record->expired_time_stamp - dns_get_timestamp_now(),
                                       record->reference_count,
                                       dns_cache_http_entry_state(record->dns_cache_entry.entry_state));

                    dns_cache_http_answers(record, response);

                    dns_string_sprintf(response, "</td></tr>");
                }
            }

            record = dns_get_next_record(context, record);
        }

        dns_string_delete(host_name, true);
    }
    dns_string_sprintf(response, "</table>");
}

int dns_cache_get_socket(context_t *context) {

    if (!g_dns_cache_socket) {
        int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!dns_set_calling_socket_options(context, socket_fd)) {
            exit(EXIT_FAILURE);
        }
        g_dns_cache_socket = socket_fd;
    }

    return g_dns_cache_socket;
}

bool dns_cache_compare(context_t *context, dns_packet_t *request, dns_packet_t *cache_entry) {

    ASSERT(context, request);
    ASSERT(context, cache_entry);

    if (request && cache_entry && ntohs(request->header.question_count)) {
        // why would we have a cache entry that does not have any questions?
        //
        ASSERT(context, ntohs(cache_entry->header.question_count) != 0);

        for (unsigned request_index = 0; request_index < ntohs(request->header.question_count); request_index++) {

            question_t *question = dns_packet_get_question(request, request_index);

            if (question) {
                dns_string_ptr request_host_name = dns_string_new(64);

                dns_question_to_host(request, question, request_host_name);
                for (unsigned cache_index = 0;
                     cache_index < ntohs(cache_entry->header.question_count); cache_index++) {
                    question = dns_packet_get_question(cache_entry, cache_index);
                    if (question) {
                        dns_string_ptr cache_host_name = dns_string_new(64);

                        dns_question_to_host(cache_entry, question, cache_host_name);
                        if (dns_string_strcmp(cache_host_name, request_host_name) == 0) {

                            dns_string_delete(cache_host_name, true);
                            dns_string_delete(request_host_name, true);
                            return true;
                        }

                        dns_string_delete(cache_host_name, true);
                    }
                }

                dns_string_delete(request_host_name, true);
            }
        }
    }

    return false;
}

dns_cache_record_t *dns_cache_find_record(context_t *context, dns_packet_t *dns_packet_to_find) {

    if (dns_packet_to_find == NULL) {
        return NULL;
    }

    dns_cache_record_t *dns_cache_record = dns_get_head(context);

    while (dns_cache_record != NULL) {
        if (dns_cache_compare(context,
                              dns_packet_to_find,
                              &dns_cache_record->dns_cache_entry.dns_packet_response)) {
            break;
        }

        dns_cache_record = dns_get_next_record(context, dns_cache_record);
    }

    return dns_cache_record;
}

dns_cache_entry_t dns_cache_find(context_t *context, dns_packet_t *dns_packet_to_find) {
    // We always return a "copy" of the entry and never the entry itself.
    //
    dns_cache_entry_t dns_cache_entry_found;
    memory_clear(&dns_cache_entry_found, sizeof(dns_cache_entry_found));

    if (dns_packet_to_find) {
        // Find the record in the Cache
        //
        dns_cache_record_t *cache_record = dns_cache_find_record(context, dns_packet_to_find);

        if (cache_record != NULL) {
            // Found it!  Now get a copy of the object and copy the "header id" over.
            //
            dns_cache_entry_found = cache_record->dns_cache_entry;
            dns_cache_entry_found.dns_packet_response.header.id = dns_packet_to_find->header.id;

            // We need to "tweak" the cached TTL, The TTL for the RECORD_A and cap it to the command
            // line parameter for max ttl
            //
            unsigned int cache_seconds = 0;
            if (dns_get_timestamp_now() > cache_record->created_time_stamp) {
                dns_packet_t *dns_packet = &dns_cache_entry_found.dns_packet_response;

                cache_seconds = dns_get_timestamp_now() - cache_record->created_time_stamp;
                unsigned int current_ttl = dns_packet_record_ttl_get(dns_packet, RECORD_A);
                unsigned int new_ttl = current_ttl < cache_seconds ? 0 : current_ttl - cache_seconds;

                dns_packet_record_ttl_set(dns_packet, RECORD_A, new_ttl);
            }

            // Release the record, we are done with it.
            //
            dns_cache_record_release(context, cache_record);
        }
    }

    return dns_cache_entry_found;
}

// Remove the record from the cache.
//
void dns_cache_record_remove(context_t *context, dns_cache_record_t *dns_cache_record) {

    ASSERT(context, dns_cache_record);

    if (g_head == NULL) {
        ERROR_LOG(context, "Fatal Error, the cache is empty and dns_cache_record_remove "
                "is trying to remove a record that does not exist, please report this as a bug.");
        return;
    }

    if (dns_cache_record && dns_cache_record->reference_count == 0) {
        ASSERT(context, dns_cache_record->reference_count == 0);

        // Acquire the head
        //
        dns_cache_record_t *dns_record_match = dns_cache_acquire_head();

        // Remove it from the list:
        //
        if (dns_cache_record == dns_record_match) {
            // kill the head.
            //
            g_head = dns_cache_record->next;
        }
        else {

            // Remove from the list
            //
            dns_cache_record_t *dns_record_previous = NULL;

            while (dns_record_match != NULL && dns_record_match != dns_cache_record) {
                dns_record_previous = dns_record_match;
                dns_record_match = dns_record_match->next;
            }

            if (dns_record_previous && dns_record_match) {
                // dns_record_previous->next = dns_record_match->next;
                __sync_lock_test_and_set(&dns_record_previous->next, dns_record_match->next);
            }
        }

        // Release the head!
        //
        dns_cache_release_head();

        if (dns_record_match) {
            // We just flip the bit to free the record, in case a second thread is in the process of "reading" the record
            // since the main thread is the "only" thread that can modify the rest of the record, this is a safe way
            // to free the record.
            //
            __sync_lock_test_and_set(&dns_record_match->dns_cache_entry.entry_state, ENTRY_FREE);
            __sync_fetch_and_sub(&g_record_used_count, 1);
        }
    }
}

dns_cache_record_t *dns_cache_insert_internal(context_t *context, dns_packet_t *dns_packet, size_t size) {

    // Size should always be less than the packet size.
    //
    ASSERT(context, size <= sizeof(dns_packet_t));

    // We want to insert the new record at the head!
    // Just in case the "other" thread is scanning the list.
    //
    dns_cache_record_t *cache_record = NULL;

    // We don't want to cache records with no answers.
    //
    if (ntohs(dns_packet->header.answer_count) > 0) {
        // Always allocate a new record, even if there is a duplicate, the clean up thread will take care of it.
        //
        for (size_t index = 0; index < dns_get_cache_entries(); index++) {
            if (__sync_bool_compare_and_swap(&g_records[index].dns_cache_entry.entry_state,
                                             ENTRY_FREE,
                                             ENTRY_IN_PROCESS)) {
                // We got one!
                //
                __sync_fetch_and_add(&g_record_used_count, 1);

                // Grab it.
                //
                cache_record = &g_records[index];

                // Lock it so we don't dump it.
                //
                dns_cache_record_hold(context, cache_record);
                break;
            }
        }

        // We found one!
        //
        if (cache_record) {
            // Clear out DNS Packet
            //
            memory_clear(&cache_record->dns_cache_entry.dns_packet_response, sizeof(dns_packet_t));

            // The TTL for the RECORD_A and cap it to the command line parameter for max ttl
            //
            unsigned int ttl = min(dns_packet_record_ttl_get(dns_packet, RECORD_A), dns_get_max_ttl());

            // Sometimes DNS Servers return 0 for A record times, in these cases we will
            // just go with the polling time.
            //
            ttl = ttl > 0 ? ttl : dns_get_cache_polling_interval();

            // Configure the record
            //
            unsigned int time_stamp_now = dns_get_timestamp_now();
            cache_record->expired_time_stamp = time_stamp_now + ttl;
            cache_record->created_time_stamp = time_stamp_now;

            size_t response_size = (size <= sizeof(dns_packet_t) ? size : sizeof(dns_packet_t));

            cache_record->dns_cache_entry.dns_packet_response_size = response_size;
            memcpy(&cache_record->dns_cache_entry.dns_packet_response, dns_packet, response_size);

            // Enable it!
            //
            __sync_lock_test_and_set(&cache_record->dns_cache_entry.entry_state, ENTRY_ENABLED);

            // Prepare to put it at the head of the list.
            //
            __sync_lock_test_and_set(&cache_record->next, dns_cache_acquire_head());

            // Add the record to the "head"  this puts the newest records at the top of the list.
            //
            __sync_lock_test_and_set(&g_head, cache_record);
            dns_cache_release_head();

            // All done!
            //
            dns_cache_record_release(context, cache_record);
        }
        else {
            ERROR_LOG(context,
                      "Cache table is full, currently size is %d, please use --entries= to enlarge it.",
                      dns_get_cache_entries());
            dns_packet_log(context, dns_packet, "Cache table is full, please use --entries= to enlarge it.");
        }
    }

    return cache_record;
}

bool dns_cache_insert(context_t *context, dns_packet_t *dns_packet, size_t size) {
    dns_cache_record_t *cache_record = dns_cache_insert_internal(context, dns_packet, size);
    return cache_record != NULL;
}

// Main entry point for the for the active cache refresh thread
//
void *dns_cache_refresh_thread(void __unused *arg) {

    context_t context = create_context();

    INFO_LOG(&context, "Starting dns_cache_refresh_thread()");

    while (g_dns_refresh_cache_loop) {

        long timestamp_now = dns_get_timestamp_now();
        long timestamp_next = timestamp_now + dns_get_cache_polling_interval();

        dns_cache_log(&context);

        dns_cache_record_t *dns_cache_record = dns_get_head(&context);

        while (dns_cache_record != NULL) {
            if (dns_cache_record->expired_time_stamp <= timestamp_now) {
                dns_packet_t dns_response;
                size_t size = 0;

                // Get a copy of the packet
                //
                dns_packet_t dns_packet = dns_cache_record->dns_cache_entry.dns_packet_response;

                size_t dns_packet_size = dns_packet_question_size(&context, &dns_packet);

                // Reset the header so it is now a question and not an answer
                //
                dns_packet.header.id = (unsigned short) (rand() % 0x3FFF);
                dns_packet.header.answer_count = 0;
                dns_packet.header.resource_count = 0;
                dns_packet.header.authority_count = 0;
                dns_packet.header.authoritative_answer = 0;
                dns_packet.header.recursion_available = 0;
                dns_packet.header.query_response_flag = 0;

                bool success = dns_resolve(&context,
                                           dns_cache_get_socket(&context),
                                           &dns_packet,
                                           (size_t) dns_packet_size,
                                           &dns_response,
                                           &size);

                if (success) {
                    // First insert!  That way the other thread will find this record BEFORE it's sibling
                    //
                    dns_cache_record_t *new_dns_cache_record = dns_cache_insert_internal(&context, &dns_response, size);

                    if (new_dns_cache_record) {
                        // We are done with it!
                        //
                        dns_cache_record_release(&context, dns_cache_record);

                        timestamp_next = min(new_dns_cache_record->expired_time_stamp, timestamp_next);

                        // Remove this entry.
                        //
                        dns_cache_record_remove(&context, dns_cache_record);
                        dns_cache_record = dns_get_head(&context);
                        continue;
                    }
                }
            }
            else {
                timestamp_next = min(dns_cache_record->expired_time_stamp, timestamp_next);
            }
            dns_cache_record = dns_get_next_record(&context, dns_cache_record);
        }

        // Get the time stamp now:
        //
        timestamp_now = dns_get_timestamp_now();

        // Save the "next" time so we can show it in diagnostics page:
        //
        dns_set_cache_timestamp_next((unsigned int) timestamp_next);

        // OK see if we need to sleep at all...
        //
        if (timestamp_now < timestamp_next) {
            DEBUG_LOG(&context, "dns_cache_refresh_thread() sleeping %d ",
                      (unsigned int) (timestamp_next - timestamp_now));
            sleep((unsigned int) (timestamp_next - timestamp_now));
        }

        // Reset the context "after" the sleep, so we a better idea of performance
        // between log calls.
        //
        context = create_context();
    }

    ERROR_LOG(&context, "Exiting dns_cache_refresh_thread()!");

    return NULL;
}

int dns_cache_init(context_t *context) {

    int result = -1;

    if (dns_get_cache_entries() <= 16) {
        ERROR_LOG(context, "Sorry we need at least 16 cache entries, you have select %d, "
                "please use --entries= to enlarge it.", dns_get_cache_entries());
    }
    else if (dns_get_resolvers() == NULL || dns_get_resolvers_count() == 0) {
        ERROR_LOG(context, "We need someone to call, no resolvers file found.  See --resolvers= to select a file.");
    }
    else {
        size_t byte_count = sizeof(dns_cache_entry_t) * (dns_get_cache_entries() + 1);
        g_records = malloc(byte_count);

        if (g_records) {
            memory_clear(g_records, byte_count);

            g_head = NULL;

            result = pthread_create(&g_dns_cache_thread_id, NULL, &dns_cache_refresh_thread, NULL);
        }
        else {
            ERROR_LOG(context,
                      "Ouch! We ran out of memory!  This is either an issue with the machine or a bug in the service");
        }
    }

    return result;
}

void dns_cache_stop() {
    pthread_kill(g_dns_cache_thread_id, SIGTERM);

    g_dns_refresh_cache_loop = false;
    g_head = NULL;

    free(g_records);
}
