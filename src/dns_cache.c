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

#ifndef __MACH__
#include <sys/cdefs.h>
#define _POSIX_C_SOURCE 200809L
#define __unused
#else

#include <ntsid.h>

#endif

#include <stdint.h>

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
#include "dns_question.h"
#include "dns_resource.h"
#include "dns_etcd_cache.h"

// Internal cache structure, it is never passed outside
// of this area, copies of the cache_entry can be
// returned to the caller but never this structure.
//
typedef struct dns_cache_record_t {
    struct dns_cache_record_t *next;            // Next record in the list.
    uint32_t reference_count;               // Reference count for the record.
    uint32_t expired_time_stamp;            // Timestamp to expire record
    uint32_t __unused created_time_stamp;   // Timestamp record was created

    dns_cache_entry cache_entry;                // Entry to return the caller.
} dns_cache_record;

dns_cache_record *g_head = NULL;
dns_cache_record *g_records = NULL;
size_t g_record_used_count = 0;

bool g_dns_refresh_cache_loop = true;
pthread_t g_dns_cache_thread_id = 0;

int g_dns_cache_socket = 0;

uint32_t dns_get_timestamp_now() {
    // Setup the entry
    //
    struct timespec time_now = timer_start();

    // time stamp in seconds
    //
    return (uint32_t) (time_now.tv_sec + (time_now.tv_nsec / 1000000000));
}

void dns_cache_record_hold(transaction_context *context, dns_cache_record *cache_record) {
    ASSERT(context, cache_record);

    if (cache_record) {
        __sync_fetch_and_add(&cache_record->reference_count, 1);
        ASSERT(context, cache_record->reference_count < 4);
    }
}

void dns_cache_record_release(transaction_context *context, dns_cache_record *cache_record) {
    ASSERT(context, cache_record);

    if (cache_record) {
        __sync_fetch_and_sub(&cache_record->reference_count, 1);
        ASSERT(context, cache_record->reference_count >= 0);
    }
}

// The lock used to secure the volatile head of the list.
// only dns_cache_acquire_head and dns_cache_release_head should
// use this global variable.
//
int g_dns_head_lock = 0;

dns_cache_record *dns_cache_acquire_head() {
    while (__sync_lock_test_and_set(&g_dns_head_lock, 1)) while (g_dns_head_lock);
    return g_head;
}

void dns_cache_release_head() {
    __sync_lock_release(&g_dns_head_lock);
}

dns_cache_record *dns_get_head(transaction_context *context) {

    ASSERT(context, context);

    dns_cache_record *head = dns_cache_acquire_head();

    if (head) {
        dns_cache_record_hold(context, head);
    }

    dns_cache_release_head();

    return head;
}

dns_cache_record *dns_get_next_record(transaction_context *context, dns_cache_record *cache_record) {

    dns_cache_record *dns_record_next = NULL;

    if (cache_record) {
        ASSERT(context, cache_record->cache_entry.entry_state == ENTRY_ENABLED);

        if (cache_record->next) {
            dns_record_next = cache_record->next;
            dns_cache_record_hold(context, dns_record_next);
        }

        dns_cache_record_release(context, cache_record);
    }

    return dns_record_next;
}

void dns_cache_log(transaction_context *context) {
    if (dns_get_debug_mode()) {
        dns_cache_record *record = dns_get_head(context);

        if (record) {
            dns_string *log_data = dns_string_new(1024);

            dns_string_sprintf(log_data, "\nquestion, expired_time_stamp, reference_count, entry_state\n");

            while (record) {

                dns_question_handle question = dns_packet_question_index(&record->cache_entry.dns_packet_response, 0);

                dns_string *host_name = dns_question_host(question);

                dns_string_sprintf(log_data, "%s: %u, %u, %d \n",
                                   dns_string_c_str(host_name),
                                   record->expired_time_stamp - dns_get_timestamp_now(),
                                   record->reference_count,
                                   record->cache_entry.entry_state);

                dns_string_free(host_name, true);

                record = dns_get_next_record(context, record);
            }

            DEBUG_LOG(context, dns_string_c_str(log_data));

            dns_string_free(log_data, true);
        }

    }
}

void dns_cache_log_answers(transaction_context *context, dns_cache_record *record, dns_string *response) {

    dns_string_sprintf(response, "\"answers\":[");

    if (record && record->cache_entry.dns_packet_response_size) {
        dns_packet *packet = &record->cache_entry.dns_packet_response;

        uint16_t answer_count = ntohs(packet->header.answer_count);
        if (answer_count) {
            for (uint16_t answer_index = 0; answer_index < answer_count; answer_index++) {
                dns_resource_handle answer = dns_packet_answer_get(context, packet, answer_index);

                dns_string *host_name = NULL;
                dns_string *resource_information = NULL;

                if (answer) {
                    if (dns_resource_record_type(context, answer) == RECORD_CNAME) {
                        host_name = dns_resource_host(packet, answer);
                        resource_information = dns_resource_data_string(context, packet, answer);
                    } else if (dns_resource_record_type(context, answer) == RECORD_A) {
                        host_name = dns_resource_host(packet, answer);
                        struct sockaddr_in address;
                        address.sin_addr.s_addr = dns_resource_data_uint32(context, answer);
                        dns_string_reset(resource_information);
                        dns_string_sprintf(resource_information, "%s", inet_ntoa(address.sin_addr));
                    } else if (dns_resource_record_type(context, answer) == RECORD_NS) {
                        struct sockaddr_in address;
                        address.sin_addr.s_addr = dns_resource_data_uint32(context, answer);
                        dns_string_reset(resource_information);
                        dns_string_sprintf(resource_information, "%s", inet_ntoa(address.sin_addr));
                    } else {
                        dns_string_reset(resource_information);
                        dns_string_sprintf(resource_information, "Not implemented for %s",
                                           dns_record_type_string(dns_resource_record_type(context, answer)));
                    }

                    dns_string_sprintf(response, "\"%s, %s\"",
                                       dns_string_c_str(host_name),
                                       dns_record_type_string(dns_resource_record_type(context, answer)));

                    dns_string_free(resource_information, true);
                    dns_string_free(host_name, true);
                    if (answer_index != answer_count - 1){
                        dns_string_sprintf(response, ", ");
                    }
                }
            }
        }
    }
    dns_string_sprintf(response, "]");
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

bool dns_cache_health_check(transaction_context *context) {
    // Check to see the "clean" up thread is running.
    //
    if (0 != pthread_kill(g_dns_cache_thread_id, 0)) {
        return false;
    }

    // Look through the table and see if w have any "odd" entries:
    //

    dns_cache_record *record = dns_get_head(context);

    if (record) {

        while (record) {

            dns_packet *packet = &record->cache_entry.dns_packet_response;

            for (unsigned question_index = 0;
                 question_index < ntohs(packet->header.question_count);
                 question_index++) {

                dns_question_handle question = dns_packet_question_index(packet, question_index);

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

void dns_cache_json_log(transaction_context *context, dns_string *response) {
    dns_cache_record *record = dns_get_head(context);

    uint32_t timestamp_now = dns_get_timestamp_now();

    dns_string_sprintf(response, "{");

    dns_string_sprintf(response, "\"cache_timestamp_next\":\"%d\",", dns_get_cache_timestamp_next());
    dns_string_sprintf(response, "\"timestamp_now\":\"%d\",", timestamp_now);
    dns_string_sprintf(response, "\"cache_timestamp_sleep\":\"%d\",", dns_get_cache_timestamp_next() - timestamp_now);

    dns_string_sprintf(response, "\"records\": [");

    if (record) {
        while (record) {

            dns_packet *packet = &record->cache_entry.dns_packet_response;

            unsigned question_count = ntohs(packet->header.question_count);

            for (unsigned question_index = 0;
                 question_index < question_count;
                 question_index++) {

                dns_question_handle question = dns_packet_question_index(packet, question_index);

                if (question) {
                    dns_string *host_name = dns_question_host(question);
                    dns_string_sprintf(response, "{");
                    dns_string_sprintf(response, "\"question\":\"%s\",", dns_string_c_str(host_name));
                    dns_string_sprintf(response, "\"time_stamp\":\"%u\",", record->expired_time_stamp);
                    dns_string_sprintf(response, "\"time_remaining\":\"%u\",",
                                       record->expired_time_stamp - timestamp_now);
                    dns_string_sprintf(response, "\"reference_count\":\"%u\",",
                                       record->reference_count - timestamp_now);
                    dns_string_sprintf(response, "\"entry_state\":\"%s\",",
                                       dns_cache_http_entry_state(record->cache_entry.entry_state));

                    dns_cache_log_answers(context, record, response);

                    dns_string_sprintf(response, "}");

                    dns_string_sprintf(response, ",");

                    dns_string_free(host_name, true);
                }
            }

            record = dns_get_next_record(context, record);
        }
        dns_string_trim(response, 1);
    }
    // Need to remove the last comma...
    dns_string_sprintf(response, "],");

    dns_etcd_cache_log(response);

    dns_string_sprintf(response, "}");
}

int dns_cache_get_socket(transaction_context *context) {

    if (!g_dns_cache_socket) {
        int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!dns_set_calling_socket_options(context, socket_fd)) {
            exit(EXIT_FAILURE);
        }
        g_dns_cache_socket = socket_fd;
    }

    return g_dns_cache_socket;
}

bool dns_cache_compare(transaction_context *context, dns_packet *request, dns_packet *cache_entry) {

    ASSERT(context, request);
    ASSERT(context, cache_entry);

    if (request && cache_entry && ntohs(request->header.question_count)) {
        // why would we have a cache entry that does not have any questions?
        //
        ASSERT(context, ntohs(cache_entry->header.question_count) != 0);

        for (unsigned request_index = 0; request_index < ntohs(request->header.question_count); request_index++) {

            dns_question_handle question = dns_packet_question_index(request, request_index);

            if (question) {
                dns_string *request_host_name = dns_question_host(question);
                for (unsigned cache_index = 0; cache_index < ntohs(cache_entry->header.question_count); cache_index++) {
                    question = dns_packet_question_index(cache_entry, cache_index);
                    if (question) {
                        dns_string *cache_host_name = dns_question_host(question);
                        if (dns_string_strcmp(cache_host_name, request_host_name) == 0) {

                            dns_string_free(cache_host_name, true);
                            dns_string_free(request_host_name, true);
                            return true;
                        }

                        dns_string_free(cache_host_name, true);
                    }
                }

                dns_string_free(request_host_name, true);
            }
        }
    }

    return false;
}

dns_cache_record *dns_cache_find_record(transaction_context *context, dns_packet *dns_packet_to_find) {

    if (dns_packet_to_find == NULL) {
        return NULL;
    }

    dns_cache_record *cache_record = dns_get_head(context);

    while (cache_record != NULL) {
        if (dns_cache_compare(context,
                              dns_packet_to_find,
                              &cache_record->cache_entry.dns_packet_response)) {
            break;
        }

        cache_record = dns_get_next_record(context, cache_record);
    }

    return cache_record;
}

dns_cache_entry dns_cache_find(transaction_context *context, dns_packet *dns_packet_to_find) {
    // We always return a "copy" of the entry and never the entry itself.
    //
    dns_cache_entry dns_cache_entry_found;
    memory_clear(&dns_cache_entry_found, sizeof(dns_cache_entry_found));

    if (dns_packet_to_find) {
        // Find the record in the Cache
        //
        dns_cache_record *cache_record = dns_cache_find_record(context, dns_packet_to_find);

        if (cache_record != NULL) {
            // Found it!  Now get a copy of the object and copy the "header id" over.
            //
            dns_cache_entry_found = cache_record->cache_entry;
            dns_cache_entry_found.dns_packet_response.header.id = dns_packet_to_find->header.id;

            // We need to "tweak" the cached TTL, The TTL for the RECORD_A and cap it to the command
            // line parameter for max ttl
            //
            dns_packet *packet = &dns_cache_entry_found.dns_packet_response;
            uint32_t current_ttl = dns_packet_record_ttl_get(context, packet, RECORD_A);

            if (current_ttl > dns_get_max_ttl()) {
                dns_packet_record_ttl_set(context, packet, RECORD_A, dns_get_max_ttl());
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
void dns_cache_record_remove(transaction_context *context, dns_cache_record *cache_record) {

    ASSERT(context, cache_record);

    if (g_head == NULL) {
        ERROR_LOG(context, "Fatal Error, the cache is empty and dns_cache_record_remove "
                "is trying to remove a record that does not exist, please report this as a bug.");
        return;
    }

    if (cache_record && cache_record->reference_count == 0) {
        ASSERT(context, cache_record->reference_count == 0);

        // Acquire the head
        //
        dns_cache_record *dns_record_match = dns_cache_acquire_head();

        // Remove it from the list:
        //
        if (cache_record == dns_record_match) {
            // kill the head.
            //
            g_head = cache_record->next;
        } else {

            // Remove from the list
            //
            dns_cache_record *dns_record_previous = NULL;

            while (dns_record_match != NULL && dns_record_match != cache_record) {
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
            __sync_lock_test_and_set(&dns_record_match->cache_entry.entry_state, ENTRY_FREE);
            __sync_fetch_and_sub(&g_record_used_count, 1);
        }
    }
}

dns_cache_record *dns_cache_insert_internal(transaction_context *context, dns_packet *packet, size_t size) {

    // Size should always be less than the packet size.
    //
    ASSERT(context, size <= sizeof(dns_packet));

    // We want to insert the new record at the head!
    // Just in case the "other" thread is scanning the list.
    //
    dns_cache_record *cache_record = NULL;

    // We don't want to cache records with no answers.
    //
    if (ntohs(packet->header.answer_count) > 0) {
        // Always allocate a new record, even if there is a duplicate, the clean up thread will take care of it.
        //
        for (size_t index = 0; index < dns_get_cache_entries(); index++) {
            if (__sync_bool_compare_and_swap(&g_records[index].cache_entry.entry_state,
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
            memory_clear(&cache_record->cache_entry.dns_packet_response, sizeof(dns_packet));

            // The TTL for the RECORD_A and cap it to the command line parameter for max ttl
            //
            uint32_t ttl = min(dns_packet_record_ttl_get(context, packet, RECORD_A), dns_get_max_ttl());

            // Sometimes DNS Servers return 0 for A record times, in these cases we will
            // just go with the polling time.
            //
            ttl = ttl > 0 ? ttl : dns_get_cache_polling_interval();

            // Configure the record
            //
            uint32_t time_stamp_now = dns_get_timestamp_now();
            cache_record->expired_time_stamp = time_stamp_now + ttl;
            cache_record->created_time_stamp = time_stamp_now;

            size_t response_size = (size <= sizeof(dns_packet) ? size : sizeof(dns_packet));

            cache_record->cache_entry.dns_packet_response_size = response_size;
            memcpy(&cache_record->cache_entry.dns_packet_response, packet, response_size);

            // Enable it!
            //
            __sync_lock_test_and_set(&cache_record->cache_entry.entry_state, ENTRY_ENABLED);

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
        } else {
            ERROR_LOG(context,
                      "Cache table is full, currently size is %d, please use --entries= to enlarge it.",
                      dns_get_cache_entries());
            dns_packet_log(context, packet, "Cache table is full, please use --entries= to enlarge it.");
        }
    }

    return cache_record;
}

bool dns_cache_insert(transaction_context *context, dns_packet *packet, size_t size) {
    dns_cache_record *cache_record = dns_cache_insert_internal(context, packet, size);
    return cache_record != NULL;
}

// Main entry point for the for the active cache refresh thread
//
void *dns_cache_refresh_thread(void __unused *arg) {

    transaction_context context = create_context();

    INFO_LOG(&context, "Starting dns_cache_refresh_thread()");

    while (g_dns_refresh_cache_loop) {

        uint32_t timestamp_now = dns_get_timestamp_now();
        uint32_t timestamp_next = timestamp_now + dns_get_cache_polling_interval();

        dns_cache_log(&context);

        dns_cache_record *cache_record = dns_get_head(&context);

        while (cache_record != NULL) {
            if (cache_record->expired_time_stamp <= timestamp_now) {
                dns_packet dns_response;
                size_t size = 0;

                // Get a copy of the packet
                //
                dns_packet packet = cache_record->cache_entry.dns_packet_response;

                size_t dns_packet_size = dns_packet_question_size(&context, &packet);

                // Reset the header so it is now a question and not an answer
                //
                packet.header.id = (uint16_t) (rand() % 0x3FFF); // NOLINT
                packet.header.answer_count = 0;
                packet.header.information_count = 0;
                packet.header.authority_count = 0;
                packet.header.authoritative_answer = 0;
                packet.header.recursion_available = 0;
                packet.header.query_response_flag = 0;

                bool success = dns_resolve(&context,
                                           dns_cache_get_socket(&context),
                                           &packet,
                                           (size_t) dns_packet_size,
                                           &dns_response,
                                           &size);

                if (success) {
                    // First insert!  That way the other thread will find this record BEFORE it's sibling
                    //
                    dns_cache_record *new_dns_cache_record = dns_cache_insert_internal(&context, &dns_response, size);

                    if (new_dns_cache_record) {
                        // We are done with it!
                        //
                        dns_cache_record_release(&context, cache_record);

                        timestamp_next = min(new_dns_cache_record->expired_time_stamp, timestamp_next);

                        // Remove this entry.
                        //
                        dns_cache_record_remove(&context, cache_record);
                        cache_record = dns_get_head(&context);
                        continue;
                    }
                }
            } else {
                timestamp_next = min(cache_record->expired_time_stamp, timestamp_next);
            }
            cache_record = dns_get_next_record(&context, cache_record);
        }

        // Get the time stamp now:
        //
        timestamp_now = dns_get_timestamp_now();

        // Save the "next" time so we can show it in diagnostics page:
        //
        dns_set_cache_timestamp_next(timestamp_next);

        // OK see if we need to sleep at all...
        //
        if (timestamp_now < timestamp_next) {
            DEBUG_LOG(&context, "dns_cache_refresh_thread() sleeping %u ",
                      (timestamp_next - timestamp_now));
            sleep(timestamp_next - timestamp_now);
        }

        // Reset the context "after" the sleep, so we a better idea of performance
        // between log calls.
        //
        context = create_context();
    }

    ERROR_LOG(&context, "Exiting dns_cache_refresh_thread()!");

    return NULL;
}

int dns_cache_init(transaction_context *context) {

    int result = -1;

    if (dns_get_cache_entries() <= 16) {
        ERROR_LOG(context, "Sorry we need at least 16 cache entries, you have select %d, "
                "please use --entries= to enlarge it.", dns_get_cache_entries());
    } else if (dns_get_resolvers() == NULL || dns_get_resolvers_count() == 0) {
        ERROR_LOG(context, "We need someone to call, no resolvers file found.  See --resolvers= to select a file.");
    } else {
        size_t byte_count = sizeof(dns_cache_entry) * (dns_get_cache_entries() + 1);
        g_records = memory_alloc(byte_count);

        if (g_records) {
            g_head = NULL;

            result = pthread_create(&g_dns_cache_thread_id, NULL, &dns_cache_refresh_thread, NULL);
        } else {
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

size_t dns_packet_a_record_create(dns_packet *request,
                                  dns_cache_entry *cache_entry,
                                  dns_string *host_name,
                                  dns_string *ip) {
    //                                1  1  1  1  1  1
    //  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                                               |
    // /                                               /
    // /                      NAME                     /
    // |                                               |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      TYPE                     |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                     CLASS                     |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      TTL                      |
    // |                                               |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                   RDLENGTH                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    // /                     RDATA                     /
    // /                                               /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    if (cache_entry) {
        dns_packet *packet = &cache_entry->dns_packet_response;
        memory_clear(packet, sizeof(dns_packet));

        packet->header.id = request->header.id;
        packet->header.recursion_desired = 0;
        packet->header.truncated_message = 0;
        packet->header.authoritative_answer = 1;
        packet->header.operation_code = 0;
        packet->header.query_response_flag = 1;
        packet->header.response_code = 0;
        packet->header.checking_disabled = 0;
        packet->header.authenticated_data = 0;
        packet->header.z_reserved = 0;
        packet->header.recursion_available = 1;

        packet->header.question_count = htons(1);
        packet->header.answer_count = htons(1);
        packet->header.information_count = 0;
        packet->header.authority_count =  htons(1);

        dns_question_handle question = dns_question_name_set(packet, dns_string_c_str(host_name));
        dns_question_type_set(question, RECORD_A);
        dns_question_class_set(question, CLASS_IN);

        dns_resource_answer_append(NULL, packet, host_name, ip);

        dns_resource_authority_append(NULL, packet);

        dns_packet_log(NULL, packet, "Cached Packet");

        return dns_packet_size(packet);
    }

    return 0;
}