#include <ntsid.h>/**********************************************************************
//    Copyright (c) 2018 Henry Seurer
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
#include <memory.h>
#include "dns_service_etcd.h"
#include "dns_etcd.h"
#include "dns_settings.h"
#include "dns_question.h"

etcd_client g_cli;


typedef struct dns_etcd_entry_t {
    dns_string *name;
    dns_string *ip;
    dns_string *value;
    uint16_t __unused port;
} dns_etcd_entry;

dns_etcd_cache *g_cache;

dns_etcd_cache *dns_etcd_cache_allocate() {
    dns_etcd_cache *cache = memory_alloc(sizeof(dns_etcd_cache));
    cache->refcount = 1;

    cache->dns_etcd_entries = dns_array_create(16);
    dns_array_init(cache->dns_etcd_entries, 3);

    return cache;
}

void dns_etcd_cache_free(dns_etcd_cache *cache) {
    if (cache) {
        size_t size = dns_array_size(cache->dns_etcd_entries);

        for (size_t i = 0; i < size; i++) {
            dns_string_free(dns_array_get(cache->dns_etcd_entries, i), true);
            dns_array_set(cache->dns_etcd_entries, i, NULL);
        }
        dns_array_destroy(cache->dns_etcd_entries);
        memory_clear(cache, sizeof(dns_etcd_cache));
        free(cache);
    }
}

dns_etcd_cache *dns_etcd_cache_hold(dns_etcd_cache *cache) {
    if (cache) {
        __sync_fetch_and_add(&cache->refcount, 1);
    }

    return cache;
}

dns_etcd_cache *dns_etcd_cache_release(dns_etcd_cache *cache) {
    if (cache) {
        if (1 == __sync_fetch_and_sub(&cache->refcount, 1)) {
            dns_etcd_cache_free(cache);
            return NULL;
        }
    }

    return cache;
}

dns_etcd_entry *dns_etcd_entry_allocate() {
    dns_etcd_entry *entry = memory_alloc(sizeof(dns_etcd_entry));

    return entry;
}

void __unused dns_etcd_entry_free(dns_etcd_entry *entry) {
    if (entry != NULL) {
        dns_string_free(entry->name, true);
        entry->name = NULL;

        dns_string_free(entry->ip, true);
        entry->ip = NULL;

        dns_string_free(entry->value, true);
        entry->value = NULL;

        memory_clear(entry, sizeof(dns_etcd_entry));
        free(entry);
    }
}

void dns_etcd_push(transaction_context *context, dns_array *etcd_dns_entries, dns_string *service,
                   etcd_response_node *node) {
    INFO_LOG(context, "Pushing node: %s : %s", dns_string_c_str(node->key), dns_string_c_str(node->value));

    dns_etcd_entry *entry = dns_etcd_entry_allocate();

    size_t count = 0;
    dns_string_array *array = dns_string_split_length(node->value, ":", &count);

    entry->name = dns_string_sprintf(dns_string_new_empty(), "%s.%s", dns_string_c_str(service) + 1,
                                     dns_get_host_name());
    entry->value = dns_string_new_str(node->key);

    if (count > 0) {
        entry->ip = dns_array_get(array, 0);
        dns_array_set(array, 0, NULL);

        if (count > 1) {
            entry->port = (uint16_t) strtol(dns_string_c_str(dns_array_get(array, 1)), NULL, 10);
        }
    }

    dns_array_append(etcd_dns_entries, entry);
}

void dns_etcd_populate(transaction_context *context, dns_etcd_cache *cache) {
    // Start at the root.
    //
    etcd_response *response = etcd_get(&g_cli, "/");

    if (response && response->node && response->node->nodes) {

        // Loop through the nodes looking for directories.
        //
        for (size_t i = 0; i < dns_array_size(response->node->nodes); i++) {
            etcd_response_node *upper_node = dns_array_get(response->node->nodes, i);

            // If it is a directory, we need to stop down adn see if it is one of ours.
            //
            if (upper_node->dir) {
                // Dig a bit deeper
                //
                etcd_response *service = etcd_get(&g_cli, dns_string_c_str(upper_node->key));

                // Did we find anything?
                //
                if (service && service->node && service->node->nodes) {
                    for (size_t j = 0; j < dns_array_size(service->node->nodes); j++) {

                        etcd_response_node *base_node = dns_array_get(service->node->nodes, j);

                        dns_etcd_push(context, cache->dns_etcd_entries, service->node->key, base_node);
                    }
                } else {
                    INFO_LOG(context, "Skipping key %s, no sub nodes.", dns_string_c_str(upper_node->key));
                }

                etcd_response_free(service);
            }
        }
    } else {
        INFO_LOG(context, "no nodes found");
    }

    etcd_response_free(response);
}

void dns_cache_entry_setup(dns_cache_entry *cache_entry, dns_etcd_entry *etcd_entry) {
    cache_entry->entry_state = ENTRY_ENABLED;



    cache_entry->dns_packet_response_size = dns_packet_a_record_create(cache_entry,
                                                                     etcd_entry->name,
                                                                     etcd_entry->ip);
}


bool dns_etcd_search(dns_string *request_host_name, dns_cache_entry *cache_entry) {

    dns_etcd_cache *cache = dns_etcd_cache_hold(g_cache);
    bool found = false;

    if (cache) {
        size_t size = dns_array_size(cache->dns_etcd_entries);

        for (size_t index = 0; index < size; index++) {
            dns_etcd_entry *etcd_entry = dns_array_get(cache->dns_etcd_entries, index);

            if (dns_string_strcmp(request_host_name, etcd_entry->name) == 0) {
                dns_cache_entry_setup(cache_entry, etcd_entry);
                found = true;
                break;
            }
        }

        dns_etcd_cache_release(cache);
    }

    return found;
}

dns_cache_entry dns_etcd_find(transaction_context *context, dns_packet *request) {
    ASSERT(context, request);

    dns_cache_entry cache_entry;
    memory_clear(&cache_entry, sizeof(cache_entry));

    if (request) {
        // Copy over the current question...
        cache_entry.dns_packet_response = *request;

        // Mark it as invalid.
        cache_entry.entry_state = ENTRY_FREE;

        if (ntohs(request->header.question_count)) {
            ASSERT(context, ntohs(request->header.question_count) != 0);
            for (unsigned request_index = 0;
                 request_index < ntohs(request->header.question_count) && cache_entry.entry_state == ENTRY_FREE;
                 request_index++) {
                dns_question_handle question = dns_packet_question_index(request, request_index);

                if (question) {
                    dns_string *request_host_name = dns_question_host(question);

                    dns_etcd_search(request_host_name, &cache_entry);

                    dns_string_free(request_host_name, true);
                }
            }
        }
    }

    return cache_entry;
}


dns_cache_entry lookup_etcd_packet(transaction_context *context, dns_packet *dns_packet_to_find) {
    dns_packet_log(context, dns_packet_to_find, "lookup_etcd_packet dns_packet_to_find");

    if (dns_get_bypass_mode()) {
        dns_cache_entry cache_entry;

        memory_clear(&cache_entry, sizeof(cache_entry));
        DEBUG_LOG(context, "Skipping lookup_etcd_packet");
        return cache_entry;
    }

    dns_cache_entry entry_found = dns_etcd_find(context, dns_packet_to_find);

    dns_packet_log(context, &entry_found.dns_packet_response, "lookup_etcd_packet packet_found");

    return entry_found;
}

int dns_service_etcd(transaction_context *context) {
    if (dns_get_etcd() != NULL) {
        memory_clear(&g_cli, sizeof(g_cli));

        dns_array *addresses = dns_array_create(1);

        if (dns_get_host_name() == NULL) {
            ERROR_LOG(context, "No Host Name defined, without we can use: %s.", dns_get_etcd());
            return SO_ERROR;
        }

        INFO_LOG(context, "ETCD service defined, using: %s", dns_get_etcd());

        dns_string *etcd_url = dns_string_new_c_string(strlen(dns_get_etcd()), dns_get_etcd());
        dns_array_append(addresses, (void *) etcd_url);
        etcd_client_init(&g_cli, addresses);

        // Global cache used to store entries.
        g_cache = dns_etcd_cache_allocate();

        dns_etcd_populate(context, g_cache);
    } else {
        INFO_LOG(context, "ETCD service not defined, disabled etcd lookup.");
    }

    return 0;
}
