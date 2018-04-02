/**********************************************************************
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
#include <ntsid.h>
#include <memory.h>
#include "dns_etcd_cache.h"
#include "dns_etcd.h"
#include "dns_settings.h"
#include "dns_question.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"
#define DEFAULT_IP_LIST_SIZE 16
#define DEFAULT_PORT_LIST_SIZE 16

etcd_client g_cli;

typedef struct dns_etcd_cache_ip_t {
    dns_string *ip;
    dns_array *ports;
} dns_etcd_cache_ip;

typedef struct dns_etcd_cache_record_t {
    dns_string *service;
    dns_string *protocol;
    dns_array *ips;
} dns_etcd_cache_record;

dns_etcd_cache *g_cache;

dns_etcd_cache *dns_etcd_cache_allocate() {
    dns_etcd_cache *cache = memory_alloc(sizeof(dns_etcd_cache));
    cache->refcount = 1;

    cache->dns_etcd_cache_records = dns_array_create(dns_get_cache_entries());

    return cache;
}

void dns_etcd_record_free(dns_etcd_cache_record *record) {
    if (record) {
        dns_string_free(record->service, true);
        dns_string_free(record->protocol, true);

        size_t num_ips = dns_array_size(record->ips);

        for (size_t i = 0; i < num_ips; i++) {
            dns_etcd_cache_ip *ip = dns_array_get(record->ips, i);

            if (ip) {
                dns_string_free(ip->ip, true);
                dns_array_free(ip->ports);


                dns_array_set(record->ips, i, NULL);
                free(ip);
            }
        }

        dns_array_free(record->ips);
        free(record);
    }
}

void dns_etcd_cache_free(dns_etcd_cache *cache) {
    if (cache) {
        size_t num_records = dns_array_size(cache->dns_etcd_cache_records);

        for (size_t i = 0; i < num_records; i++) {
            dns_etcd_record_free(dns_array_get(cache->dns_etcd_cache_records, i));
            dns_array_set(cache->dns_etcd_cache_records, i, NULL);
        }

        dns_array_free(cache->dns_etcd_cache_records);
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

dns_etcd_cache_record *dns_etcd_record_alloc() {
    dns_etcd_cache_record *record = memory_alloc(sizeof(dns_etcd_cache_record));
    record->ips = dns_array_create(DEFAULT_IP_LIST_SIZE);

    return record;
}

dns_etcd_cache_ip *dns_etcd_ip_find(dns_array *ips, const char *ip_address) {
    size_t num_records = dns_array_size(ips);

    for (size_t i = 0; i < num_records; i++) {
        dns_etcd_cache_ip *ip = dns_array_get(ips, i);
        if (strcmp(ip_address, dns_string_c_str(ip->ip)) == 0) {
            return ip;
        }
    }

    return NULL;
}

dns_etcd_cache_ip *dns_etcd_ip_find_create(dns_array *ips, dns_string *ip_address) {

    dns_etcd_cache_ip *ip = dns_etcd_ip_find(ips, dns_string_c_str(ip_address));

    if (ip) {
        return ip;
    }

    ip = memory_alloc(sizeof(dns_etcd_cache_ip));
    ip->ports = dns_array_create(DEFAULT_PORT_LIST_SIZE);
    ip->ip = dns_string_new_str(ip_address);

    dns_array_push(ips, ip);
    return ip;
}

void dns_etcd_ip_push(dns_etcd_cache_record *record, dns_string *value) {
    ASSERT(NULL, record && value);

    if (record && value) {
        size_t count = 0;
        dns_string_array *elements = dns_string_split_length(value, ":", &count);

        if (count > 0) {
            ASSERT(NULL, count == 2);

            dns_string *ip_address = dns_array_get(elements, 0);

            dns_etcd_cache_ip *ip = dns_etcd_ip_find_create(record->ips, ip_address);

            dns_array_push(ip->ports, (void *) strtol(dns_string_c_str(dns_array_get(elements, 1)), NULL, 10));

            dns_string_free(dns_array_get(elements, 0), true);
            dns_string_free(dns_array_get(elements, 1), true);

            dns_array_free(elements);
        }
    }
}

dns_etcd_cache_record *dns_etcd_cache_find_create(dns_array *records, dns_string *service, dns_string *protocol) {
    ASSERT(NULL, records && service && protocol);

    if (records && service && protocol) {
        size_t num_records = dns_array_size(records);

        for (size_t i = 0; i < num_records; i++) {
            dns_etcd_cache_record *record = dns_array_get(records, i);
            if (strcmp(dns_string_c_str(service), dns_string_c_str(record->service)) == 0) {
                // Found it!
                return record;
            }
        }
        // Nope, need to make one.
        dns_etcd_cache_record *record = dns_etcd_record_alloc();

        record->service = dns_string_new_str(service);
        record->protocol = dns_string_new_str(protocol);

        dns_array_push(records, record);
        return record;
    }

    return NULL;
}

void dns_etcd_record_push(transaction_context *context,
                          dns_array *records,
                          dns_string *service,
                          etcd_response_node *node) {
    INFO_LOG(context, "Pushing node: %s : %s", dns_string_c_str(node->key), dns_string_c_str(node->value));

    dns_string *service_name = dns_string_sprintf(dns_string_new_empty(),
                                                  "%s.%s",
                                                  dns_string_c_str(service) + 1,
                                                  dns_get_host_name());

    dns_string *protocol_name = dns_string_sprintf(dns_string_new_empty(),
                                                   "_http._tcp.%s",
                                                   dns_get_host_name());

    dns_etcd_cache_record *record = dns_etcd_cache_find_create(records, service_name, protocol_name);

    dns_etcd_ip_push(record, node->value);

    dns_string_free(service_name, true);
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

                        dns_etcd_record_push(context, cache->dns_etcd_cache_records, service->node->key, base_node);
                    }
                } else {
                    INFO_LOG(context, "Skipping key %s, no sub nodes.", dns_string_c_str(upper_node->key));
                }

                etcd_response_free(service);
            }
        }
    } else {
        ERROR_LOG(context, "ETCD service: no nodes found");
    }

    etcd_response_free(response);
}

void dns_cache_entry_setup(dns_packet *request, dns_cache_entry *cache_entry, dns_etcd_cache_record *records) {
    cache_entry->entry_state = ENTRY_ENABLED;

    // First if ip in the list matches the host_ip use that one
    //
    dns_etcd_cache_ip *ip = dns_etcd_ip_find(records->ips, dns_get_host_ip());

    // If not then randomly select one from the list.
    //
    if (NULL == ip) {
        dns_array_shuffle(records->ips);
        ip = dns_array_top(records->ips);
    }

    dns_question_handle question = dns_packet_question_index(request, 0);

    record_type_t qtype = dns_question_type(question);

    if (qtype == RECORD_A) {
        cache_entry->dns_packet_response_size = dns_packet_a_record_create(request,
                                                                           cache_entry,
                                                                           records->service,
                                                                           ip->ip);
    } else if (qtype == RECORD_SRV) {
        dns_string *service_name = dns_string_sprintf(dns_string_new_empty(), "_http._tcp.%s", dns_get_host_name());

        cache_entry->dns_packet_response_size = dns_packet_srv_record_create(request,
                                                                             cache_entry,
                                                                             service_name,
                                                                             dns_get_max_ttl(),
                                                                             ip->ports,
                                                                             records->protocol);
        dns_string_free(service_name, true);
    }
}

bool dns_etcd_search(dns_packet *request, dns_string *request_host_name, dns_cache_entry *cache_entry) {

    dns_etcd_cache *cache = dns_etcd_cache_hold(g_cache);
    bool found = false;

    if (cache) {
        size_t size = dns_array_size(cache->dns_etcd_cache_records);

        for (size_t index = 0; index < size; index++) {
            dns_etcd_cache_record *record = dns_array_get(cache->dns_etcd_cache_records, index);

            dns_question_handle question = dns_packet_question_index(request, 0);

            record_type_t qtype = dns_question_type(question);

            if (qtype == RECORD_A) {
                if (dns_string_strcmp(request_host_name, record->service) == 0) {
                    dns_cache_entry_setup(request, cache_entry, record);
                    found = true;
                    break;
                }
            } else if (qtype == RECORD_SRV) {
                if (dns_string_strcmp(request_host_name, record->protocol) == 0) {
                    dns_cache_entry_setup(request, cache_entry, record);
                    found = true;
                    break;
                }
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

        uint16_t question_count = ntohs(request->header.question_count);
        if (question_count) {
            ASSERT(context, question_count != 0);
            for (unsigned request_index = 0;
                 request_index < question_count && cache_entry.entry_state == ENTRY_FREE;
                 request_index++) {
                dns_question_handle question = dns_packet_question_index(request, request_index);

                if (question) {
                    dns_string *request_host_name = dns_question_host(question);

                    dns_etcd_search(request, request_host_name, &cache_entry);

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
            ERROR_LOG(context, "No Host Name defined, without we can not use: %s.", dns_get_etcd());
            return SO_ERROR;
        }

        if (dns_get_host_ip() == NULL) {
            ERROR_LOG(context, "No Host IP defined, without we can not use: %s.", dns_get_etcd());
            return SO_ERROR;
        }

        INFO_LOG(context, "ETCD service defined, using: %s", dns_get_etcd());

        dns_string *etcd_url = dns_string_new_c(strlen(dns_get_etcd()), dns_get_etcd());
        dns_array_push(addresses, (void *) etcd_url);
        etcd_client_init(&g_cli, addresses);

        // Global cache used to store entries.
        g_cache = dns_etcd_cache_allocate();

        dns_etcd_populate(context, g_cache);
    } else {
        INFO_LOG(context, "ETCD service not defined, disabled etcd lookup.");
    }

    return 0;
}

void dns_etcd_cache_log(dns_string *response) {
    dns_etcd_cache *cache = dns_etcd_cache_hold(g_cache);

    if (cache) {
        size_t num_records = dns_array_size(cache->dns_etcd_cache_records);
        dns_string_sprintf(response, "\"etcd\" : [");

        for (size_t record_index = 0; record_index < num_records; record_index++) {
            dns_etcd_cache_record *record = dns_array_get(cache->dns_etcd_cache_records, record_index);
            if (record) {
                dns_string_sprintf(response, "{\"protocol\": \"%s\",", dns_string_c_str(record->protocol));
                dns_string_sprintf(response, "\"service\": \"%s\",", dns_string_c_str(record->service));
                dns_string_sprintf(response, "\"ips\" : [");
                size_t num_ips = dns_array_size(record->ips);
                for (size_t ip_index = 0; ip_index < num_ips; ip_index++) {
                    dns_etcd_cache_ip *ip = dns_array_get(record->ips, ip_index);

                    dns_string_sprintf(response, "{ \"ip\" : \"%s\", \"ports\" : [", dns_string_c_str(ip->ip));

                    size_t num_ports = dns_array_size(ip->ports);
                    for (size_t port_index = 0; port_index < num_ports; port_index++) {
                        unsigned port = (unsigned) dns_array_get(ip->ports, port_index);
                        dns_string_sprintf(response, "%d", port);
                        if (port_index < num_ports - 1) {
                            dns_string_sprintf(response, ", ");
                        }
                    }
                    dns_string_sprintf(response, "]}");
                    if (ip_index < num_ips - 1) {
                        dns_string_sprintf(response, ", ");
                    }
                }
                dns_string_sprintf(response, "]}");
                if (record_index < num_records - 1) {
                    dns_string_sprintf(response, ", ");
                }
            }
        }
        dns_string_sprintf(response, "]");

        dns_etcd_cache_release(cache);
    }

}

#pragma clang diagnostic pop