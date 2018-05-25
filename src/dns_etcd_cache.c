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
#include <memory.h>
#include <arpa/inet.h>
#include "dns_etcd_cache.h"
#include "dns_etcd.h"
#include "dns_settings.h"
#include "dns_question.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"
#define DEFAULT_IP_LIST_SIZE 16
#define DEFAULT_PORT_LIST_SIZE 16

etcd_client g_etcd_client;

typedef struct dns_etcd_cache_ip_t {
    dns_string *ip;
    dns_array *ports;
} dns_etcd_cache_ip;

typedef struct dns_etcd_cache_record_t {
    dns_string *service;
    dns_string *protocol;
    dns_array *ips;
} dns_etcd_cache_record;

dns_etcd_cache *g_etcd_cache;

dns_etcd_cache *dns_etcd_cache_allocate() {
    dns_etcd_cache *cache = memory_alloc(sizeof(dns_etcd_cache));
    cache->refcount = 1;

    cache->dns_etcd_cache_records = dns_array_create(dns_cache_size_get());

    return cache;
}

void dns_etcd_record_free(dns_etcd_cache_record *record) {
    if (record) {
        dns_string_free(record->service, true);
        dns_string_free(record->protocol, true);

        size_t num_ips = dns_array_size(record->ips);

        for (size_t i = 0; i < num_ips; i++) {
            dns_etcd_cache_ip *ip = (dns_etcd_cache_ip *) dns_array_get(record->ips, i);

            if (ip) {
                dns_string_free(ip->ip, true);
                dns_array_free(ip->ports);


                dns_array_set(record->ips, i, 0);
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
            dns_etcd_record_free((dns_etcd_cache_record *) dns_array_get(cache->dns_etcd_cache_records, i));
            dns_array_set(cache->dns_etcd_cache_records, i, 0);
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
        dns_etcd_cache_ip *ip = (dns_etcd_cache_ip *) dns_array_get(ips, i);
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

    dns_array_push(ips, (uintptr_t) ip);
    return ip;
}

void dns_etcd_ip_port_push(dns_etcd_cache_record *record, dns_string *host_ip, dns_string *host_port) {
    ASSERT(NULL, record && host_ip && host_port);

    if (record && host_ip && host_port) {
        dns_etcd_cache_ip *ip = dns_etcd_ip_find_create(record->ips, host_ip);
        dns_array_push(ip->ports, (uintptr_t) strtol(dns_string_c_str(host_port), NULL, 10));
    }
}

dns_etcd_cache_record *dns_etcd_cache_find_create(dns_array *records, dns_string *service, dns_string *protocol) {
    ASSERT(NULL, records && service && protocol);

    if (records && service && protocol) {
        size_t num_records = dns_array_size(records);

        for (size_t i = 0; i < num_records; i++) {
            dns_etcd_cache_record *record = (dns_etcd_cache_record *) dns_array_get(records, i);
            if (strcmp(dns_string_c_str(service), dns_string_c_str(record->service)) == 0) {
                // Found it!
                return record;
            }
        }
        // Nope, need to make one.
        dns_etcd_cache_record *record = dns_etcd_record_alloc();

        record->service = dns_string_new_str(service);
        record->protocol = dns_string_new_str(protocol);

        dns_array_push(records, (uintptr_t) record);
        return record;
    }

    return NULL;
}

dns_string *dns_etcd_port_type(dns_string *protocol, etcd_response_node *server) {
    dns_string *path = dns_string_sprintf(dns_string_new_empty(),
                                          "%s/port_type",
                                          dns_string_c_str(server->key));

    etcd_response *port_type_node = etcd_get(&g_etcd_client, dns_string_c_str(path));

    dns_string_free(path, true);

    if (port_type_node && port_type_node->node && port_type_node->node->value) {
        return dns_string_sprintf(dns_string_reset(protocol),
                                  "_%s",
                                  dns_string_c_str(port_type_node->node->value));
    }

    return dns_string_sprintf(dns_string_reset(protocol), "_tcp");
}

dns_string *dns_etcd_transport(dns_string *transport, etcd_response_node *server) {
    dns_string *path = dns_string_sprintf(dns_string_new_empty(),
                                          "%s/attrs/protocol",
                                          dns_string_c_str(server->key));

    etcd_response *protocol_node = etcd_get(&g_etcd_client, dns_string_c_str(path));

    dns_string_free(path, true);

    if (protocol_node && protocol_node->node && protocol_node->node->value) {
        return dns_string_sprintf(dns_string_reset(transport),
                                  "_%s",
                                  dns_string_c_str(protocol_node->node->value));
    }

    return dns_string_sprintf(dns_string_reset(transport), "_http");
}


etcd_response_node *dns_etcd_find_host_ip(transaction_context *context, etcd_response *servers) {
    etcd_response_node *server = NULL;
    etcd_response *host_ip = NULL;

    dns_string *path = dns_string_new_empty();
    for (size_t j = 0; j < dns_array_size(servers->node->nodes); j++) {
        server = (etcd_response_node *) dns_array_get(servers->node->nodes, j);

        dns_string_sprintf(path, "%s/host_ip", dns_string_c_str(server->key));
        host_ip = etcd_get(&g_etcd_client, dns_string_c_str(path));

        // Did we find server that matches our host_ip,  if we have then use that one.
        //
        if (0 == strcmp(dns_string_c_str(host_ip->node->value), dns_host_ip_get())) {
            INFO_LOG(context, "Found Host IP Address %s", dns_host_ip_get());
            break;
        }

        dns_string_reset(path);
    }

    if (dns_string_length(path) == 0) {
        size_t offset = (size_t) rand() % dns_array_size(servers->node->nodes); // NOLINT
        server = (etcd_response_node *) dns_array_get(servers->node->nodes, offset);
    }

    dns_string_free(path, true);

    return server;
}

dns_string *dns_etcd_protocol_name(etcd_response_node *server) {
    dns_string *protocol = dns_etcd_port_type(dns_string_new_empty(), server);
    dns_string *transport = dns_etcd_transport(dns_string_new_empty(), server);

    dns_string *protocol_name = dns_string_sprintf(dns_string_new_empty(),
                                                   "%s.%s.%s",
                                                   dns_string_c_str(transport),
                                                   dns_string_c_str(protocol),
                                                   dns_host_name_get());
    dns_string_free(transport, true);
    dns_string_free(protocol, true);

    return protocol_name;
}

dns_string *dns_etcd_service_name(etcd_response_node *service, etcd_response_node *server) {

    dns_string *path = dns_string_sprintf(dns_string_new_empty(),
                                          "%s/attrs/host_name",
                                          dns_string_c_str(server->key));

    etcd_response *host_name_node = etcd_get(&g_etcd_client, dns_string_c_str(path));

    dns_string_free(path, true);

    dns_string *service_name = dns_string_new_empty();

    if (host_name_node && host_name_node->node && host_name_node->node->value) {
        service_name = dns_string_sprintf(service_name,
                                          "%s.%s",
                                          dns_string_c_str(host_name_node->node->value),
                                          dns_host_name_get());
    } else {
        if (service->key && dns_string_length(service->key)) {
            service_name = dns_string_sprintf(service_name,
                                              "%s.%s",
                                              dns_string_c_str(service->key) + 1,
                                              dns_host_name_get());
        }

    }

    return service_name;
}

dns_string *dns_etcd_host_ip(etcd_response_node *server) {
    dns_string *path = dns_string_sprintf(dns_string_new_empty(),
                                          "%s/host_ip",
                                          dns_string_c_str(server->key));

    etcd_response *host_ip = etcd_get(&g_etcd_client, dns_string_c_str(path));

    return dns_string_new_str(host_ip->node->value);
}

dns_string *dns_etcd_port(etcd_response_node *server) {
    dns_string *path = dns_string_sprintf(dns_string_new_empty(),
                                          "%s/host_port",
                                          dns_string_c_str(server->key));

    etcd_response *host_port = etcd_get(&g_etcd_client, dns_string_c_str(path));

    return dns_string_new_str(host_port->node->value);
}

void dns_etcd_record_push(transaction_context *context,
                          dns_array *records,
                          etcd_response_node *service) {
    INFO_LOG(context, "Pushing service: %s : %s", dns_string_c_str(service->key), dns_string_c_str(service->value));

    // Loop through and see if there is a matching local host ip address,

    etcd_response *servers = etcd_get(&g_etcd_client, dns_string_c_str(service->key));

    if (servers
        && servers->node
        && servers->node->nodes) {
        etcd_response_node *server = dns_etcd_find_host_ip(context, servers);

        dns_string *protocol_name = dns_etcd_protocol_name(server);

        dns_string *service_name = dns_etcd_service_name(service, server);

        dns_etcd_cache_record *record = dns_etcd_cache_find_create(records, service_name, protocol_name);

        dns_string_free(protocol_name, true);
        dns_string_free(service_name, true);

        dns_string *host_ip = dns_etcd_host_ip(server);
        dns_string *host_port = dns_etcd_port(server);

        dns_etcd_ip_port_push(record, host_ip, host_port);

        dns_string_free(host_ip, true);
        dns_string_free(host_port, true);
    }
}

void dns_etcd_populate(transaction_context *context, dns_etcd_cache *cache) {

    // Start at the root.
    //
    etcd_response *services = etcd_get(&g_etcd_client, "/");

    if (services && services->node && services->node->nodes) {

        // Loop through the nodes looking for directories.
        //
        for (size_t i = 0; i < dns_array_size(services->node->nodes); i++) {
            etcd_response_node *service = (etcd_response_node *) dns_array_get(services->node->nodes, i);

            // Did we find anything?
            //
            if (service) {
                dns_etcd_record_push(context, cache->dns_etcd_cache_records, service);
            } else {
                INFO_LOG(context, "Skipping key %s, no sub nodes.", dns_string_c_str(service->key));
            }
        }
    } else {
        ERROR_LOG(context, "ETCD service: no nodes found");
    }

    etcd_response_free(services);
}

void dns_cache_entry_setup(dns_packet *request, dns_cache_entry *cache_entry, dns_etcd_cache_record *records) {
    cache_entry->entry_state = ENTRY_ENABLED;

    // First if ip in the list matches the host_ip use that one
    //
    dns_etcd_cache_ip *ip = dns_etcd_ip_find(records->ips, dns_host_ip_get());

    // If not then randomly select one from the list.
    //
    if (NULL == ip) {
        dns_array_shuffle(records->ips);
        ip = (dns_etcd_cache_ip *) dns_array_top(records->ips);
    }

    if (ip == NULL) {
        ERROR_LOG(NULL, "YIKES: Internal error");
        return;
    }

    dns_question_handle question = dns_packet_question_index(request, 0);

    record_type_t qtype = dns_question_type(question);

    if (qtype == RECORD_A) {
        cache_entry->dns_packet_response_size = dns_packet_a_record_create(request,
                                                                           cache_entry,
                                                                           records->service,
                                                                           ip->ip);
    } else if (qtype == RECORD_SRV) {
        cache_entry->dns_packet_response_size = dns_packet_srv_record_create(request,
                                                                             cache_entry,
                                                                             records->protocol,
                                                                             dns_max_ttl_get(),
                                                                             ip->ports,
                                                                             records->service);
    }
}

bool dns_etcd_search(dns_packet *request, dns_string *request_host_name, dns_cache_entry *cache_entry) {

    dns_etcd_cache *cache = dns_etcd_cache_hold(g_etcd_cache);
    bool found = false;

    if (cache) {
        size_t size = dns_array_size(cache->dns_etcd_cache_records);

        for (size_t index = 0; index < size; index++) {
            dns_etcd_cache_record *record = (dns_etcd_cache_record *) dns_array_get(cache->dns_etcd_cache_records, index);

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

    dns_cache_entry entry_found = dns_etcd_find(context, dns_packet_to_find);

    dns_packet_log(context, &entry_found.dns_packet_response, "lookup_etcd_packet packet_found");

    return entry_found;
}

int dns_etcd_watcher_callback(void __unused *user_data, etcd_response *resp) {
    transaction_context context_base = context_create();
    transaction_context *context = &context_base;

    etcd_response_log(context, resp);

    // Something changed... time to reload...
    //

    // Create a new cache:
    //
    dns_etcd_cache *new_etcd_cache = dns_etcd_cache_allocate();
    dns_etcd_populate(context, new_etcd_cache);

    // Save the old one
    //
    dns_etcd_cache *old_etcd_cache = g_etcd_cache;

    // Swap
    //
    g_etcd_cache = new_etcd_cache;

    // Release the old one.
    //
    dns_etcd_cache_release(old_etcd_cache);

    return 0;
}

int dns_service_etcd(transaction_context *context) {
    if (dns_etcd_get() != NULL) {
        memory_clear(&g_etcd_client, sizeof(g_etcd_client));

        dns_array *addresses = dns_array_create(1);

        if (dns_host_name_get() == NULL) {
            ERROR_LOG(context, "No Host Name defined, without we can not use: %s.", dns_etcd_get());
            return SO_ERROR;
        }

        if (dns_host_ip_get() == NULL) {
            ERROR_LOG(context, "No Host IP defined, without we can not use: %s.", dns_etcd_get());
            return SO_ERROR;
        }

        INFO_LOG(context, "ETCD service defined, using: %s", dns_etcd_get());

        dns_string *etcd_url = dns_string_new_c(strlen(dns_etcd_get()), dns_etcd_get());
        dns_array_push(addresses, (uintptr_t) etcd_url);
        etcd_client_init(&g_etcd_client, addresses);

        g_etcd_client.settings.verbose = dns_debug_mode_get();

        g_etcd_cache = dns_etcd_cache_allocate();

        dns_etcd_populate(context, g_etcd_cache);
        dns_array *etcd_watchers = dns_array_create(1);

        etcd_watcher_add(etcd_watchers, etcd_watcher_create(&g_etcd_client, "", 0, true, false,
                                                            dns_etcd_watcher_callback, NULL));

        etcd_watcher_multi_async(&g_etcd_client, etcd_watchers);

    } else {
        INFO_LOG(context, "ETCD service not defined, disabled etcd lookup.");
    }

    return 0;
}

void dns_etcd_cache_log(dns_string *response) {
    dns_etcd_cache *cache = dns_etcd_cache_hold(g_etcd_cache);

    if (cache) {
        size_t num_records = dns_array_size(cache->dns_etcd_cache_records);
        dns_string_sprintf(response, "\"etcd\" : [");

        for (size_t record_index = 0; record_index < num_records; record_index++) {
            dns_etcd_cache_record *record = (dns_etcd_cache_record *) dns_array_get(cache->dns_etcd_cache_records, record_index);
            if (record) {
                dns_string_sprintf(response, "{\"protocol\": \"%s\",", dns_string_c_str(record->protocol));
                dns_string_sprintf(response, "\"service\": \"%s\",", dns_string_c_str(record->service));
                dns_string_sprintf(response, "\"ips\" : [");
                size_t num_ips = dns_array_size(record->ips);
                for (size_t ip_index = 0; ip_index < num_ips; ip_index++) {
                    dns_etcd_cache_ip *ip = (dns_etcd_cache_ip *) dns_array_get(record->ips, ip_index);

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