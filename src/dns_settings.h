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

#ifndef DNS_CACHE_DNS_SETTINGS_H
#define DNS_CACHE_DNS_SETTINGS_H

#include "dns_utils.h"

bool dns_calling_socket_options_set(transaction_context *context, int dns_socket);

bool dns_debug_mode_get();

void dns_http_mode_set(bool debug_mode);

uint32_t dns_max_ttl_get();

void dns_max_ttl_set(uint32_t max_ttl);

bool dns_log_mode_get();

void dns_log_mode_set(bool log_mode);

bool dns_bypass_cache_get();

void dns_bypass_mode_set(bool bypass_mode);

bool dns_optimize_mode_get();

void dns_optimize_mode_set(bool optimize_mode);

uint16_t dns_port_get();

void dns_port_set(uint16_t port);

uint16_t dns_http_port_get();

void dns_http_port_set(uint16_t port);

uint32_t dns_socket_timeout_get();

void dns_socket_timeout_set(uint32_t timeout_ms);

uint32_t dns_cache_size_get();

void dns_cache_size_set(uint32_t cache_entries);

uint32_t dns_cache_polling_interval_get();

void dns_cache_polling_interval_set(uint32_t cache_polling_interval_seconds);

const char *dns_resolvers_file_get();

void dns_resolvers_file_set(char *g_resolvers_file);

char **dns_resolvers_get();

void dns_resolvers_set(char **resolvers);

void dns_resolvers_count_set(size_t count);

size_t dns_resolvers_count_get();

void dns_run_as_daemon_set(bool daemon);

bool dns_run_as_daemon_get();

pid_t dns_daemon_process_id_get();

void dns_daemon_process_id_set(pid_t daemon_process_id);

void dns_cache_timestamp_next_set(uint32_t count);

uint32_t dns_cache_timestamp_next_get();

const char *dns_active_cache_version_get();

int dns_resolve_retry_count_get();

void dns_etcd_set(const char *etcd);

const char *dns_etcd_get();

void dns_host_name_set(const char *host_name);

const char *dns_host_name_get();

void dns_host_ip_set(const char *host_name);

const char *dns_host_ip_get();

#endif //DNS_CACHE_DNS_SETTINGS_H

