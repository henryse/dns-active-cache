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

bool dns_set_calling_socket_options(transaction_context *context, int dns_socket);

bool dns_get_debug_mode();

void dns_set_http_mode(bool debug_mode);

uint32_t dns_get_max_ttl();

void dns_set_max_ttl(uint32_t max_ttl);

bool dns_get_log_mode();

void dns_set_log_mode(bool log_mode);

bool dns_get_bypass_mode();

void dns_set_bypass_mode(bool bypass_mode);

bool dns_get_optimize_mode();

void dns_set_optimize_mode(bool optimize_mode);

uint16_t dns_get_port();

void dns_set_port(uint16_t port);

uint16_t dns_http_get_port();

void dns_http_set_port(uint16_t port);

uint32_t dns_get_socket_timeout();

void dns_set_socket_timeout(uint32_t timeout_ms);

uint32_t dns_get_cache_entries();

void dns_set_cache_entries(uint32_t cache_entries);

uint32_t dns_get_cache_polling_interval();

void dns_set_cache_polling_interval(uint32_t cache_polling_interval_seconds);

const char *dns_get_resolvers_file();

void dns_set_resolvers_file(char *g_resolvers_file);

char **dns_get_resolvers();

void dns_set_resolvers(char **resolvers);

void dns_set_resolvers_count(size_t count);

size_t dns_get_resolvers_count();

void dns_set_run_as_daemon(bool daemon);

bool dns_get_run_as_daemon();

pid_t dns_get_daemon_process_id();

void dns_set_daemon_process_id(pid_t daemon_process_id);

void dns_set_cache_timestamp_next(uint32_t count);

uint32_t dns_get_cache_timestamp_next();

const char *get_active_cache_version();

int get_dns_resolve_retry_count();

void dns_set_etcd(const char *etcd);

const char *dns_get_etcd();

void dns_set_host_name(const char *host_name);

const char *dns_get_host_name();

void dns_set_host_ip(const char *host_name);

const char *dns_get_host_ip();

#endif //DNS_CACHE_DNS_SETTINGS_H

