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

#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <limits.h>
#include "dns_settings.h"
#include "version_config.h"

bool g_debug_mode = false;
bool g_log_mode = true;
bool g_bypass_mode = false;
bool g_optimize_mode = false;
uint16_t g_port = 53;
uint16_t g_http_port = 0;
uint32_t g_socket_timeout_sec = 5;
uint32_t g_cache_entries = 64;
uint32_t g_cache_polling_interval_seconds = 16;
char *g_resolvers_file = NULL;
char **g_resolvers = NULL;
const char *g_etcd_server = NULL;
const char *g_host_name = NULL;
const char *g_host_ip = NULL;
size_t g_resolvers_count = 0;
uint32_t g_cache_timestamp_next = 0;
uint32_t g_max_ttl = UINT_MAX / 2;
bool g_run_as_daemon = false;
pid_t g_daemon_process_id = 0;

bool dns_calling_socket_options_set(transaction_context *context, int dns_socket) {
    struct timeval timeout;
    timeout.tv_sec = dns_socket_timeout_get();
    timeout.tv_usec = 0;

    if (setsockopt(dns_socket,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   (char *) &timeout,
                   sizeof(timeout)) != 0) {
        ERROR_LOG(context, "setsockopt SO_RCVTIMEO failed, "
                           "this is either a networking issue or a bug in the service.");
        return false;
    }
    if (setsockopt(dns_socket,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   (char *) &timeout,
                   sizeof(timeout)) != 0) {

        ERROR_LOG(context, "setsockopt SO_SNDTIMEO failed, "
                           "this is either a networking issue or a bug in the service.");
        return false;
    }

    int option_one = 1;

    if (setsockopt(dns_socket,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &option_one,
                   sizeof(option_one)) != 0) {
        ERROR_LOG(context, "setsockopt SO_REUSEADDR failed, "
                           "this is either a networking issue or a bug in the service.");
        return false;
    }

    return true;
}

uint16_t dns_port_get() {
    return g_port;
}

void dns_port_set(uint16_t port) {
    g_port = port;
}

uint16_t dns_http_port_get() {
    return g_http_port;
}

void dns_http_port_set(uint16_t port) {
    g_http_port = port;
}

uint32_t dns_socket_timeout_get() {
    return g_socket_timeout_sec;
}

void dns_socket_timeout_set(uint32_t timeout_sec) {
    g_socket_timeout_sec = timeout_sec;
}

uint32_t dns_cache_size_get() {
    return g_cache_entries;
}

void dns_cache_size_set(uint32_t cache_entries) {
    g_cache_entries = cache_entries;
}

bool dns_debug_mode_get() {
    return g_debug_mode;
}

void dns_http_mode_set(bool debug_mode) {
    g_debug_mode = debug_mode;
}

uint32_t dns_max_ttl_get() {
    return g_max_ttl;
}

void dns_max_ttl_set(uint32_t max_ttl) {
    g_max_ttl = max_ttl;
}

bool dns_log_mode_get() {
    return g_log_mode;
}

void dns_log_mode_set(bool log_mode) {
    g_log_mode = log_mode;
}

bool dns_bypass_cache_get() {
    return g_bypass_mode;
}

void dns_bypass_mode_set(bool bypass_mode) {
    g_bypass_mode = bypass_mode;
}

bool dns_optimize_mode_get() {
    return g_optimize_mode;
}

void dns_optimize_mode_set(bool optimize_mode) {
    g_optimize_mode = optimize_mode;
}

uint32_t dns_cache_polling_interval_get() {
    return g_cache_polling_interval_seconds;
}

void dns_cache_polling_interval_set(uint32_t cache_polling_interval_seconds) {
    g_cache_polling_interval_seconds = cache_polling_interval_seconds;
}

const char *dns_resolvers_file_get() {
    return g_resolvers_file;
}

void dns_resolvers_file_set(char *resolvers_file) {
    g_resolvers_file = resolvers_file;
}

char **dns_resolvers_get() {
    return g_resolvers;
}

void dns_resolvers_set(char **resolvers) {
    g_resolvers = resolvers;
}

void dns_resolvers_count_set(size_t count) {
    g_resolvers_count = count;
}

size_t dns_resolvers_count_get() {
    return g_resolvers_count;
}

void dns_run_as_daemon_set(bool daemon) {
    g_run_as_daemon = daemon;
}

bool dns_run_as_daemon_get() {
    return g_run_as_daemon;
}

pid_t dns_daemon_process_id_get() {
    return g_daemon_process_id;
}

void dns_daemon_process_id_set(pid_t daemon_process_id) {
    g_daemon_process_id = daemon_process_id;
}

void dns_cache_timestamp_next_set(uint32_t count) {
    g_cache_timestamp_next = count;
}

uint32_t dns_cache_timestamp_next_get() {
    return g_cache_timestamp_next;
}

const char *dns_active_cache_version_get() {
    return ACTIVE_DNS_CACHE_VERSION;
}

int dns_resolve_retry_count_get() {
    return 3;
}

void dns_etcd_set(const char *etcd) {
    g_etcd_server = etcd;
}

const char *dns_etcd_get() {
    return g_etcd_server;
}

void dns_host_name_set(const char *host_name) {
    g_host_name = host_name;
}

const char *dns_host_name_get() {
    return g_host_name;
}

const char *dns_host_ip_get() {
    return g_host_ip;
}

void dns_host_ip_set(const char *host_ip) {
    g_host_ip = host_ip;
}