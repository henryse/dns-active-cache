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
uint16_t g_debug_port = 0;
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

bool dns_set_calling_socket_options(transaction_context *context, int dns_socket) {
    struct timeval timeout;
    timeout.tv_sec = dns_get_socket_timeout();
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

uint16_t dns_get_port() {
    return g_port;
}

void dns_set_port(uint16_t port) {
    g_port = port;
}

uint16_t debug_get_port() {
    return g_debug_port;
}

void debug_set_port(uint16_t port) {
    g_debug_port = port;
}

uint32_t dns_get_socket_timeout() {
    return g_socket_timeout_sec;
}

void dns_set_socket_timeout(uint32_t timeout_sec) {
    g_socket_timeout_sec = timeout_sec;
}

uint32_t dns_get_cache_entries() {
    return g_cache_entries;
}

void dns_set_cache_entries(uint32_t cache_entries) {
    g_cache_entries = cache_entries;
}

bool dns_get_debug_mode() {
    return g_debug_mode;
}

void dns_set_debug_mode(bool debug_mode) {
    g_debug_mode = debug_mode;
}

uint32_t dns_get_max_ttl() {
    return g_max_ttl;
}

void dns_set_max_ttl(uint32_t max_ttl) {
    g_max_ttl = max_ttl;
}

bool dns_get_log_mode() {
    return g_log_mode;
}

void dns_set_log_mode(bool log_mode) {
    g_log_mode = log_mode;
}

bool dns_get_bypass_mode() {
    return g_bypass_mode;
}

void dns_set_bypass_mode(bool bypass_mode) {
    g_bypass_mode = bypass_mode;
}

bool dns_get_optimize_mode() {
    return g_optimize_mode;
}

void dns_set_optimize_mode(bool optimize_mode) {
    g_optimize_mode = optimize_mode;
}

uint32_t dns_get_cache_polling_interval() {
    return g_cache_polling_interval_seconds;
}

void dns_set_cache_polling_interval(uint32_t cache_polling_interval_seconds) {
    g_cache_polling_interval_seconds = cache_polling_interval_seconds;
}

const char *dns_get_resolvers_file() {
    return g_resolvers_file;
}

void dns_set_resolvers_file(char *resolvers_file) {
    g_resolvers_file = resolvers_file;
}

char **dns_get_resolvers() {
    return g_resolvers;
}

void dns_set_resolvers(char **resolvers) {
    g_resolvers = resolvers;
}

void dns_set_resolvers_count(size_t count) {
    g_resolvers_count = count;
}

size_t dns_get_resolvers_count() {
    return g_resolvers_count;
}

void dns_set_run_as_daemon(bool daemon) {
    g_run_as_daemon = daemon;
}

bool dns_get_run_as_daemon() {
    return g_run_as_daemon;
}

pid_t dns_get_daemon_process_id() {
    return g_daemon_process_id;
}

void dns_set_daemon_process_id(pid_t daemon_process_id) {
    g_daemon_process_id = daemon_process_id;
}

void dns_set_cache_timestamp_next(uint32_t count) {
    g_cache_timestamp_next = count;
}

uint32_t dns_get_cache_timestamp_next() {
    return g_cache_timestamp_next;
}

const char *get_active_cache_version() {
    return ACTIVE_DNS_CACHE_VERSION;
}

int get_dns_resolve_retry_count() {
    return 3;
}

void dns_set_etcd(const char *etcd) {
    g_etcd_server = etcd;
}

const char *dns_get_etcd() {
    return g_etcd_server;
}

void dns_set_host_name(const char *host_name) {
    g_host_name = host_name;
}

const char *dns_get_host_name(){
    return g_host_name;
}

const char *dns_get_host_ip() {
    return g_host_ip;
}

void dns_set_host_ip(const char *host_ip) {
    g_host_ip = host_ip;
}
