/**********************************************************************
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
//    This file is derived from: https://github.com/shafreeck/cetcd
//
**********************************************************************/
#ifndef DNS_ACTIVE_CACHE_ETCD_H
#define DNS_ACTIVE_CACHE_ETCD_H

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"

#include <curl/curl.h>
#include <pthread.h>
#include <stdint.h>
#include "dns_array.h"
#include "dns_string.h"

typedef pthread_t etcd_watch_id;

enum ETCD_HTTP_METHOD {
    ETCD_HTTP_GET,
    ETCD_HTTP_POST,
    ETCD_HTTP_PUT,
    ETCD_HTTP_DELETE,
    ETCD_HTTP_HEAD,
    ETCD_HTTP_OPTION
};
enum ETCD_EVENT_ACTION {
    ETCD_SET,
    ETCD_GET,
    ETCD_UPDATE,
    ETCD_CREATE,
    ETCD_DELETE,
    ETCD_EXPIRE,
    ETCD_CAS,
    ETCD_CAD,
    ETCD_ACTION_MAX
};

// etcd error codes range is [100, 500]
// We use 1000+ as etcd error codes;
//

#define error_response_parsed_failed 1000
#define error_send_request_failed    1001
#define error_cluster_failed         1002
typedef struct etcd_error_t {
    int etcd_code;
    dns_string_ptr message;
    dns_string_ptr cause;
    uint64_t index;
} etcd_error;

typedef struct etcd_client_t {
    CURL *curl;
    etcd_error *err;
    dns_array watchers;        // curl watch handlers
    dns_array *addresses;      // cluster addresses
    const char *keys_space;
    const char *stat_space;
    const char *member_space;
    size_t picked;
    struct {
        int verbose;
        uint64_t ttl;
        uint64_t connect_timeout;
        uint64_t read_timeout;
        uint64_t write_timeout;
        dns_string_ptr user;
        dns_string_ptr password;
    } settings;

} etcd_client;

typedef struct etcd_response_node_t {
    dns_array *nodes;          //struct etcd_response_node_t
    dns_string_ptr key;
    dns_string_ptr value;
    int dir;                    // 1 for true, and 0 for false
    uint64_t expiration;
    int64_t ttl;
    uint64_t modified_index;
    uint64_t created_index;

} etcd_response_node;

typedef struct etcd_response_t {
    etcd_error *err;
    int action;
    struct etcd_response_node_t *node;
    struct etcd_response_node_t *prev_node;
    uint64_t etcd_index;
    uint64_t raft_index;
    uint64_t raft_term;
} etcd_response;

typedef etcd_response *etcd_response_ptr;

struct etcd_response_parser_t;

typedef int (*etcd_watcher_callback)(void *user_data, etcd_response *resp);

typedef struct etcd_watcher_t {
    etcd_client *cli;
    struct etcd_response_parser_t *parser;
    size_t attempts;
    int array_index;            //  the index in array cli->watchers

    CURL *curl;
    int once;
    int recursive;
    uint64_t index;
    dns_string_ptr key;
    void *user_data;
    etcd_watcher_callback callback;
} etcd_watcher;

// etcd_client_create allocate the etcd_client and return the pointer*/
//
etcd_client *etcd_client_create(dns_array *addresses);

// etcd_client_init initialize a etcd_client*/
//
void etcd_client_init(etcd_client *cli, dns_array *addresses);

// etcd_client_destroy destroy the resource a client used*/
//
void etcd_client_destroy(etcd_client *cli);

// etcd_client_release free the etcd_client object*/
//
void etcd_client_release(etcd_client *cli);

// etcd_addresses_release free the array of an etcd cluster addresses*/
//
void etcd_addresses_release(dns_array *addrs);

// etcd_client_sync_cluster sync the members of an etcd cluster, this may be used
// when the members of etcd changed
//
void etcd_client_sync_cluster(etcd_client *cli);

// etcd_setup_user set the auth username and password*/
void etcd_setup_user(etcd_client *cli, const char *user, const char *password);

// etcd_setup_tls setup the tls cert and key*/
void etcd_setup_tls(etcd_client *cli, const char *CA,
                    const char *cert, const char *key);

// etcd_get get the value of a key*/
etcd_response *etcd_get(etcd_client *cli, const char *key);

// etcd_lsdir list the nodes under a directory*/
etcd_response *etcd_lsdir(etcd_client *cli, const char *key, int sort, int recursive);

// etcd_set set the value of a key*/
etcd_response *etcd_set(etcd_client *cli, const char *key,
                        const char *value, uint64_t ttl);

// etcd_mkdir create a directory, it will fail if the key has exist*/
etcd_response *etcd_mkdir(etcd_client *cli, const char *key, uint64_t ttl);

// etcd_mkdir create a directory whether it exist or not*/
etcd_response *etcd_setdir(etcd_client *cli, const char *key, uint64_t ttl);

// etcd_updatedir update the ttl of a directory*/
etcd_response *etcd_updatedir(etcd_client *cli, const char *key, uint64_t ttl);

// etcd_update update the value or ttl of a key, only refresh the ttl if refresh is set*/
etcd_response *etcd_update(etcd_client *cli, const char *key,
                           const char *value, uint64_t ttl, int refresh);

// etcd_create create a node with value*/
etcd_response *etcd_create(etcd_client *cli, const char *key,
                           const char *value, uint64_t ttl);

// etcd_create_in_order create in order keys*/
etcd_response *etcd_create_in_order(etcd_client *cli, const char *key,
                                    const char *value, uint64_t ttl);

// etcd_delete delete a key*/
etcd_response *etcd_delete(etcd_client *cli, const char *key);

// etcd_rmdir delete a directory*/
etcd_response *etcd_rmdir(etcd_client *cli, const char *key, int recursive);

// etcd_watch watch the changes of a key*/
etcd_response *etcd_watch(etcd_client *cli, const char *key, uint64_t index);

// etcd_watch_recursive watch a key and all its sub keys*/
etcd_response *etcd_watch_recursive(etcd_client *cli, const char *key, uint64_t index);

etcd_response *etcd_cmp_and_swap(etcd_client *cli, const char *key, const char *value,
                                 const char *prev, uint64_t ttl);

etcd_response *etcd_cmp_and_swap_by_index(etcd_client *cli, const char *key, const char *value,
                                          uint64_t prev, uint64_t ttl);

etcd_response *etcd_cmp_and_delete(etcd_client *cli, const char *key, const char *prev);

etcd_response *etcd_cmp_and_delete_by_index(etcd_client *cli, const char *key, uint64_t prev);

// etcd_watcher_create create a watcher object*/
etcd_watcher *etcd_watcher_create(etcd_client *cli, const char *key, uint64_t index,
                                  int recursive, int once, etcd_watcher_callback callback, void *userdata);

// etcd_add_watcher add a watcher to the array*/
int etcd_add_watcher(dns_array *watchers, etcd_watcher *watcher);

// etcd_del_watcher delete a watcher from the array*/
int etcd_del_watcher(dns_array *watchers, etcd_watcher *watcher);

// etcd_multi_watch setup all watchers and wait*/
int etcd_multi_watch(etcd_client *cli, dns_array *watchers);

// etcd_multi_watch setup all watchers in a seperate thread and return the watch id*/
etcd_watch_id etcd_multi_watch_async(etcd_client *cli, dns_array *watchers);

// etcd_multi_watch stop the watching thread with the watch id*/
int etcd_multi_watch_async_stop(etcd_client *cli, etcd_watch_id wid);

// etcd_stop_watcher stop a watcher which has been setup*/
int etcd_stop_watcher(etcd_client *cli, etcd_watcher *watcher);

void etcd_response_print(etcd_response *resp);

etcd_response *etcd_response_allocate();

void etcd_response_free(etcd_response *resp);

void etcd_error_release(etcd_error *err);

#pragma clang diagnostic pop
#endif //DNS_ACTIVE_CACHE_ETCD_H

