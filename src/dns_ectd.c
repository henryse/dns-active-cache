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

#include "dns_etcd_json_parser.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"

enum ETCD_API_TYPE {
    ETCD_KEYS,
    ETCD_MEMBERS
};

typedef struct etcd_request_t {
    enum ETCD_HTTP_METHOD method;
    enum ETCD_API_TYPE api_type;
    dns_string *uri;
    dns_string *url;
    dns_string *data;
    etcd_client *cli;
} etcd_request;

static const char *http_method[] = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTION"
};

typedef struct etcd_response_parser_t {
    int st;
    int http_status;
    enum ETCD_API_TYPE api_type;
    dns_string *buf;
    void *resp;
    yajl_parser_context ctx;
    yajl_handle json;
} etcd_response_parser;

static const char *etcd_event_action[] = {
        "set",
        "get",
        "update",
        "create",
        "delete",
        "expire",
        "compareAndSwap",
        "compareAndDelete"
};

void *etcd_cluster_request(etcd_client *cli, etcd_request *req);

int etcd_curl_setopt(CURL *curl, etcd_watcher *watcher);

void etcd_client_init(etcd_client *cli, dns_array *addresses) {
    size_t i = 0;
    dns_array *addrs = NULL;
    dns_string *addr = NULL;
    curl_global_init(CURL_GLOBAL_ALL);
    srand((uint32_t) time(0));

    cli->keys_space = "v2/keys";
    cli->stat_space = "v2/stat";
    cli->member_space = "v2/members";
    cli->curl = curl_easy_init();

    addrs = dns_array_create(dns_array_size(addresses));
    for (i = 0; i < dns_array_size(addresses); ++i) {
        addr = dns_array_get(addresses, i);
        if (strncmp(dns_string_c_str(addr), "http", 4) != 0) {
            dns_array_append(addrs,
                             dns_string_sprintf(dns_string_new_empty(), "http://%s", dns_string_c_str(addr)));
        } else {
            dns_array_append(addrs, dns_string_new_str(addr));
        }
    }

    cli->addresses = dns_array_shuffle(addrs);
    cli->picked = rand() % (dns_array_size(cli->addresses)); // NOLINT

    cli->settings.verbose = 0;
    cli->settings.connect_timeout = 1;
    cli->settings.read_timeout = 1;
    cli->settings.write_timeout = 1;
    cli->settings.user = NULL;
    cli->settings.password = NULL;

    dns_array_init(&cli->watchers, 10);

    curl_easy_setopt(cli->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(cli->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(cli->curl, CURLOPT_TCP_KEEPINTVL, 1L);
    curl_easy_setopt(cli->curl, CURLOPT_USERAGENT, "etcd");
    curl_easy_setopt(cli->curl, CURLOPT_POSTREDIR, 3L);
    curl_easy_setopt(cli->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
}

etcd_client *etcd_client_create(dns_array *addresses) {
    etcd_client *cli = NULL;

    cli = memory_alloc(sizeof(etcd_client));
    etcd_client_init(cli, addresses);
    return cli;
}

void etcd_client_destroy(etcd_client *cli) {
    etcd_addresses_release(cli->addresses);
    dns_array_release(cli->addresses);
    cli->addresses = NULL;

    dns_string_free(cli->settings.user, 0);
    cli->settings.user = NULL;

    dns_string_free(cli->settings.password, 0);
    cli->settings.password = NULL;

    curl_easy_cleanup(cli->curl);
    cli->curl = NULL;

    curl_global_cleanup();
    dns_array_destroy(&cli->watchers);
}

void etcd_client_release(etcd_client *cli) {
    if (cli) {
        etcd_client_destroy(cli);
        free(cli);
    }
}

void etcd_addresses_release(dns_array *addrs) {
    dns_string *string = NULL;
    if (addrs) {
        size_t count = dns_array_size(addrs);
        for (size_t i = 0; i < count; ++i) {
            string = dns_array_get(addrs, i);
            dns_string_free(string, 0);
        }
    }
}

void etcd_client_sync_cluster(etcd_client *cli) {
    etcd_request req;
    dns_array *addrs = NULL;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_GET;
    req.api_type = ETCD_MEMBERS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s", cli->member_space);
    addrs = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    if (addrs == NULL) {
        return;
    }
    etcd_addresses_release(cli->addresses);
    dns_array_release(cli->addresses);
    cli->addresses = dns_array_shuffle(addrs);
    cli->picked = rand() % (dns_array_size(cli->addresses)); // NOLINT
}

void etcd_setup_user(etcd_client *cli, const char *user, const char *password) {
    if (user != NULL) {
        cli->settings.user = dns_string_new_c_string(strlen(user), user);
    }
    if (password != NULL) {
        cli->settings.password = dns_string_new_c_string(strlen(password), password);
    }
}

void etcd_setup_tls(etcd_client *cli, const char *CA, const char *cert, const char *key) {
    if (CA) {
        curl_easy_setopt(cli->curl, CURLOPT_CAINFO, CA);
    }
    if (cert) {
        curl_easy_setopt(cli->curl, CURLOPT_SSLCERT, cert);
    }
    if (key) {
        curl_easy_setopt(cli->curl, CURLOPT_SSLKEY, key);
    }
}

size_t etcd_parse_response(char *ptr, size_t size, size_t nmemb, void *user_data);

etcd_watcher *etcd_watcher_create(etcd_client *cli,
                                  const char *key,
                                  uint64_t index,
                                  int recursive,
                                  int once,
                                  etcd_watcher_callback callback,
                                  void *user_data) {
    etcd_watcher *watcher = memory_alloc(sizeof(etcd_watcher));
    watcher->cli = cli;
    watcher->key = dns_string_new_c_string(strlen(key), key);
    watcher->index = index;
    watcher->recursive = recursive;
    watcher->once = once;
    watcher->callback = callback;
    watcher->user_data = user_data;
    watcher->curl = curl_easy_init();

    watcher->parser = memory_alloc(sizeof(etcd_response_parser));
    watcher->parser->st = 0;
    watcher->parser->buf = dns_string_new_empty();
    watcher->parser->resp = etcd_response_allocate();

    watcher->array_index = -1;

    return watcher;
}

void etcd_watcher_release(etcd_watcher *watcher) {
    if (watcher) {
        if (watcher->key) {
            dns_string_free(watcher->key, true);
            watcher->key = NULL;
        }
        if (watcher->curl) {
            curl_easy_cleanup(watcher->curl);
            watcher->curl = NULL;
        }
        if (watcher->parser) {
            dns_string_free(watcher->parser->buf, true);
            watcher->parser->buf = NULL;

            if (watcher->parser->json) {
                yajl_free(watcher->parser->json);
                watcher->parser->json = NULL;
                dns_string_array_destroy(&watcher->parser->ctx.key_stack);
                dns_string_array_destroy(&watcher->parser->ctx.node_stack);
            }
            etcd_response_free(watcher->parser->resp);
            watcher->parser->resp = NULL;

            free(watcher->parser);
            watcher->parser = NULL;
        }
        free(watcher);
    }
}

// reset the temp resource one time watching used
void etcd_watcher_reset(etcd_watcher *watcher) {
    if (!watcher) {
        return;
    }

    // reset the curl handler
    curl_easy_reset(watcher->curl);
    etcd_curl_setopt(watcher->curl, watcher);

    if (watcher->parser) {
        watcher->parser->st = 0;
        // allocate the resp, because it is freed after calling the callback
        watcher->parser->resp = etcd_response_allocate();

        // clear the buf, it is allocated by etcd_watcher_create,
        // so should only be freed in etcd_watcher_release
        //
        dns_string_reset(watcher->parser->buf);

        // the json object created by etcd_parse_response, so it should be freed
        // after having got some response
        if (watcher->parser->json) {
            yajl_free(watcher->parser->json);
            watcher->parser->json = NULL;

            dns_string_array_destroy(&watcher->parser->ctx.key_stack);
            dns_string_array_destroy(&watcher->parser->ctx.node_stack);
            watcher->parser->json = NULL;
        }
    }
}

static dns_string *etcd_watcher_build_url(etcd_client *cli, etcd_watcher *watcher) {
    dns_string *url = NULL;
    url = dns_string_sprintf(dns_string_new_empty(),
                             "%s/%s%s?wait=true",
                             (dns_string *) dns_array_get(cli->addresses,
                                                            cli->picked),
                             cli->keys_space,
                             watcher->key);
    if (watcher->index) {
        url = dns_string_sprintf(url, "&waitIndex=%lu", watcher->index);
    }
    if (watcher->recursive) {
        url = dns_string_sprintf(url, "&recursive=true");
    }
    return url;
}

int etcd_curl_setopt(CURL *curl, etcd_watcher *watcher) {
    dns_string *url = NULL;

    url = etcd_watcher_build_url(watcher->cli, watcher);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    dns_string_free(url, true);

    // See above about CURLOPT_NOSIGNAL
    //
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, watcher->cli->settings.connect_timeout);
#if LIBCURL_VERSION_NUM >= 0x071900
    curl_easy_setopt(watcher->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(watcher->curl, CURLOPT_TCP_KEEPINTVL, 1L); // the same as go-etcd
#endif
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "etcd");
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, 3L);     // post after redirecting
    curl_easy_setopt(curl, CURLOPT_VERBOSE, watcher->cli->settings.verbose);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, etcd_parse_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, watcher->parser);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_setopt(curl, CURLOPT_PRIVATE, watcher);
    watcher->curl = curl;

    return 1;
}

int etcd_add_watcher(dns_array *watchers, etcd_watcher *watcher) {
    etcd_watcher *w = NULL;

    etcd_curl_setopt(watcher->curl, watcher);

    watcher->attempts = dns_array_size(watcher->cli->addresses);
    // We use an array to store watchers. It will cause holes when remove some watchers.
    // watcher->array_index is used to reset to the original hole if the watcher was deleted before.
    //
    if (watcher->array_index == -1) {
        dns_array_append(watchers, watcher);
        watcher->array_index = (int) (dns_array_size(watchers) - 1);
    } else {
        w = dns_array_get(watchers, (size_t) watcher->array_index);
        if (w) {
            etcd_watcher_release(w);
        }
        dns_array_set(watchers, (size_t) watcher->array_index, watcher);
    }
    return 1;
}

int etcd_del_watcher(dns_array *watchers, etcd_watcher *watcher) {
    if (watcher) {
        int index = watcher->array_index;
        if (index >= 0) {
            dns_array_set(watchers, (size_t) index, NULL);
            etcd_watcher_release(watcher);
        }
    }
    return 1;
}

int etcd_stop_watcher(etcd_client *cli, etcd_watcher *watcher) {
    // Clear the callback function pointer to ensure to stop notify the user
    // Set once to 1 indicates that the watcher would stop after next trigger.
    //
    // The watcher object would be freed by etcd_reap_watchers
    // Watchers may hang forever if it would be never triggered after set once to 1
    // FIXME: Cancel the blocking watcher
    //
    UNUSED(cli);
    watcher->callback = NULL;
    watcher->once = 1;
    return 1;
}

static int etcd_reap_watchers(etcd_client *cli, CURLM *mcurl) {
    uint64_t index = 0;
    int added = 0, ignore = 0;
    CURLMsg *msg = NULL;
    CURL *curl = NULL;
    dns_string *url = NULL;
    etcd_watcher *watcher = NULL;
    etcd_response *resp = NULL;
    added = 0;

    while ((msg = curl_multi_info_read(mcurl, &ignore)) != NULL) {
        if (msg->msg == CURLMSG_DONE) {
            curl = msg->easy_handle;
            curl_easy_getinfo(curl, CURLINFO_PRIVATE, &watcher);

            resp = watcher->parser->resp;
            index = watcher->index;
            if (msg->data.result != CURLE_OK) {
                // try next in round-robin ways
                // FIXME There is a race condition if multiple watchers failed
                if (watcher->attempts) {
                    cli->picked = (cli->picked + 1) % (dns_array_size(cli->addresses));
                    url = etcd_watcher_build_url(cli, watcher);
                    curl_easy_setopt(watcher->curl, CURLOPT_URL, url);
                    dns_string_free(url, true);
                    curl_multi_remove_handle(mcurl, curl);
                    watcher->parser->st = 0;
                    curl_easy_reset(curl);
                    etcd_curl_setopt(curl, watcher);
                    curl_multi_add_handle(mcurl, curl);
                    continue;
                } else {
                    resp->err = memory_alloc(sizeof(etcd_error));
                    resp->err->etcd_code = error_cluster_failed;
                    resp->err->message = dns_string_new_c_string(32, "etcd_reap_watchers: all cluster servers failed.");
                }
            }
            if (watcher->callback) {
                watcher->callback(watcher->user_data, resp);
                if (resp->err && resp->err->etcd_code != 401) { // not outdated
                    curl_multi_remove_handle(mcurl, curl);
                    etcd_watcher_release(watcher);
                    break;
                }
                if (resp->node) {
                    index = resp->node->modified_index;
                } else {
                    ++index;
                }
                etcd_response_free(resp);
                watcher->parser->resp = NULL; // suppress it be freed again by etcd_watcher_release
            }
            if (!watcher->once) {
                curl_multi_remove_handle(mcurl, curl);
                etcd_watcher_reset(watcher);

                if (watcher->index) {
                    watcher->index = index + 1;
                    url = etcd_watcher_build_url(cli, watcher);
                    curl_easy_setopt(watcher->curl, CURLOPT_URL, url);
                    dns_string_free(url, true);
                }
                curl_multi_add_handle(mcurl, watcher->curl);
                ++added;
                continue;
            }
            curl_multi_remove_handle(mcurl, curl);
            etcd_watcher_release(watcher);
        }
    }
    return added;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#pragma ide diagnostic ignored "OCDFAInspection"

int etcd_multi_watch(etcd_client *cli, dns_array *watchers) {
    int maxfd = 0, left = 0, added = 0;
    long timeout = 0;
    etcd_watcher *watcher = NULL;

    fd_set r, w, e;
    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_ZERO(&e);

    struct timeval tv;
    memory_clear(&tv, sizeof(tv));

    CURLM *curlm = curl_multi_init();
    int count = (int) dns_array_size(watchers);
    for (int i = 0; i < count; ++i) {
        watcher = dns_array_get(watchers, (size_t) i);
        curl_easy_setopt(watcher->curl, CURLOPT_PRIVATE, watcher);
        curl_multi_add_handle(curlm, watcher->curl);
    }
    long back_off = 100;          // 100ms
    long back_off_max = 1000;     // 1 sec

    for (;;) {
        curl_multi_perform(curlm, &left);
        if (left) {
            FD_ZERO(&r);
            FD_ZERO(&w);
            FD_ZERO(&e);

            curl_multi_timeout(curlm, &timeout);
            if (timeout == -1) {
                timeout = 100; // wait for 0.1 seconds
            }
            tv.tv_sec = timeout / 1000;
#ifdef __MACH__
            tv.tv_usec = (__darwin_suseconds_t) ((timeout % 1000) * 1000);
#else
            tv.tv_usec = (timeout % 1000) * 1000;
#endif
            curl_multi_fdset(curlm, &r, &w, &e, &maxfd);

            // TODO handle errors
            select(maxfd + 1, &r, &w, &e, &tv);

            curl_multi_perform(curlm, &left);
        }
        added = etcd_reap_watchers(cli, curlm);
        if (added == 0 && left == 0) {
            // It will call curl_multi_perform immediately if:
            // 1. left is 0
            // 2. a new attempt should be issued
            // It is expected to sleep a mount time between attempts.
            // So we fix this by increasing added counter only
            // when a new request should be issued.
            // When added is 0, maybe there are retring requests or nothing.
            // Either situations should wait before issuing the request.
            //
            if (back_off < back_off_max) {
                back_off = 2 * back_off;
            } else {
                back_off = back_off_max;
            }
            tv.tv_sec = back_off / 1000;
#ifdef __MACH__
            tv.tv_usec = (__darwin_suseconds_t) ((timeout % 1000) * 1000);
#else
            tv.tv_usec = (back_off % 1000) * 1000;
#endif
            select(1, 0, 0, 0, &tv);
        }
    }

    curl_multi_cleanup(curlm);
    return count;
}

#pragma clang diagnostic pop

static void *etcd_multi_watch_wrapper(void *args[]) {
    etcd_client *cli = args[0];
    dns_array *watchers = args[1];
    free(args);
    etcd_multi_watch(cli, watchers);
    return 0;
}

etcd_watch_id etcd_multi_watch_async(etcd_client *cli, dns_array *watchers) {
    void **args = NULL;
    args = calloc(2, sizeof(void *));
    args[0] = cli;
    args[1] = watchers;
    pthread_t thread = NULL;
    pthread_create(&thread, NULL, (void *(*)(void *)) etcd_multi_watch_wrapper, args);
    return thread;
}

int etcd_multi_watch_async_stop(etcd_client *cli, etcd_watch_id wid) {
    (void) cli;
    // Cancel causes the thread exit immediately, so the resouce has been
    // allocated won't be freed. The memory leak is OK because the process
    // is going to exit.
    // TODO fix the memory leaks
    //
    pthread_cancel(wid);
    pthread_join(wid, 0);
    return 0;
}

etcd_response *etcd_get(etcd_client *cli, const char *key) {
    return etcd_lsdir(cli, key, 0, 0);
}

etcd_response *etcd_lsdir(etcd_client *cli, const char *key, int sort, int recursive) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    etcd_response *resp = NULL;

    req.method = ETCD_HTTP_GET;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);
    if (sort) {
        req.uri = dns_string_sprintf(req.uri, "?sorted=true");
    }
    if (recursive) {
        req.uri = dns_string_sprintf(req.uri, "%crecursive=true", sort ? '&' : '?');
    }
    resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_set(etcd_client *cli, const char *key,
                        const char *value, uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    char *value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));
    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "value=%s", value_escaped);

    curl_free(value_escaped);
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }

    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);

    dns_string_free(req.uri, true);
    dns_string_free(params, true);

    return resp;
}

etcd_response *etcd_mkdir(etcd_client *cli, const char *key, uint64_t ttl) {

    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "dir=true&prevExist=false");
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_setdir(etcd_client *cli, const char *key, uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "dir=true");
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_updatedir(etcd_client *cli, const char *key, uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));


    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "dir=true&prevExist=true");
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_update(etcd_client *cli,
                           const char *key,
                           const char *value,
                           uint64_t ttl,
                           int refresh) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "prevExist=true");
    if (value) {
        char *value_escaped;
        value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));
        params = dns_string_sprintf(params, "&value=%s", value_escaped);
        curl_free(value_escaped);
    }
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    if (refresh) {
        params = dns_string_sprintf(params, "&refresh=true");
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_create(etcd_client *cli,
                           const char *key,
                           const char *value,
                           uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    char *value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));
    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "prevExist=false&value=%s", value_escaped);
    curl_free(value_escaped);
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_create_in_order(etcd_client *cli,
                                    const char *key,
                                    const char *value,
                                    uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_POST;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    char *value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));
    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "value=%s", value_escaped);
    curl_free(value_escaped);
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_delete(etcd_client *cli, const char *key) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));


    req.method = ETCD_HTTP_DELETE;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_rmdir(etcd_client *cli, const char *key, int recursive) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_DELETE;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s?dir=true", cli->keys_space, key);
    if (recursive) {
        req.uri = dns_string_sprintf(req.uri, "&recursive=true");
    }

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_watch(etcd_client *cli, const char *key, uint64_t index) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_GET;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s?wait=true&waitIndex=%lu", cli->keys_space, key, index);

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_watch_recursive(etcd_client *cli, const char *key, uint64_t index) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_GET;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s?wait=true&recursive=true&waitIndex=%lu", cli->keys_space,
                                 key,
                                 index);

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_cmp_and_swap(etcd_client *cli, const char *key, const char *value, const char *prev, uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    char *value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "value=%s&prevValue=%s", value_escaped, prev);
    curl_free(value_escaped);
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_cmp_and_swap_by_index(etcd_client *cli,
                                          const char *key,
                                          const char *value,
                                          uint64_t prev,
                                          uint64_t ttl) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_PUT;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s", cli->keys_space, key);

    char *value_escaped = curl_easy_escape(cli->curl, value, (int) strlen(value));

    dns_string *params = dns_string_sprintf(dns_string_new_empty(), "value=%s&prevIndex=%lu", value_escaped, prev);
    curl_free(value_escaped);
    if (ttl) {
        params = dns_string_sprintf(params, "&ttl=%lu", ttl);
    }
    req.data = params;

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    dns_string_free(params, true);
    return resp;
}

etcd_response *etcd_cmp_and_delete(etcd_client *cli, const char *key, const char *prev) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_DELETE;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s?prevValue=%s", cli->keys_space, key, prev);

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

etcd_response *etcd_cmp_and_delete_by_index(etcd_client *cli, const char *key, uint64_t prev) {
    etcd_request req;
    memory_clear(&req, sizeof(etcd_request));

    req.method = ETCD_HTTP_DELETE;
    req.api_type = ETCD_KEYS;
    req.uri = dns_string_sprintf(dns_string_new_empty(), "%s%s?prevIndex=%lu", cli->keys_space, key, prev);

    etcd_response *resp = etcd_cluster_request(cli, &req);
    dns_string_free(req.uri, true);
    return resp;
}

void etcd_node_release(etcd_response_node *node) {

    if (node->nodes) {
        size_t count = dns_array_size(node->nodes);
        for (size_t i = 0; i < count; ++i) {
            etcd_response_node *n = dns_array_get(node->nodes, i);
            etcd_node_release(n);
        }
        dns_array_release(node->nodes);
    }
    if (node->key) {
        dns_string_free(node->key, true);
        node->key = NULL;
    }
    if (node->value) {
        dns_string_free(node->value, true);
        node->value = NULL;
    }

    memory_clear(node, sizeof(etcd_response_node));
    free(node);
}

etcd_response *etcd_response_allocate() {
    etcd_response *response = memory_alloc(sizeof(etcd_response));

    return response;
}

void etcd_response_free(etcd_response *response) {
    if (response) {
        if (response->err) {
            etcd_error_release(response->err);
            response->err = NULL;
        }
        if (response->node) {
            etcd_node_release(response->node);
        }
        if (response->prev_node) {
            etcd_node_release(response->prev_node);
        }
        memory_clear(response, sizeof(etcd_response));
        free(response);
    }
}

void etcd_error_release(etcd_error *err) {
    if (err) {
        if (err->message) {
            dns_string_free(err->message, true);
            err->message = NULL;
        }
        if (err->cause) {
            dns_string_free(err->cause, true);
            err->cause = NULL;
        }
        free(err);
    }
}

static void etcd_node_print(etcd_response_node *node) {
    if (node) {
        printf("Node TTL: %lu\n", (unsigned long) node->ttl);
        printf("Node ModifiedIndex: %lu\n", (unsigned long) node->modified_index);
        printf("Node CreatedIndex: %lu\n", (unsigned long) node->created_index);
        printf("Node Key: %s\n", (char *) node->key);
        printf("Node Value: %s\n", (char *) node->value);
        printf("Node Dir: %d\n", node->dir);
        printf("\n");
        if (node->nodes) {
            int count = (int) dns_array_size(node->nodes);
            for (int i = 0; i < count; ++i) {
                etcd_response_node *n = dns_array_get(node->nodes, (size_t) i);
                etcd_node_print(n);
            }
        }
    }
}

void etcd_response_print(etcd_response *resp) {
    if (resp->err) {
        printf("Error Code:%d\n", resp->err->etcd_code);
        printf("Error Message:%s\n", dns_string_c_str(resp->err->message));
        printf("Error Cause:%s\n", dns_string_c_str(resp->err->cause));
        return;
    }
    printf("Etcd Action:%s\n", etcd_event_action[resp->action]);
    printf("Etcd Index:%lu\n", (unsigned long) resp->etcd_index);
    printf("Raft Index:%lu\n", (unsigned long) resp->raft_index);
    printf("Raft Term:%lu\n", (unsigned long) resp->raft_term);
    if (resp->node) {
        printf("-------------Node------------\n");
        etcd_node_print(resp->node);
    }
    if (resp->prev_node) {
        printf("-----------prevNode------------\n");
        etcd_node_print(resp->prev_node);
    }
}

size_t etcd_parse_response(char *ptr,
                           size_t size,
                           size_t nmemb,
                           void *user_data) {
    etcd_response *resp = NULL;
    dns_array *addrs = NULL;

    enum resp_parser_st {
        request_line_start_st,
        request_line_end_st,
        request_line_http_status_start_st,
        request_line_http_status_st,
        request_line_http_status_end_st,
        header_key_start_st,
        header_key_st,
        header_key_end_st,
        header_val_start_st,
        header_val_st,
        header_val_end_st,
        blank_line_st,
        json_start_st,
        json_end_st,
        response_discard_st
    };
    // Headers we are interested in:
    // X-Etcd-Index: 14695
    // X-Raft-Index: 672930
    // X-Raft-Term: 12
    //
    etcd_response_parser *parser = user_data;
    if (parser->api_type == ETCD_MEMBERS) {
        addrs = parser->resp;
    } else {
        resp = parser->resp;
    }
    size_t len = size * nmemb;
    for (int i = 0; i < len; ++i) {
        if (parser->st == request_line_start_st) {
            if (ptr[i] == ' ') {
                parser->st = request_line_http_status_start_st;
            }
            continue;
        }
        if (parser->st == request_line_end_st) {
            if (ptr[i] == '\n') {
                parser->st = header_key_start_st;
            }
            continue;
        }
        if (parser->st == request_line_http_status_start_st) {
            dns_string_append_str_length(parser->buf, ptr + i, 1);
            parser->st = request_line_http_status_st;
            continue;
        }
        if (parser->st == request_line_http_status_st) {
            if (ptr[i] == ' ') {
                parser->st = request_line_http_status_end_st;
            } else {
                dns_string_append_str_length(parser->buf, ptr + i, 1);
                continue;
            }
        }

        if (parser->st == request_line_http_status_end_st) {
            dns_string *val = parser->buf;
            parser->http_status = atoi(dns_string_c_str(val)); // NOLINT
            dns_string_reset(parser->buf);
            parser->st = request_line_end_st;
            if (parser->api_type == ETCD_MEMBERS && parser->http_status != 200) {
                parser->st = response_discard_st;
            }
            continue;
        }
        if (parser->st == header_key_start_st) {
            if (ptr[i] == '\r') {
                ++i;
            }
            if (ptr[i] == '\n') {
                parser->st = blank_line_st;
                if (parser->http_status >= 300 && parser->http_status < 400) {
                    // this is a redirection, restart the state machine
                    parser->st = request_line_start_st;
                    break;
                }
                continue;
            }
            parser->st = header_key_st;
        }
        if (parser->st == header_key_st) {
            dns_string_append_str_length(parser->buf, ptr + i, 1);
            if (ptr[i] == ':') {
                parser->st = header_key_end_st;
            } else {
                continue;
            }
        }
        if (parser->st == header_key_end_st) {
            parser->st = header_val_start_st;
            continue;
        }
        if (parser->st == header_val_start_st) {
            if (ptr[i] == ' ') {
                continue;
            }
            parser->st = header_val_st;
        }
        if (parser->st == header_val_st) {
            if (ptr[i] == '\r') {
                ++i;
            }
            if (ptr[i] == '\n') {
                parser->st = header_val_end_st;
            } else {
                dns_string_append_str_length(parser->buf, ptr + i, 1);
                continue;
            }
        }
        if (parser->st == header_val_end_st) {
            parser->st = header_key_start_st;
            if (parser->api_type == ETCD_MEMBERS) {
                dns_string_reset(parser->buf);
                continue;
            }
            size_t count = 0;
            dns_string_array *kvs = dns_string_split_length(parser->buf, ":", &count);
            dns_string_reset(parser->buf);
            if (count < 2) {
                dns_string_array_delete(kvs);
                continue;
            }

            dns_string *key = dns_array_get(kvs, 0);
            dns_string *val = dns_array_get(kvs, 1);
            if (strncmp(dns_string_c_str(key), "X-Etcd-Index", sizeof("X-Etcd-Index") - 1) == 0) {
                resp->etcd_index = (uint64_t) atoi(dns_string_c_str(val)); // NOLINT
            } else if (strncmp(dns_string_c_str(key), "X-Raft-Index", sizeof("X-Raft-Index") - 1) == 0) {
                resp->raft_index = (uint64_t) atoi(dns_string_c_str(val)); // NOLINT
            } else if (strncmp(dns_string_c_str(key), "X-Raft-Term", sizeof("X-Raft-Term") - 1) == 0) {
                resp->raft_term = (uint64_t) atoi(dns_string_c_str(val)); // NOLINT
            }
            dns_string_array_delete(kvs);
            continue;
        }
        if (parser->st == blank_line_st) {
            if (ptr[i] != '{') {
                // not a json response, discard
                parser->st = response_discard_st;
                if (resp->err == NULL && parser->api_type == ETCD_KEYS) {
                    resp->err = memory_alloc(sizeof(etcd_error));
                    resp->err->etcd_code = error_response_parsed_failed;
                    resp->err->message = dns_string_new_c_string(64, "not a json response");
                    resp->err->cause = dns_string_new_c_string(len, ptr);
                }
                continue;
            }
            parser->st = json_start_st;
            dns_array_init(&parser->ctx.key_stack, 10);
            dns_array_init(&parser->ctx.node_stack, 10);
            if (parser->api_type == ETCD_MEMBERS) {
                parser->ctx.user_data = addrs;
                parser->json = yajl_alloc(&sync_callbacks, 0, &parser->ctx);
            } else {
                if (parser->http_status != 200 && parser->http_status != 201) {
                    resp->err = memory_alloc(sizeof(etcd_error));
                    parser->ctx.user_data = resp->err;
                    parser->json = yajl_alloc(&error_callbacks, 0, &parser->ctx);
                } else {
                    parser->ctx.user_data = resp;
                    parser->json = yajl_alloc(&callbacks, 0, &parser->ctx);
                }
            }
        }
        if (parser->st == json_start_st) {
            if (yajl_status_ok == yajl_parse(parser->json, (const unsigned char *) ptr + i, len - i)) {
                //all text left has been parsed, break the for loop
                break;
            } else {
                parser->st = json_end_st;
            }
        }
        if (parser->st == json_end_st) {
            yajl_status status = yajl_complete_parse(parser->json);
            // parse failed, TODO set error message
            if (status != yajl_status_ok) {
                if (parser->api_type == ETCD_KEYS && resp->err == NULL) {
                    resp->err = memory_alloc(sizeof(etcd_error));
                    resp->err->etcd_code = error_response_parsed_failed;
                    resp->err->message = dns_string_new_c_string(32, "http response is invalid json format");
                    resp->err->cause = dns_string_new_c_string(len, ptr);
                }
                return 0;
            }
            break;
        }
        if (parser->st == response_discard_st) {
            return len;
        }
    }
    return len;
}

void *etcd_send_request(CURL *curl,
                        etcd_request *req) {
    etcd_response_parser parser;
    memory_clear(&parser, sizeof(parser));

    etcd_response *resp = NULL;
    dns_array *addrs = NULL;

    if (req->api_type == ETCD_MEMBERS) {
        addrs = dns_array_create(10);
        parser.resp = addrs;
    } else {
        resp = etcd_response_allocate();
        parser.resp = resp;
    }

    parser.api_type = req->api_type;
    parser.st = 0; // 0 should be the start state of the state machine
    parser.buf = dns_string_new_empty();
    parser.json = NULL;

    curl_easy_setopt(curl, CURLOPT_URL, dns_string_c_str(req->url));
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method[req->method]);
    if (req->method == ETCD_HTTP_PUT || req->method == ETCD_HTTP_POST) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dns_string_c_str(req->data));
    } else {
        // We must clear post fields here:
        // We reuse the curl handle for all HTTP methods.
        // CURLOPT_POSTFIELDS would be set when issue a PUT request.
        // The field  pointed to the freed req->data. It would be
        //reused by next request.
        //
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    }
    if (req->cli->settings.user) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, dns_string_c_str(req->cli->settings.user));
    }
    if (req->cli->settings.password) {
        curl_easy_setopt(curl, CURLOPT_PASSWORD, dns_string_c_str(req->cli->settings.password));
    }
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &parser);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, etcd_parse_response);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, req->cli->settings.verbose);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, req->cli->settings.connect_timeout);

    struct curl_slist *chunk = NULL;
    chunk = curl_slist_append(chunk, "Expect:");

    CURLcode curl_response = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    if (curl_response != CURLE_OK) {
        // TODO: Need Do something here..
    }

    curl_response = curl_easy_perform(curl);

    curl_slist_free_all(chunk);
    //release the parser resource
    dns_string_free(parser.buf, true);
    if (parser.json) {
        yajl_free(parser.json);
        dns_string_array_destroy(&parser.ctx.key_stack);
        dns_string_array_destroy(&parser.ctx.node_stack);
    }

    if (curl_response != CURLE_OK) {
        if (req->api_type == ETCD_MEMBERS) {
            return addrs;
        }
        if (resp->err == NULL) {
            resp->err = memory_alloc(sizeof(etcd_error));
            resp->err->etcd_code = error_send_request_failed;
            resp->err->message = dns_string_new_c_string(32, curl_easy_strerror(curl_response));
            resp->err->cause = (req->url);
        }
        return resp;
    }
    return parser.resp;
}

// etcd_cluster_request tries to request the whole cluster. It round-robin to next server if the request failed
//
void *etcd_cluster_request(etcd_client *cli,
                           etcd_request *req) {
    size_t count = dns_array_size(cli->addresses);
    etcd_response *response = NULL;

    for (size_t i = 0; i < count; ++i) {
        dns_string *url = dns_string_sprintf(dns_string_new_empty(), "%s/%s",
                                                dns_string_c_str((dns_string *) dns_array_get(cli->addresses,
                                                                                                cli->picked)),
                                                dns_string_c_str(req->uri));

        // TODO: This needs to be cleaned up!  Get rid of the evil void * from the calls.
        req->url = url;
        req->cli = cli;
        void *service_response = etcd_send_request(cli->curl, req);
        dns_string_free(url, true);

        if (req->api_type == ETCD_MEMBERS) {
            dns_array *addrs = (dns_array *) service_response;
            // Got the result addresses, return
            if (addrs && dns_array_size(addrs)) {
                return addrs;
            }
            // Empty or error ? retry
            if (addrs) {
                dns_array_release(addrs);
            }
            if (i == count - 1) {
                break;
            }
        } else if (req->api_type == ETCD_KEYS) {
            response = (etcd_response *)service_response;
            if (response && response->err && response->err->etcd_code == error_send_request_failed) {
                if (i == count - 1) {
                    // Note we
                    break;
                }
                etcd_response_free(response);
                response=NULL;
            } else {
                // got response, return
                return response;
            }
        }
        // try next
        cli->picked = (cli->picked + 1) % count;
    }

    // the whole cluster failed
    //
    if (req->api_type == ETCD_MEMBERS) return NULL;
    if (response) {
        etcd_error *err = NULL;

        if (response->err) {
            err = response->err; // remember last error
        }
        response->err = memory_alloc(sizeof(etcd_error));
        response->err->etcd_code = error_cluster_failed;
        response->err->message = dns_string_new_c_string(32, "etcd_cluster_request: all cluster servers failed.");
        if (err) {
            etcd_error_release(err);
        }
        response->err->cause = dns_string_new_str(req->uri);
    }
    return response;
}

#pragma clang diagnostic pop