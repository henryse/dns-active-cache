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

#ifndef DNS_ACTIVE_CACHE_ETCD_JSON_PARSER_H
#define DNS_ACTIVE_CACHE_ETCD_JSON_PARSER_H

#include <yajl/yajl_parse.h>
#include <string.h>
#include <stdlib.h>
#include "dns_etcd.h"
#include "dns_utils.h"

typedef struct yajl_parser_context_t {
    void *user_data;
    dns_string_array key_stack;
    dns_string_array node_stack;
} yajl_parser_context;
#define UNUSED(v) (void)(v)

bool etcd_string_eq(dns_string *string1, const char *string2){
    bool result = strncmp(dns_string_c_str(string1), string2, strlen(string2)) == 0;
    result = result && dns_string_length(string1) == strlen(string2);
    return result;
}

static int etcd_parse_action(dns_string *act) {
    if (etcd_string_eq(act, "set")) {
        return ETCD_SET;
    }
    if (etcd_string_eq(act, "update")) {
        return ETCD_UPDATE;
    }
    if (etcd_string_eq(act, "get")) {
        return ETCD_GET;
    }
    if (etcd_string_eq(act, "delete")) {
        return ETCD_DELETE;
    }
    if (etcd_string_eq(act, "create")) {
        return ETCD_CREATE;
    }
    if (etcd_string_eq(act, "expire")) {
        return ETCD_EXPIRE;
    }
    if (etcd_string_eq(act, "compareAndSwap")) {
        return ETCD_CAS;
    }
    if (etcd_string_eq(act, "compareAndDelete")) {
        return ETCD_CAD;
    }
    return -1;
}

static int yajl_parse_bool_cb(void *ctx, int val) {
    yajl_parser_context *c = ctx;
    etcd_response_node *node;
    dns_string *key;

    key = dns_array_pop(&c->key_stack);
    if (etcd_string_eq(key, "dir")) {
        node = dns_array_top(&c->node_stack);
        node->dir = val;
    }
    dns_string_free(key, true);
    return 1;
}

static int yajl_parse_integer_cb(void *ctx, long long val) {
    yajl_parser_context *c = ctx;
    etcd_response_node *node;
    dns_string *key;

    key = dns_array_pop(&c->key_stack);
    node = dns_array_top(&c->node_stack);
    if (etcd_string_eq(key, "ttl")) {
        node->ttl = (int64_t) val;
    } else if (etcd_string_eq(key, "modifiedindex")) {
        node->modified_index = (uint64_t) val;
    } else if (etcd_string_eq(key, "createdindex")) {
        node->created_index = (uint64_t) val;
    } else if (etcd_string_eq(key, "expiration")) {
        node->expiration = (uint64_t) val;
    }
    dns_string_free(key, true);

    return 1;
}

static int yajl_parse_string_cb(void *ctx, const unsigned char *val, size_t len) {
    yajl_parser_context *c = ctx;
    etcd_response_node *node;
    etcd_response *resp;
    dns_string *key, *value;

    key = dns_array_pop(&c->key_stack);
    if (etcd_string_eq(key, "key")) {
        node = dns_array_top(&c->node_stack);
        node->key = dns_string_new_fixed(len, (const char *) val);
    } else if (etcd_string_eq(key, "value")) {
        node = dns_array_top(&c->node_stack);
        node->value = dns_string_new_fixed(len, (const char *) val);
    } else if (etcd_string_eq(key, "action")) {
        resp = c->user_data;
        value = dns_string_new_fixed(len, (const char *) val);
        resp->action = etcd_parse_action(value);
        dns_string_free(value, true);
    }
    dns_string_free(key, true);
    return 1;
}

static int yajl_parse_start_map_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string *key;
    etcd_response_node *node, *child;

    /*this is key of nodes*/
    if (dns_array_size(&c->key_stack) > 0) {
        key = dns_array_top(&c->key_stack);
        node = dns_array_top(&c->node_stack);
        if (etcd_string_eq(key, "nodes")) {
            child = memory_alloc(sizeof(etcd_response_node));
            dns_array_append(node->nodes, child);
            dns_array_append(&c->node_stack, child);
            dns_array_append(&c->key_stack, dns_string_new_c(sizeof("noname"), "noname"));
        }
        return 1;
    }

    if (c->user_data == NULL) {
        c->user_data = etcd_response_allocate();
    }

    return 1;
}

static int yajl_parse_map_key_cb(void *ctx, const unsigned char *key, size_t len) {
    yajl_parser_context *c = ctx;
    etcd_response *resp = (etcd_response *) c->user_data;

    dns_string *name = dns_string_new_fixed(len, (const char *) key);
    dns_string_tolower(name);
    dns_array_append(&c->key_stack, name);

    if (etcd_string_eq(name, "node")) {
        resp->node = memory_alloc(sizeof(etcd_response_node));
        dns_array_append(&c->node_stack, resp->node);
    } else if (etcd_string_eq(name, "prevnode")) {
        resp->prev_node = memory_alloc(sizeof(etcd_response_node));
        dns_array_append(&c->node_stack, resp->prev_node);
    }
    return 1;
}

static int yajl_parse_end_map_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string *key = dns_array_pop(&c->key_stack);
    if (key) {
        dns_string_free(key, true);
    }
    dns_array_pop(&c->node_stack);
    return 1;
}

static int yajl_parse_start_array_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    etcd_response_node *node;
    dns_string *key;

    key = dns_array_top(&c->key_stack);
    node = (etcd_response_node *) dns_array_top(&c->node_stack);
    if (etcd_string_eq(key, "nodes")) {
        if (node) {
            node->nodes = dns_array_create(10);
        }
    }
    return 1;
}

static int yajl_parse_end_array_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string *key;

    key = (dns_string *) dns_array_top(&c->key_stack);
    if (key != NULL && etcd_string_eq(key, "nodes")) {
        dns_string_free(dns_array_pop(&c->key_stack), true);
    }
    return 1;
}

static int yajl_parse_null_ignore_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string_free(dns_array_pop(&c->key_stack), true);
    /*just ignore*/
    return 1;
}

static int yajl_parse_double_ignore_cb(void *ctx, double val) {
    UNUSED(val);
    return yajl_parse_null_ignore_cb(ctx);
}

static int yajl_parse_bool_ignore_cb(void *ctx, int val) {
    UNUSED(val);
    return yajl_parse_null_ignore_cb(ctx);
}

static yajl_callbacks callbacks = {
        yajl_parse_null_ignore_cb, //null
        yajl_parse_bool_cb, //boolean
        yajl_parse_integer_cb, //integer
        yajl_parse_double_ignore_cb, //double
        NULL, //number
        yajl_parse_string_cb, //string
        yajl_parse_start_map_cb, //start map
        yajl_parse_map_key_cb, //map key
        yajl_parse_end_map_cb, //end map
        yajl_parse_start_array_cb, //start array
        yajl_parse_end_array_cb //end array
};

/* Error message parse functions
 * Parsing error response is more simple than a normal response,
 * we do not have to handle the nested objects , so we do not need
 * a node_stack.
 * */
static int yajl_err_parse_integer_cb(void *ctx, long long val) {
    yajl_parser_context *c = ctx;
    etcd_error *err = c->user_data;
    dns_string *key = dns_array_pop(&c->key_stack);
    if (etcd_string_eq(key, "errorcode")) {
        err->etcd_code = (int) val;
    }
    dns_string_free(key, true);
    return 1;
}

static int yajl_err_parse_string_cb(void *ctx, const unsigned char *val, size_t len) {
    yajl_parser_context *c = ctx;
    etcd_error *err = c->user_data;
    dns_string *key = dns_array_pop(&c->key_stack);
    if (etcd_string_eq(key, "message")) {
        err->message = dns_string_new_c(len, (const char *) val);
    } else if (etcd_string_eq(key, "cause")) {
        err->cause = dns_string_new_c(len, (const char *) val);
    }
    dns_string_free(key, true);

    return 1;
}

static int yajl_err_parse_start_map_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    if (c->user_data == NULL) {
        c->user_data = memory_alloc(sizeof(etcd_error));
    }
    return 1;
}

static int yajl_err_parse_map_key_cb(void *ctx, const unsigned char *key, size_t len) {
    yajl_parser_context *c = ctx;
    dns_string *name = dns_string_new_c(len, (const char *) key);
    dns_string_tolower(name);
    dns_array_append(&c->key_stack, name);
    return 1;
}

static int yajl_err_parse_end_map_cb(void *ctx) {
    UNUSED(ctx);
    return 1;
}

static yajl_callbacks error_callbacks = {
        yajl_parse_null_ignore_cb, //null
        yajl_parse_bool_ignore_cb, //boolean
        yajl_err_parse_integer_cb, //integer
        yajl_parse_double_ignore_cb, //double
        NULL, //number
        yajl_err_parse_string_cb, //string
        yajl_err_parse_start_map_cb, //start map
        yajl_err_parse_map_key_cb, //map key
        yajl_err_parse_end_map_cb, //end map
        NULL,                //start array
        yajl_parse_null_ignore_cb //end array
};

static int yajl_sync_parse_string_cb(void *ctx, const unsigned char *val, size_t len) {
    yajl_parser_context *c = ctx;
    dns_array *array = c->user_data;
    dns_string *key = dns_array_top(&c->key_stack);
    if (key && etcd_string_eq(key, "clientURLs")) {
        dns_array_append(array, dns_string_new_c(len, (const char *) val));
    }
    return 1;
}

static int yajl_sync_parse_start_map_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    if (c->user_data == NULL) {
        c->user_data = dns_array_create(10);
    }
    return 1;
}

static int yajl_sync_parse_map_key_cb(void *ctx, const unsigned char *key, size_t len) {
    yajl_parser_context *c = ctx;
    dns_string *name = dns_string_new_c(len, (const char *) key);
    if (etcd_string_eq(name, "clientURLs")) {
        dns_array_append(&c->key_stack, name);
    } else {
        dns_string_free(name, true);
    }
    return 1;
}

static int yajl_sync_parse_end_map_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string *key = dns_array_pop(&c->key_stack);
    if (key) {
        dns_string_free(key, true);
    }
    return 1;
}

static int yajl_sync_parse_end_array_cb(void *ctx) {
    yajl_parser_context *c = ctx;
    dns_string *key;
    key = dns_array_top(&c->key_stack);
    if (key && etcd_string_eq(key, "clientURLs")) {
        dns_string_free(dns_array_pop(&c->key_stack), true);
    }
    return 1;
}

static yajl_callbacks sync_callbacks = {
        NULL,  //null
        NULL,  //boolean
        NULL, //integer
        NULL, //double
        NULL, //number
        yajl_sync_parse_string_cb, //string
        yajl_sync_parse_start_map_cb, //start map
        yajl_sync_parse_map_key_cb, //map key
        yajl_sync_parse_end_map_cb, //end map
        NULL, //start array
        yajl_sync_parse_end_array_cb //end array
};

#endif //DNS_ACTIVE_CACHE_ETCD_JSON_PARSER_H