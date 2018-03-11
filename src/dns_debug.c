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

#ifndef __MACH__
#define _POSIX_C_SOURCE 200809L
#define __unused
#include <strings.h>
#else

#include <ntsid.h>

#endif

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "dns_utils.h"
#include "dns_settings.h"
#include "dns_service.h"
#include "dns_cache.h"

size_t http_read_line(int socket, dns_string_ptr buffer) {
    if (NULL == buffer) {
        return 0;
    }

    // Free the buffer because the expectation is that we are reading in a
    // whole new line.
    //
    dns_string_reset(buffer);

    // Now we read in the data:
    //
    char c = '\0';

    while (c != '\n') {
        ssize_t n = recv(socket, &c, 1, 0);

        if (n > 0) {
            if (c == '\r') {
                n = recv(socket, &c, 1, MSG_PEEK);

                if ((n > 0) && (c == '\n')) {
                    recv(socket, &c, 1, 0);
                } else {
                    c = '\n';
                }
            }
            dns_string_append_char(buffer, c);
        } else {
            c = '\n';
        }
    }

    return dns_string_length(buffer);
}

void http_output_debug_page(transaction_context *context, dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    dns_string_sprintf(response_body, "<HTML><TITLE>DNS Active Cache </TITLE>\r\n");
    dns_string_sprintf(response_body, "<BODY><CENTER><B>DNS Active Cache Stats</B></CENTER><BR>\r\n");
    dns_string_sprintf(response_body, "\r\n");

    dns_cache_html_log(context, response_body);

    dns_string_sprintf(response_body, "\r\n");

    dns_string_sprintf(response_body, "</BODY></HTML>\r\n");
    dns_string_sprintf(response_body, "\r\n");

    dns_string_sprintf(response, "HTTP/1.0 200 OK\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Content-Type: text/html\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}

void http_output_status_page(transaction_context *context, dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    dns_cache_json_log(context, response_body);

    dns_string_sprintf(response, "HTTP/1.0 200 OK\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Content-Type: application/json;charset=UTF-8\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}


void http_output_health_check(transaction_context *context, dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    if (dns_cache_health_check(context)) {
        dns_string_sprintf(response_body, "{\"status\":\"UP\"}");
    } else {
        dns_string_sprintf(response_body, "{\"status\":\"DOWN\"}");
    }

    dns_string_sprintf(response, "HTTP/1.0 200 OK\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Transfer-Encoding: Identity\r\n");
    dns_string_sprintf(response, "Content-Type: application/json;charset=UTF-8\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}

void http_output_active(transaction_context  __unused *context, dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    dns_string_sprintf(response_body, "ACTIVE");

    dns_string_sprintf(response, "HTTP/1.0 200 OK\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Transfer-Encoding: Identity\r\n");
    dns_string_sprintf(response, "Content-Type: text/plain;charset=UTF-8\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}

void http_output_build_info(dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    dns_string_sprintf(response_body, "{\"version\":\"%s\"}", get_active_cache_version());

    dns_string_sprintf(response, "HTTP/1.0 200 OK\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Content-Type: application/json;charset=UTF-8\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}

void http_not_found(dns_string_ptr response) {

    dns_string_ptr response_body = dns_string_new(1024);

    dns_string_sprintf(response_body, "<HTML><TITLE>Not Found</TITLE>\r\n");
    dns_string_sprintf(response_body, "<BODY><P>The server could not fulfill\r\n");
    dns_string_sprintf(response_body, "your request because the resource specified\r\n");
    dns_string_sprintf(response_body, "is unavailable or nonexistent.</P>\r\n");
    dns_string_sprintf(response_body, "</BODY></HTML>\r\n");
    dns_string_sprintf(response_body, "\r\n");

    dns_string_sprintf(response, "HTTP/1.0 404 NOT FOUND\r\n");
    dns_string_sprintf(response, "Server: %s\r\n", get_active_cache_version());
    dns_string_sprintf(response, "Content-Type: text/html\r\n");
    dns_string_sprintf(response, "Connection: close\r\n");
    dns_string_sprintf(response, "Content-Length: %d\r\n", dns_string_length(response_body));
    dns_string_sprintf(response, "\r\n%s", dns_string_c_str(response_body));

    dns_string_free(response_body, true);
}

void http_output_response(transaction_context *context, dns_string_ptr request_path, dns_string_ptr response) {

    if (request_path && 0 == strncmp(dns_string_c_str(request_path), "/health", strlen("/health"))) {
        // Do Health Checks
        //
        http_output_health_check(context, response);
    }
    if (request_path && 0 == strncmp(dns_string_c_str(request_path), "/active", strlen("/active"))) {
        // Just respond with ACTIVE
        //
        http_output_active(context, response);
    } else if (request_path && 0 == strncmp(dns_string_c_str(request_path), "/buildinfo", strlen("/buildinfo"))) {
        // Output Build information
        //
        http_output_build_info(response);
    } else if (request_path && 0 == strncmp(dns_string_c_str(request_path), "/status", strlen("/status"))) {
        // Just output stats.
        //
        http_output_status_page(context, response);
    } else if (request_path && 0 == strncmp(dns_string_c_str(request_path), "/debug", strlen("/debug"))) {
        // Just output stats.
        //
        http_output_debug_page(context, response);
    } else {
        http_not_found(response);
    }
}

void http_send_response(int socket, dns_string_ptr response) {
    if (NULL != response) {
        if (dns_string_length(response) > 0) {
            send(socket,
                 dns_string_c_str(response),
                 dns_string_length(response), 0);
        }
    }
}

int debug_startup_connection(transaction_context *context) {

    struct addrinfo hints;
    memory_clear(&hints, sizeof hints);

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_string[16];   // needs to fit a short
    memory_clear(port_string, sizeof port_string);
    snprintf(port_string, sizeof port_string, "%d", debug_get_port());

    struct addrinfo *response = NULL;
    getaddrinfo(NULL, port_string, &hints, &response);

    int socket_fd = socket(response->ai_family, response->ai_socktype, response->ai_protocol);

    if (socket_fd == -1) {
        ERROR_LOG(context, "Unable to create socket, this is either a network issue where the port %"
                " is already in use or a bug in the service.", debug_get_port());
    } else {
        // The setsockopt() function is used to allow the local address to
        // be reused when the server is restarted before the required wait
        // time expires.
        //
        int option_one = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                       (char *) &option_one, sizeof(option_one)) < 0) {
            ERROR_LOG(context, "Setsockopt(SO_REUSEADDR) failed, this is either"
                    " a network issue or a bug in the service.");
        }

        if (bind(socket_fd, response->ai_addr, response->ai_addrlen) < 0) {
            ERROR_LOG(context, "Bind failed on socket %d, this is either a network "
                    "issue or a bug in the service", socket_fd);
            close(socket_fd);
            socket_fd = -1;
        }

        // The backlog argument (5) defines the maximum length to which the queue of pending connections for
        // sockfd may grow. If a connection request arrives when the queue is full, the client may receive an
        // error with an indication of ECONNREFUSED or, if the underlying protocol supports
        // retransmission, the request may be ignored so that a later reattempt at connection succeeds.
        //

        if (listen(socket_fd, 5) < 0) {
            ERROR_LOG(context, "listen debug failed");
            close(socket_fd);
            socket_fd = -1;
        }
    }

    return socket_fd;
}

// List of methods
//
typedef enum {
    http_invalid,
    http_get,
    http_post,
    http_delete,
    http_put,
    http_options,
    http_head,
    http_trace,
    http_connect
} http_method_t;

http_method_t http_map_string_to_method(dns_string_ptr request_buffer) {
    http_method_t result = http_invalid;
    const char *method = dns_string_c_str(request_buffer);

    if (0 == strncasecmp(method, "GET", 3)) {
        result = http_get;
    } else if (0 == strncasecmp(method, "POST", 4)) {
        result = http_post;
    } else if (0 == strncasecmp(method, "PUT", 3)) {
        result = http_put;
    } else if (0 == strncasecmp(method, "DELETE", 6)) {
        result = http_delete;
    } else if (0 == strncasecmp(method, "OPTIONS", 7)) {
        result = http_options;
    } else if (0 == strncasecmp(method, "HEAD", 4)) {
        result = http_head;
    } else if (0 == strncasecmp(method, "TRACE", 5)) {
        result = http_trace;
    } else if (0 == strncasecmp(method, "CONNECT", 7)) {
        result = http_connect;
    }

    return result;
}

dns_string_ptr http_parse_path(dns_string_ptr request_buffer) {
    const char *query = dns_string_c_str(request_buffer);

    // Skip Method
    //
    while (*query != '\0' && *query != ' ' && *query != '\t') {
        ++query;
    }

    // Skip Spaces
    //
    while (*query != '\0' && (*query == ' ' || *query == '\t')) {
        ++query;
    }

    dns_string_ptr request_path = dns_string_new(1024);

    // Extract the path
    //
    while (*query != '\0' && *query != '?' && *query != ' ' && *query != '\t') {
        dns_string_append_char(request_path, *query);
        query++;
    }

    return request_path;
}

void *debug_thread(void __unused *arg) {

    transaction_context context = create_context();

    INFO_LOG(&context, "Starting debug thread on port %hu", debug_get_port());

    if (debug_get_port()) {
        int socket_fd = debug_startup_connection(&context);

        if (-1 != socket_fd) {
            INFO_LOG(&context, "[INFO] DNS Active Cache has taking the stage on port %d", debug_get_port());

            while (dns_service_running()) {
                dns_string_ptr request_buffer = dns_string_new(1024);

                struct sockaddr_in sockaddr_client;
                socklen_t sockaddr_client_length = sizeof(sockaddr_client);
                memory_clear(&sockaddr_client, sockaddr_client_length);

                int client_socket = accept(socket_fd, (struct sockaddr *) &sockaddr_client, &sockaddr_client_length);
                http_read_line(client_socket, request_buffer);

                http_method_t method = http_map_string_to_method(request_buffer);

                dns_string_ptr request_path = http_parse_path(request_buffer);

                dns_string_ptr response_buffer = dns_string_new(1024);
                switch (method) {
                    case http_get:
                        http_output_response(&context, request_path, response_buffer);
                        break;
                    default:
                        http_not_found(response_buffer);
                        break;
                }

                http_send_response(client_socket, response_buffer);

                close(client_socket);

                dns_string_free(response_buffer, true);
                dns_string_free(request_buffer, true);
                dns_string_free(request_path, true);
            }

            close(socket_fd);
        } else {
            ERROR_LOG(&context, "[ERROR] DNS Active Cache was unable to take the stage on port %d", debug_get_port());
        }
    }

    return NULL;
}

pthread_t g_debug_thread_id = 0;

void debug_service_start() {
    if (dns_get_debug_mode()) {
        pthread_create(&g_debug_thread_id, NULL, &debug_thread, NULL);
    }
}

