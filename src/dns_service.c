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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/errno.h>

#include "dns_service.h"
#include "dns_settings.h"
#include "dns_http.h"
#include "dns_etcd_cache.h"
#include "dns_question.h"

typedef struct dns_incoming_request_t {
    int socket_fd;
    dns_packet packet;
    ssize_t dns_packet_size;
    struct sockaddr_storage addr;
    socklen_t addr_length;
} dns_incoming_request;

// Global Variables:
//
bool g_dns_service_running = true;

bool dns_service_running() {
    return g_dns_service_running;
}

int startup_connection(transaction_context *context, short port) {

    struct addrinfo hints;
    memory_clear(&hints, sizeof hints);

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    char port_string[16];   // needs to fit a short
    memory_clear(port_string, sizeof port_string);
    snprintf(port_string, sizeof port_string, "%d", port);

    struct addrinfo *response = NULL;
    getaddrinfo(NULL, port_string, &hints, &response);

    int socket_fd = socket(response->ai_family, response->ai_socktype, response->ai_protocol);

    if (socket_fd == -1) {
        ERROR_LOG(context, "Unable to create socket, this is either a network issue where the port %d"
                " is already in use or a bug in the service.", port);
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
    }

    return socket_fd;
}

int g_dns_service_socket_fd = 0;

int dns_service_get_socket(transaction_context *context) {

    if (!g_dns_service_socket_fd) {
        int dns_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!dns_set_calling_socket_options(context, dns_socket_fd)) {
            exit(EXIT_FAILURE);
        }
        g_dns_service_socket_fd = dns_socket_fd;
    }

    return g_dns_service_socket_fd;
}

void dns_service_stop() {
    close(g_dns_service_socket_fd);
    g_dns_service_running = false;
}

void log_incoming_request(transaction_context *context, struct sockaddr_storage *addr, ssize_t packet_size) {
    if (dns_get_log_mode()) {
        char ip_string[INET6_ADDRSTRLEN];
        memory_clear(ip_string, sizeof ip_string);

        if (addr->ss_family == AF_INET) {
            inet_ntop(addr->ss_family,
                      &((struct sockaddr_in *) addr)->sin_addr,
                      ip_string, sizeof ip_string);

        } else {
            inet_ntop(addr->ss_family,
                      &((struct sockaddr_in6 *) addr)->sin6_addr,
                      ip_string, sizeof ip_string);
        }

        dns_string *sb_response = dns_string_new(1024);

        dns_string_sprintf(sb_response, "request=incoming;bytes=%d;ip_address=%s", packet_size, ip_string);

        INFO_LOG(context, dns_string_c_str(sb_response));

        dns_string_free(sb_response, true);
    }
}

bool read_incoming_request(transaction_context *context, int socket_fd, dns_incoming_request *incoming_request) {

    ASSERT(context, incoming_request);

    if (incoming_request == NULL || context == NULL) {
        ERROR_LOG(context, "read_incoming_request has invalid parameters this is a bug in the service.");
        return false;
    }

    incoming_request->socket_fd = socket_fd;
    incoming_request->addr_length = sizeof(incoming_request->addr);
    incoming_request->dns_packet_size = recvfrom(socket_fd,
                                                 &incoming_request->packet,
                                                 sizeof(incoming_request->packet),
                                                 0,
                                                 (struct sockaddr *) &incoming_request->addr,
                                                 &incoming_request->addr_length);

    // We Reset the context here because of the "wait" in recvfrom, we really don't want to measure that.
    //
    *context = create_context();

    log_incoming_request(context, &incoming_request->addr, incoming_request->addr_length);

    return incoming_request->dns_packet_size > 0;
}

bool send_back_response(transaction_context *context,
                        dns_incoming_request *incoming_request,
                        dns_packet *dns_response,
                        ssize_t dns_response_size) {

    ssize_t size = sendto(incoming_request->socket_fd,
                          dns_response,
                          (size_t) dns_response_size,
                          0,
                          (const struct sockaddr *) &incoming_request->addr,
                          incoming_request->addr_length);

    if (size < 0) {
        ERROR_LOG(context, "sendto() failed, this is either a network issue or a bug in the service. size = %d", size);
    }

    return size > 0;
}

bool dns_resolve(transaction_context *context,
                 int dns_socket,
                 dns_packet *packet,
                 size_t packet_size,
                 dns_packet *dns_packet_response,
                 size_t *dns_packet_response_size) {

    ASSERT(context, dns_packet_response != NULL && dns_packet_response_size != NULL && packet_size > 0);

    if (dns_packet_response
        && dns_packet_response_size
        && dns_get_resolvers_count() > 0) {

        memory_clear(dns_packet_response, sizeof(dns_packet));
        *dns_packet_response_size = 0;

        dns_packet dns_request;
        memory_clear(&dns_request, sizeof(dns_request));

        memcpy(&dns_request, packet, packet_size);

        struct sockaddr_in destination_addr;
        memory_clear(&destination_addr, sizeof(destination_addr));

        destination_addr.sin_family = AF_INET;
        destination_addr.sin_port = htons(53);
        socklen_t destination_size = sizeof(struct sockaddr_in);

        for (int index = 0; index < dns_get_resolvers_count(); index++) {

            destination_addr.sin_addr.s_addr = inet_addr(dns_get_resolvers()[index]);

            if (sendto(dns_socket,
                       &dns_request,
                       packet_size,
                       0,
                       (const struct sockaddr *) &destination_addr,
                       destination_size) <= 0) {

                ERROR_LOG(context, "sendto() failed, this is either a networking issue or a bug in the service. "
                        "Trying to connect to: %s", dns_get_resolvers()[index]);
            } else {
                dns_packet_log(context,
                               &dns_request,
                               "Packet sent to server %s: (size: %d)",
                               dns_get_resolvers()[index],
                               packet_size);

                struct sockaddr_in response_addr;
                memory_clear(&response_addr, sizeof(response_addr));
                socklen_t response_addr_size = 0;

                // NOTE: We maybe should make this a configurable.
                int retry_count = get_dns_resolve_retry_count();

                do {
                    ssize_t response_size = recvfrom(dns_socket,
                                                     dns_packet_response,
                                                     sizeof(dns_packet),
                                                     0,
                                                     (struct sockaddr *) &response_addr,
                                                     &response_addr_size);

                    if (response_size > 0) {
                        *dns_packet_response_size = (size_t) response_size;
                        dns_packet_log(context,
                                       dns_packet_response,
                                       "Packet received from server %s: (size: %d)",
                                       dns_get_resolvers()[index],
                                       response_size);

                        // It is only a success if we get an answer back!
                        //
                        return ntohs(dns_packet_response->header.answer_count) > 0;
                    }

                    INFO_LOG(context, "Failed to connect: retry count: %d", retry_count);

                } while (retry_count > 0 && (errno == EAGAIN || errno == EWOULDBLOCK));

                ERROR_LOG(context, "recvfrom() failed connecting to %s, %d : %s.", dns_get_resolvers()[index], errno,
                          strerror(errno));
            }
        }
    } else {
        ERROR_LOG(context, "dns_resolve() failed, please check network connectivity or could be an internal error.");
    }

    return false;
}

dns_cache_entry lookup_dns_packet(transaction_context *context, dns_packet *dns_packet_to_find) {
    if (dns_get_bypass_mode()) {
        dns_cache_entry cache_entry;
        memory_clear(&cache_entry, sizeof(cache_entry));

        return cache_entry;
    }

    return dns_cache_find(context, dns_packet_to_find);
}

dns_string *get_first_question_host_name(dns_packet *packet) {
    dns_question_handle *question = dns_packet_question_index(packet, 0);
    return dns_question_host(question);
}

struct timespec log_start_request(transaction_context *context, dns_incoming_request *incoming_request) {
    struct timespec start_time = timer_start();

    dns_string *first_question_host_name = get_first_question_host_name(&incoming_request->packet);

    if (first_question_host_name) {
        INFO_LOG(context, "Started processing for '%s'", dns_string_c_str(first_question_host_name));

        dns_string_free(first_question_host_name, true);
    } else {
        ERROR_LOG(context, "Out of memory, can't allocate string!  This is either an issue with the server or a bug.");
    }

    return start_time;
}

void log_end_request(transaction_context *context, struct timespec start_time, dns_incoming_request *incoming_request) {

    dns_string *first_question_host_name = get_first_question_host_name(&incoming_request->packet);

    if (first_question_host_name) {
        INFO_LOG(context, "'%s';nanoseconds=%d ",
                 dns_string_c_str(first_question_host_name),
                 timer_end(start_time));

        dns_string_free(first_question_host_name, true);
    } else {
        ERROR_LOG(context, "Out of memory, can't allocate string!  This is either an issue with the server or a bug.");
    }
}

void process_request(transaction_context *context, int socket_fd) {

    dns_incoming_request incoming_request;
    memory_clear(&incoming_request, sizeof(incoming_request));

    if (read_incoming_request(context, socket_fd, &incoming_request)) {

        struct timespec start_time = log_start_request(context, &incoming_request);

        // Look in etcd first....
        //
        dns_cache_entry cache_entry = lookup_etcd_packet(context, &incoming_request.packet);

        if (cache_entry.entry_state != ENTRY_ENABLED) {
            // Look in DNS Cache
            //
            cache_entry = lookup_dns_packet(context, &incoming_request.packet);
        }

        if (cache_entry.entry_state == ENTRY_ENABLED) {
            send_back_response(context,
                               &incoming_request,
                               &cache_entry.dns_packet_response,
                               cache_entry.dns_packet_response_size);
        } else {
            INFO_LOG(context, "Cache miss, going to upstream resolver");
            dns_packet dns_response;
            memory_clear(&dns_response, sizeof(dns_response));

            size_t dns_response_size = 0;

            bool success = dns_resolve(context,
                                       dns_service_get_socket(context),
                                       &incoming_request.packet,
                                       (size_t) incoming_request.dns_packet_size,
                                       &dns_response,
                                       &dns_response_size);

            send_back_response(context, &incoming_request, &dns_response, dns_response_size);

            if (success) {
                dns_cache_insert(context, &dns_response, dns_response_size);
            }
        }

        log_end_request(context, start_time, &incoming_request);
    }
}

void dns_service_loop(int socket_fd) {

    while (dns_service_running()) {
        transaction_context context = create_context();
        process_request(&context, socket_fd);
    }
}


int dns_service_start(transaction_context *context) {

    if (dns_get_resolvers() != NULL) {

        debug_service_start();

        int socket_fd = startup_connection(context, dns_get_port());
        if (socket_fd != -1) {
            dns_service_loop(socket_fd);
        }

        close(socket_fd);

        free_string_array(dns_get_resolvers(), dns_get_resolvers_count());
        dns_cache_stop();
        return 0;
    }

    dns_cache_stop();
    return SO_ERROR;
}

