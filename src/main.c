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

#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#ifndef __MACH__
#include <unistd.h>
#endif

#include "dns_service.h"
#include "dns_cache.h"
#include "dns_settings.h"
#include "dns_etcd_cache.h"

void shutdown_service() {
    transaction_context context = context_create();
    ERROR_LOG(&context, "Service is shutting down!");
    dns_service_stop();
    dns_cache_stop();
}

void signal_shutdown(int value) {
    transaction_context context = context_create();
    ERROR_LOG(&context, "Shutting down the service, signal: %d", value);
    shutdown_service();
    exit(value);
}

void signal_SIGPIPE(int value) {
    transaction_context context = context_create();
    ERROR_LOG(&context, "SIGPIPE failure: %d", value);
    shutdown_service();
    exit(value);
}

void dns_process_setup() {
    signal(SIGABRT, signal_shutdown);
    signal(SIGFPE, signal_shutdown);
    signal(SIGILL, signal_shutdown);
    signal(SIGINT, signal_shutdown);
    signal(SIGSEGV, signal_shutdown);
    signal(SIGTERM, signal_shutdown);
    signal(SIGPIPE, signal_SIGPIPE);
}

void usage(const char *program) {
    fprintf(stdout, "Version: %s\n", dns_active_cache_version_get());
    fprintf(stdout, "Usage:     %s --port=PORT --resolvers=RESOLVERS --timeout_ms=TIMEOUT_IN_MS\n", program);
    fprintf(stdout, "Example:   %s --port=5300 --resolvers=/etc/resolv.dns_cache --timeout_ms=500 \n\n", program);
    fprintf(stdout, "DNS Active Cache is a high performance DNS cache intended for server environments.\n"
                    "This is a simple active local DNS caching service, it NOT intended to be used as a desktop DNS cache.\n"
                    "The issue we are trying to address has to do with Cloud Deployments(AWS).  The DNS style load balancing requires \n"
                    "services to constantly query upstream DNS servers to discover what IP address they need \n"
                    "to send requests to.  We were able to reduce our DNS requests to sub millisecond \n"
                    "requests by having a local smart cache.\n\n"
                    "Most servers only talk to a couple of upstream servers, so this service will allow you to configure \n"
                    "how many 'cache entries' you need(see 'Configuration' below).\n\n"
                    "This simple service will do the following:\n\n"
                    "     1. When a DNS request comes in it will try to call the DSN servers defined in 'resolv.dns_cache'.\n\n"
                    "     2. If a valid DNS entry is found, it will then store the entry into the local cache, see entries parameter.\n\n"
                    "     3. A separate thread there after will keep refreshing the local DNS entries local cache.\n\n"
                    "Thus after the first request, all future requests will be cached locally.\n");
    fprintf(stdout, "     log            General logging messages. default: %s\n",
            dns_log_mode_get() ? "true" : "false");
    fprintf(stdout, "     port           port to listen on, the default is %d\n", dns_port_get());
    fprintf(stdout, "     resolvers      resolvers file containing a list of name-servers. default: %s\n",
            dns_resolvers_file_get());
    fprintf(stdout, "     timeout        Network time out in seconds.  Default: %ds\n",
            dns_socket_timeout_get());
    fprintf(stdout,
            "     interval       How often should the service scan the cache to find timed out entries. default: %ds\n",
            dns_cache_polling_interval_get());
    fprintf(stdout, "     entries        Max cache entries. default: %d\n", dns_cache_size_get());
    fprintf(stdout, "     etcd           ETCD path, for example: --etcd=http://192.168.1.129:2379, if this is not "
                    " set then ETCD support is not used.\n");
    fprintf(stdout, "     http           Simple HTTP port to dump diagnostics, support HTTP GET, [host]:[port], "
                    "if zero then disabled.  default: %hu\n", dns_http_port_get());
    fprintf(stdout, "     optimize       Optimize the use of ports by reusing them. default: %s\n",
            dns_optimize_mode_get() ? "true" : "false");
    fprintf(stdout, "     maxttl         Max TTL in seconds for DNS entries, if an upstream server returns a value "
                    "high then maxttl, the TTL will be set to maxttl.  default:  %ds\n", dns_max_ttl_get());
    fprintf(stdout, "     daemon         Run as a daemon.  default: %s\n", dns_run_as_daemon_get() ? "true" : "false");
    fprintf(stdout, "     host_name      Required for ETCD: host name to used as the base name for services "
                    " and is used as the DNS authority."
                    "\n");
    fprintf(stdout,
            "     host_ip        Required for ETCD: host ip used for identifying what the local hosted services listed in ETCD\n");
    fprintf(stdout, "     help           Get this help message\n");
}

bool is_valid_ip_address(char *ipAddress) {
    char str[INET6_ADDRSTRLEN];
    int result = inet_pton(AF_INET, ipAddress, str);

    if (result != 1) {
        // maybe IPV6?
        result = inet_pton(AF_INET6, ipAddress, str);
    }

    return result == 1;
}

bool get_ip_address(char *line, char **ip_address) {
    if (NULL != line) {
        char *save = NULL;
        char *token = strtok_r(line, " \n", &save);

        if (token && strcmp(token, "nameserver") == 0) {
            token = strtok_r(save, " \n", &save);
            if (is_valid_ip_address(token)) {
                if (ip_address != NULL) {
                    *ip_address = malloc_string(strlen(token));
                    strcpy(*ip_address, token);
                }
                return true;
            }
        }
    }

    return false;
}

size_t resolvers_parse_ip_address(FILE *file, char **ip_addresses) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t count = 0;

    while ((read = getline(&line, &len, file)) != -1) {
        if (read > 0) {
            if (line[0] == '#') {
                continue;
            }

            if (get_ip_address(line, (ip_addresses ? &ip_addresses[count] : NULL))) {
                count++;
            }
        }
    }
    if (line) {
        free(line);
    }

    return count;
}

char **resolvers_parse(const char *resolvers_file, size_t *count) {
    char **resolvers = NULL;

    // Check to see if the file exists and
    // open the file and parse out the ip address.
    //
    FILE *file = fopen(resolvers_file, "r");

    if (NULL != file) {

        // Count the number of ip addresses
        //
        *count = resolvers_parse_ip_address(file, NULL);

        // Allocate the memory
        //
        resolvers = malloc_string_array(*count);

        // Rewind the file
        //
        rewind(file);

        // Parse it again.
        //
        resolvers_parse_ip_address(file, resolvers);

        // Close file
        //
        fclose(file);
    }

    return resolvers;
}

bool parse_arguments(transaction_context *context, int argc, char *argv[]) {

    static struct option long_options[] =
            {
                    {"log",       optional_argument, 0, 'l'},
                    {"port",      optional_argument, 0, 'p'},
                    {"resolvers", optional_argument, 0, 'r'},
                    {"timeout",   optional_argument, 0, 't'},
                    {"interval",  optional_argument, 0, 'v'},
                    {"entries",   optional_argument, 0, 'e'},
                    {"etcd",      optional_argument, 0, 'E'},
                    {"http",      optional_argument, 0, 'H'},
                    {"bypass",    optional_argument, 0, 'b'},
                    {"optimize",  optional_argument, 0, 'o'},
                    {"maxttl",    optional_argument, 0, 'm'},
                    {"daemon",    optional_argument, 0, 'D'},
                    {"host_name", optional_argument, 0, 'h'},
                    {"host_ip",   optional_argument, 0, 'i'},
                    {"help",      optional_argument, 0, '?'},
                    {0, 0,                           0, 0}
            };

    int option_index = 0;
    int c = 0;

    do {
        c = getopt_long(argc, argv, "?p:r:t:e:E:v:d:b:o:m:i:", long_options, &option_index);

        switch (c) {
            case -1:
                // Ignore this one.
                break;

            case 'l':
                dns_log_mode_set(strcmp(optarg, "true") == 0);
                INFO_LOG(context, "Enable Logging mode %s", optarg);
                break;

            case 'p':
                dns_port_set((in_port_t) strtol(optarg, NULL, 10));
                INFO_LOG(context, "Port to use %s", optarg);
                break;

            case 'r': {
                char *resolvers_file = malloc_string(strlen(optarg));
                strncpy(resolvers_file, optarg, strlen(optarg));
                dns_resolvers_file_set(resolvers_file);

                INFO_LOG(context, "Resolvers file %s", optarg);
            }
                break;

            case 't':
                dns_socket_timeout_set((uint32_t) atol(optarg)); // NOLINT
                INFO_LOG(context, "Network timeout %ss", optarg);
                break;

            case 'v':
                dns_cache_polling_interval_set((uint32_t) atol(optarg)); // NOLINT
                INFO_LOG(context, "DNS cache polling interval %ss", optarg);
                break;

            case 'e':
                dns_cache_size_set((uint32_t) atol(optarg)); // NOLINT
                INFO_LOG(context, "Max cache entries %s", optarg);
                break;

            case 'E': {
                char *etcd = malloc_string(strlen(optarg));
                strncpy(etcd, optarg, strlen(optarg));
                dns_etcd_set(etcd);

                INFO_LOG(context, "Etcd server %s", optarg);
            }
                break;

            case 'H':
                dns_http_port_set((uint16_t) atol(optarg)); // NOLINT
                dns_http_mode_set(dns_http_port_get() != 0);
                INFO_LOG(context, "Enable debug mode at port", optarg);
                break;

            case 'b':
                dns_bypass_mode_set(strcmp(optarg, "true") == 0);
                INFO_LOG(context, "Bypass cache, useful for debugging %s", optarg);
                break;

            case 'o':
                dns_optimize_mode_set(strcmp(optarg, "true") == 0);
                INFO_LOG(context, "Optimize socket %s", optarg);
                break;

            case 'm':
                dns_max_ttl_set((uint32_t) strtol(optarg, NULL, 10));
                INFO_LOG(context, "DNS Max TTL %s", optarg);
                break;

            case 'D':
                dns_run_as_daemon_set(strcmp(optarg, "true") == 0);
                INFO_LOG(context, "Run as a daemon %s", optarg);
                break;

            case 'h': {
                char *host_name = malloc_string(strlen(optarg));
                strncpy(host_name, optarg, strlen(optarg));
                dns_host_name_set(host_name);

                INFO_LOG(context, "Host Name %s", optarg);
            }
                break;
            case 'i': {
                char *host_ip = malloc_string(strlen(optarg));
                strncpy(host_ip, optarg, strlen(optarg));
                dns_host_ip_set(host_ip);

                INFO_LOG(context, "Host IP Address %s", optarg);
            }
                break;
            case '?':
            default:
                usage("dns_active_cache");
                return false;
        }
    } while (c != -1);


    if (dns_http_port_get() == dns_port_get()) {
        ERROR_LOG(context, "Debug Port %hu must be different from DNS port %hu", dns_http_port_get(), dns_port_get());
        return false;
    }

    return true;
}

void fork_process(transaction_context *context) {
    if (dns_run_as_daemon_get()) {

        INFO_LOG(context, "Starting as Daemon");

        // Create child process
        //
        pid_t process_id = fork();

        // Indication of fork() failure
        //
        if (process_id < 0) {
            ERROR_LOG(context, "Forking the process failed.");
            // Return failure in exit status
            exit(1);
        }

        // PARENT PROCESS. Need to kill it.
        //
        if (process_id > 0) {
            INFO_LOG(context, "Process ID of child process %d \n", process_id);

            // return success in exit status
            //
            exit(0);
        }

        // We need to reload the context... we are in the forked process.
        //
        *context = context_create();

        // Unmask the file mode
        //
        umask(0);

        //set new session
        //
        pid_t sid = setsid();
        if (sid < 0) {
            // Return failure
            exit(1);
        }

        // Daemon Process ID
        //
        dns_daemon_process_id_set(sid);

        // Change the current working directory to root.
        //
        chdir("/");

        // Close stdin. stdout and stderr
        //
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // Setup base service
        //
        dns_process_setup();
    } else {
        INFO_LOG(context, "Not starting as Daemon");
    }
}

int main(int argc, char *argv[]) {
    // Context for the transaction
    //
    transaction_context context = context_create();

    // Setup base service
    //
    dns_resolvers_file_set("/etc/resolv.dns_cache");

    int return_value = -1;

    // Parse the command line arguments.
    //
    if (parse_arguments(&context, argc, argv)) {

        // OK fork the process, DO NOT do too much before this call.
        // or else things could get weird.
        //
        fork_process(&context);

        // Create the log files...
        //
        create_logs(&context);

        // Get the list of resolvers
        //
        size_t count = 0;
        dns_resolvers_set(resolvers_parse(dns_resolvers_file_get(), &count));
        dns_resolvers_count_set(count);

        if (dns_resolvers_get() != NULL) {
            // Setup the cache
            //
            if (dns_cache_init(&context) == 0) {
                // Log the version
                //
                INFO_LOG(&context, "Staring DNS Active Service version: %s", dns_active_cache_version_get());

                // Start Etcd Service
                //
                dns_service_etcd(&context);

                // Start Processing Messages
                //
                return_value = dns_service_start(&context);
            } else {
                ERROR_LOG(&context, "Failed to start the service, unable to setup the service.");
            }
        } else {
            ERROR_LOG(&context, "Unable to find resolvers config file %s, please see --resolvers= options",
                      dns_resolvers_file_get());
        }
    } else {
        ERROR_LOG(&context, "Failed paring command line arguments");
    }

    close_logs(&context);

    return return_value;
}