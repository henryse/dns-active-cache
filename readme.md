DNS Active Cache
====

## NOTE
Currently working on adding etcd support.  Old Caching functionality still works.  If you enable ETCD support
A and SRV Records are currently supported.

An invaluable guide in learning about DNS communications can be found at [zytrax](http://www.zytrax.com/books/dns/).
I could not have done this project without it.

### Work Items
    
    1. Check question type in cache if it does not match, forward request again
    2. Document how to use with Registerator and make Dockerfile example

## Introduction

This is a simple active local [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) caching service, 
it **NOT** intended to be used as a desktop [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) cache.
  
The purpose of this service is meant to address any of the following:

* The issue we are trying to address has to do with [AWS Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/)
for services that are sensitive to DNS lookup times.   Specifically this is aimed at using [NGINX](https://www.nginx.com) as reverse proxy.

Because ELBs are rebalanced using IP Addresses, services under heavy load can get backed up waiting for a timed out
DNS entry to be refreshed.  This can be especially effective for DNS style load 
balancing which requires services to constantly query upstream DNS servers to discover what IP address they need
to send requests to.  We were able to reduce our DNS requests to sub millisecond response times by having a local smart cache.

* MicroServices that can be isolated from the DNS but still needing local DNS lookups.
 
Most servers only talk to a couple of upstream servers, so this service will allow you to configure how 
many **cache entries** you need(see **Configuration** below).

This simple service will do the following:

 1. When a DNS *question* request comes into DNS Active Cache the first time, it will try to call the DSN servers defined in *resolv.dns_cache*.

 2. If a valid DNS entry is found, it will then store that entry into the local cache, see **entries** parameter below.

 3. A separate thread, there after, will keep refreshing the local DNS cache entries based on it's time to live(TTL).

Thus after the first *question*, all future requests/responses will be cached locally.

An entry will be expired from the local cache based on the DNS Records TTL.

## Version 2.0 Process Flow

The product now supports ETCD as a service discovery backend.  It will also cache upstream DNS entries described above.

The DNS Active Cache's general algorithm is as follows:

        if etcd_enabled then
            if find_etcd_entry(question) then
                return result
            end
        end

        if !cache_bypass then
            if find_dns_cache(question) then
                return result
            end
        end

        if call_upstream_resolver(question) then
            if !cache_bypass then
                add_answer_to_cache(result)
            end

            return result
        end

        return dns_entry_not_found();

This service expects the entries in ETCD to have to following layout:

	<prefix>/<service-name>/<service-id>/<host_ip> = <ip>   - Hosts IP Address
	<prefix>/<service-name>/<service-id>/<host_port> = <host_port> - host port
	<prefix>/<service-name>/<service-id>/<exposed_port> = <exposed_port> - Docker Exposed Port
	<prefix>/<service-name>/<service-id>/<exposed_ip> = <exposed_ip> - Docker Exposed IP
	<prefix>/<service-name>/<service-id>/<tags> = <tags> - Directory of Tags, see above.
	<prefix>/<service-name>/<service-id>/<attrs> = <attrs> - Directory of Attributes
	<prefix>/<service-name>/<service-id>/<address> = <ip>:<port>
	<prefix>/<service-name>/<service-id>/<port_type> = <port_type> - tcp, udp etc...

We have a special version of [registrator](https://www.github.com/henryse/registrator) that supports this format.

## How to Build and Install

Create a pull request for this project.

Install **cmake** to build this project:
        
Mac OSX:
        
        brew install cmake
         
Make sure you have the following(example for Cent OS):

        yum -y install iconv-devel \
            libuuid-devel \
            bind-utils

or

        apt-get install \
            libghc-iconv-dev \
            uuid-dev 

[YAML Parser](https://lloyd.github.io/yajl/):
    
    git clone git://github.com/lloyd/yajl
    
    ./configure && make install

Use **cmake** to build the project:

        cmake .
        make
        make install

If you do not have **cmake** here how to install it(example for Cent OS):

        yum groupinstall 'Development Tools’
        cd \(your favorite place to build stuff)
        wget http://www.cmake.org/files/v3.3/cmake-3.3.1.tar.gz
        tar xzvf cmake-3.3.1.tar.gz
        cd cmake-3.3.1
        ./configure --prefix=/usr/local/cmake
        make
        make install
        cd ..
        rm -rf cmake-3.3.1
        rm -rf cmake-3.3.1.tar.gz

Configuration Settings
====

The following command line parameters are supported:

         port           port to listen on, the default is 53.
         resolvers      resolvers file containing a list of nameservers, default is /etc/resolv.dns_cache
         timeout        Network time out in seconds, the default is 5s
         interval       How often should the service scan the cache to find timed out entries. Default: 5s     
         entries        Max cache entries, default is 64
         http           Set the port to listen on for exposing an HTTP status endpoint, defualt is 0 == disabled.
         maxttl         Set the max ttl for all A Records. 
         
         etcd           ETCD path, for example: --etcd=http://192.168.1.129:2379, if this is not set then ETCD support is not used.
         host_ip        Only used if etcd is enabled. Used for DSN IP resolution when ETCD is enabled.
         host_name      Only used if etcd is enabled. Used for host name when resolving ETCD based addresses.
               
         help           Get this help message
  
### --port
Port to listen on, default is 53.

### --resolvers
See **Resolvers Config** section below.  The default location is: /etc/resolv.dns_cache

## --timeout
This is the "network" time out for how long it should wait for a response from an upstream name server.  Default is 5 seconds

### --interval
How often should the service scan the cache to find timed out entries.  Once this time expires, the **cache refresh thread** will go out and refresh the cache looking for expired entries. Default is 5 seconds.

### --entries
How many DNS entries you will have, this should be large enough such that it can hold number of upstream servers + 2.  Default is 64

### --http
Port to listen on to enable HTTP diagnostic endpoint, this is an HTTP/JSON page that tells you the current status of the DNS entries in the cache.

### --help
Display the help options as well as what the defaults are for the setting above.

### --maxttl
Allows you to specify the maximum TTL in seconds for all A records, this overrides the DNS's TTL for a given entry.

#### status 

    http://[server name]:http_port/status

Will return an JSON document showing the current cached items, their state, timeout and order of precedence.
* You should never see duplicate names, you might get luck to catch the rare case, but when you refresh the page the
duplicate should vanish
* DNS Active Cache scans from the top item down when looking for matches.

#### buildinfo

    http://[server name]:http_port/buildinfo

Will return a JSON document describing the current version of DNS Active Cache, for example:

    {"version":"dns-active-cache-v1.0.15"}

#### health

    http://[server name]:http_port/health

Will return a JSON document describing if the service is healthy by performing a couple of tasks, these include:
* Are the relevant background threads still running
* Are the entries TTL in the cache is less then what maxTTL is set to.

For example, if the service is health you will see:
    
    {"status":"UP"}

For example, if the service is in a bad state you will see:

    {"status":"DOWN"}

## Resolvers Config
This file contains the list of name servers to scan for DNS entries:

        # sample file.
        nameserver 192.168.50.1

You can have as many as you like, the program will scan them in order from first to last.

## Outstanding Issues

( ) Automated test script to validate service.

( ) Might be nice to have the ability to set a lower bound on TTLs

## Common Development Settings

Running dns_active_cache you can use the following parameters when exposing http status port:

        --http=8080
        --port=5300
        --resolvers=/Users/[your user dir]/dns_cache/conf/resolv.dns_cache


ETCD common development settings:

        --port=5300
        --http=8080
        --resolvers=resolv.dns_cache
        --etcd=http://192.168.1.129:2379
        --host_name=applegate.farm
        --host_ip=192.168.1.129

Note: the ip addresses above are your "local" ip addresses.

You can test the above with something like:

        dig @localhost -p 5300 www.vatican.va

For XCode builds you can do the following:

        cmake . -DCMAKE_BUILD_TYPE=Debug -G Xcode 

## Error Messages

The following is a list of errors that can be returned from the service and what the action should be.  For any error that requires you to log a bug please enter the entire log entry in the ticket.

    Error: "Fatal Error, the cache is empty and dns_cache_record_remove is trying to remove a record that does not exist, please report this as a bug."
    Action: This is a bug in the service, restart the service and log a bug.
    Behavior: Degraded performance.

    Error: "Cache table is full, currently size is %d, please use --entries= to enlarge it."
    Action: Restart DNS Active Cache with a larger value for --entries= on the command line.  The default value is 16 if no entries specified.
    Behavior: Degraded performance.

    Error: "Sorry we need at least 16 cache entries, you have select %d, please use --entries= to enlarge it."
    Action: Restart DNS Active Cache with a larger value for --entries= on the command line.  The default value is 16 if no entries specified.
    Behavior: Degraded performance.

    Error: "We need someone to call, no resolvers file found.  See --resolvers= to select a file."
    Action: Ensure that the default resolvers file found in /etc/resolv.dns_cache or the specified by the command line option --resolvers= has entries specified.
    Behavior: FATAL, service failed to start

    Error: "Ouch! We ran out of memory!  This is either an issue with the machine or a bug in the service"
    Action: Restart the service and log a bug if it is DNS Active Cache that has sucked up all of the memory.  If your system has run out of memory then you have bigger problems.
    Behavior: FATAL, service has exited.

    Error: "Failed to allocate logging string, out of memory? This is either a bug or an issue with the server."
    Action: Restart the service and log a bug if it is DNS Active Cache that has sucked up all of the memory.  If your system has run out of memory then you have bigger problems.
    Behavior: FATAL, service has exited.

    Error: "Unable to create socket, this is either a network issue where the port is in use or a bug in the service."
    Error: "Unable to create socket, this is either a network issue where the port %h is already in use or a bug in the service."
    Action: The service was never started, please verify that the port is not already in use.
    Behavior: FATAL, service has exited.

    Error: "Setsockopt(SO_REUSEADDR) failed, this is either a network issue or a bug in the service."
    Action: Not a fatal issue, but a bug should be logged with the version of OS you are using.
    Behavior: Degraded performance.

    Error: "Bind failed on socket %d, this is either a network issue or a bug in the service"
    Action: The service was never started, please verify that the port is not already in use or the network is properly configured.
    Behavior: FATAL, service has exited.
    
    Error: "sendto() failed, this is either a networking issue or a bug in the service."
    Action: The service was never started, please verify that the port is not already in use or the network is properly configured.
    Behavior: Degraded performance, the calling service will continue to succeed but the DNS upstream server is not available.
    
    Error: "Out of memory, can't allocate string!  This is either an issue with the server or a bug."
    Action: Restart the service and log a bug if it is DNS Active Cache that has sucked up all of the memory.  If your system has run out of memory then you have bigger problems.
    Behavior: FATAL, service has exited.
    
    Error: "Out of memory, can't allocate string!  This is either an issue with the server or a bug."
    Action: Restart the service and log a bug if it is DNS Active Cache that has sucked up all of the memory.  If your system has run out of memory then you have bigger problems.
    Behavior: FATAL, service has exited.
    
    Error: "setsockopt SO_RCVTIMEO failed, this is either a networking issue or a bug in the service."
    Action: Not a fatal issue, but a bug should be logged with the version of OS you are using.
    Behavior: FATAL, service has exited.
    
    Error: "setsockopt SO_SNDTIMEO failed, this is either a networking issue or a bug in the service."
    Action: Not a fatal issue, but a bug should be logged with the version of OS you are using.
    Behavior: FATAL, service has exited.
    
    Error: "setsockopt SO_REUSEADDR failed, this is either a networking issue or a bug in the service."
    Action: Not a fatal issue, but a bug should be logged with the version of OS you are using.
    Behavior: FATAL, service has exited.