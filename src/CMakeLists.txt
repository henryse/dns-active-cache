#**********************************************************************
#    Copyright (c) 2015 Henry Seurer
#
#    Permission is hereby granted, free of charge, to any person
#    obtaining a copy of this software and associated documentation
#    files (the "Software"), to deal in the Software without
#    restriction, including without limitation the rights to use,
#    copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the
#    Software is furnished to do so, subject to the following
#    conditions:
#
#    The above copyright notice and this permission notice shall be
#    included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#    OTHER DEALINGS IN THE SOFTWARE.
#
#**********************************************************************

cmake_minimum_required(VERSION 3.3)
project(dns_active_cache)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(ACTIVE_DNS_CACHE_VERSION "dns-active-cache-v1.0.3")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_C_FLAGS "-std=gnu99")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_C_FLAGS "-std=gnu99 -pthread -luuid -lrt")
endif ()

find_package(JAJL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

configure_file(version_config.h.in ${CMAKE_BINARY_DIR}/generated/version_config.h)
include_directories(${CMAKE_BINARY_DIR}/generated/ /usr/local/include/ ${CURL_INCLUDE_DIRS} ${YAJL_INCLUDE_DIRS}) # Make sure it can be included...

set(SOURCE_FILES
        main.c
        dns_service.c
        dns_service.h
        dns_utils.c
        dns_utils.h
        dns_packet.c
        dns_packet.h
        dns_cache.c
        dns_cache.h
        dns_settings.c
        dns_settings.h
        dns_string.c
        dns_string.h
        version_config.h
        dns_debug.c
        dns_debug.h
        dns_etcd.h
        dns_array.h
        dns_array.c
        dns_ectd.c
        dns_etcd_json_parser.h dns_service_etcd.c dns_service_etcd.h)

link_libraries(${CURL_LIBRARY} ${YAJL_LIBRARIES})

add_executable(dns_active_cache ${SOURCE_FILES})

install(TARGETS dns_active_cache DESTINATION bin)