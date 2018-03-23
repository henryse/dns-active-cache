#!/usr/bin/env bash

COUNTER=1024
until [ ${COUNTER} -lt 0 ]; do
    dig @localhost -p 5300 "etcd.applegate.farm"
   let COUNTER-=1
done