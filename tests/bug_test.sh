#!/usr/bin/env bash

COUNTER=1024
until [ ${COUNTER} -lt 0 ]; do
    dig @localhost -p 5300 henry.ladros.com
    dig @localhost -p 5300 anne.ladros.com
   let COUNTER-=1
done