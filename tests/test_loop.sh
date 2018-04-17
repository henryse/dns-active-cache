#!/usr/bin/env bash
COUNTER=1024
until [ ${COUNTER} -lt 0 ]; do
    dig any @localhost -p 5300 www.bing.com
    dig any @localhost -p 5300 www.hotwire.com
    dig any @localhost -p 5300 www.expedia.com
    dig any @localhost -p 5300 www.wotif.com
    dig any @localhost -p 5300 www.travelocity.com
    dig any @localhost -p 5300 www.microsoft.com
    dig any @localhost -p 5300 www.vatican.va
    dig any @localhost -p 5300 www.google.com
    dig any @localhost -p 5300 www.orbitz.com
    dig any @localhost -p 5300 www.booking.com
    dig any @localhost -p 5300 www.priceline.com
    dig any @localhost -p 5300 www.apple.com
    dig any @localhost -p 5300 www.appleinsider.com
    dig any @localhost -p 5300 www.zerohedge.com
    dig any @localhost -p 5300 www.peakprosperity.com
    dig any @localhost -p 5300 www.ft.com
    dig any @localhost -p 5300 www.pugetsoundbees.org
    dig any @localhost -p 5300 www.latimes.com
    dig any @localhost -p 5300 www.united.com
    dig any @localhost -p 5300 winefolly.com
    dig any @localhost -p 5300 news.bbc.co.uk
    dig any @localhost -p 5300 www.visa.com
    dig any @localhost -p 5300 www.mastercard.com


#    dig www.bing.com
#    dig www.hotwire.com
#    dig www.expedia.com
#    dig www.wotif.com
#    dig www.travelocity.com
#    dig www.microsoft.com
#    dig www.vatican.va
#    dig www.google.com
#    dig www.orbitz.com
#    dig www.booking.com
#    dig www.priceline.com
#    dig www.apple.com
#    dig www.appleinsider.com
#    dig www.zerohedge.com
#    dig www.peakprosperity.com
#    dig www.ft.com
#    dig www.pugetsoundbees.org
#    dig www.latimes.com
#    dig www.united.com
#    dig winefolly.com
#    dig news.bbc.co.uk
#    dig www.visa.com
#    dig www.mastercard.com

#    dig any @::1 -p 5300 www.hotwire.com
#    dig any @::1 -p 5300 www.expedia.com
#    dig any @::1 -p 5300 www.wotif.com
#    dig any @::1 -p 5300 www.travelocity.com
#    dig any @::1 -p 5300 www.microsoft.com
#    dig any @::1 -p 5300 www.vatican.va
#    dig any @::1 -p 5300 www.google.com
#    dig any @::1 -p 5300 www.orbitz.com
#    dig any @::1 -p 5300 www.booking.com
#    dig any @::1 -p 5300 www.priceline.com
#    dig any @::1 -p 5300 www.apple.com
#    dig any @::1 -p 5300 www.appleinsider.com
#    dig any @::1 -p 5300 www.zerohedge.com
#    dig any @::1 -p 5300 www.peakprosperity.com
#    dig any @::1 -p 5300 www.ft.com
#    dig any @::1 -p 5300 www.pugetsoundbees.org
#    dig any @::1 -p 5300 www.latimes.com
#    dig any @::1 -p 5300 www.united.com
#    dig any @::1 -p 5300 winefolly.com
#    dig any @::1 -p 5300 news.bbc.co.uk
#    dig @localhost -p 5300 "_http._tcp.applegate.farm" SRV
#   dig @localhost -p 5300 "etcd.applegate.farm"
    let COUNTER-=1
done