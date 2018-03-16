#!/usr/bin/env bash
COUNTER=1024
until [ ${COUNTER} -lt 0 ]; do
    dig @localhost -p 5300 www.bing.com
    dig @localhost -p 5300 www.hotwire.com
    dig @localhost -p 5300 www.expedia.com
    dig @localhost -p 5300 www.wotif.com
    dig @localhost -p 5300 www.travelocity.com
    dig @localhost -p 5300 www.microsoft.com
    dig @localhost -p 5300 www.vatican.va
    dig @localhost -p 5300 www.google.com
    dig @localhost -p 5300 www.orbitz.com
    dig @localhost -p 5300 www.booking.com
    dig @localhost -p 5300 www.priceline.com
    dig @localhost -p 5300 www.apple.com
    dig @localhost -p 5300 www.appleinsider.com
    dig @localhost -p 5300 www.zerohedge.com
    dig @localhost -p 5300 www.peakprosperity.com
    dig @localhost -p 5300 www.ft.com
    dig @localhost -p 5300 www.pugetsoundbees.org
    dig @localhost -p 5300 www.latimes.com
    dig @localhost -p 5300 www.united.com
    dig @localhost -p 5300 winefolly.com
    dig @localhost -p 5300 news.bbc.co.uk
    dig @localhost -p 5300 www.visa.com
    dig @localhost -p 5300 www.mastercard.com


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

#    dig @::1 -p 5300 www.hotwire.com
#    dig @::1 -p 5300 www.expedia.com
#    dig @::1 -p 5300 www.wotif.com
#    dig @::1 -p 5300 www.travelocity.com
#    dig @::1 -p 5300 www.microsoft.com
#    dig @::1 -p 5300 www.vatican.va
#    dig @::1 -p 5300 www.google.com
#    dig @::1 -p 5300 www.orbitz.com
#    dig @::1 -p 5300 www.booking.com
#    dig @::1 -p 5300 www.priceline.com
#    dig @::1 -p 5300 www.apple.com
#    dig @::1 -p 5300 www.appleinsider.com
#    dig @::1 -p 5300 www.zerohedge.com
#    dig @::1 -p 5300 www.peakprosperity.com
#    dig @::1 -p 5300 www.ft.com
#    dig @::1 -p 5300 www.pugetsoundbees.org
#    dig @::1 -p 5300 www.latimes.com
#    dig @::1 -p 5300 www.united.com
#    dig @::1 -p 5300 winefolly.com
#    dig @::1 -p 5300 news.bbc.co.uk
    let COUNTER-=1
done