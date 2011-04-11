#!/usr/bin/env python

import dpkt
import sys

f = open(sys.argv[1])
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    if tcp.dport == 80 and len(tcp.data) > 0:
        http = dpkt.http.Request(tcp.data)
        print "URI is ", http.uri
    if tcp.sport == 80 and len(tcp.data) > 0:
        try :
            http = dpkt.http.Response(tcp.data)
            print "HTTP version is ", http.version
            print "Status code is ", http.status
            print "Status reason ", http.reason
            print "date", http.headers['date']
            print "accept-ranges", http.headers['accept-ranges']
            print "content-type", http.headers['content-type']
            print "connection", http.headers['connection']
            print "server", http.headers['server']
        except dpkt.dpkt.UnpackError :
            print "Encounted an unpacking error"
f.close()
