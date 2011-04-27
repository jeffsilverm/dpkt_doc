#!/usr/bin/env python
# This program listens to an ethernet, filters on ARP packets, and builds a table of physical (Ethernet) addresses <=> IPv4 addresses

import dpkt
import sys
import socket
import pcap
import subprocess
# import dnet     # used to translate Ethernet addresses from packed 48 bit number to human readable format
import binascii

hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
if hostname == 'jeffs-laptop\n' :
    pc = pcap.pcap('wlan0')       # set up for packet capture
else:
    pc = pcap.pcap('eth0')
pc.setfilter('arp')         # Use a kernel filter and just pass arp traffic

for ts, pkt in pc:
    # parse the packet.  Because the filter allows only ARP packets through, we don't have to decode the ethertype
    eth = dpkt.ethernet.Ethernet(pkt)
    arp = eth.arp
    print arp
    print arp.hrd
    print arp.pro
    if arp.op==1 :
        print "request"
    elif arp.op==2 :
	print "reply"
    else :
	print "op has an unexpected value %d", arp.op
    print "Target protocol address", socket.inet_ntoa(arp.tpa)	#IPv4 address
    print "target hardware address", binascii.hexlify(arp.tha)



    




