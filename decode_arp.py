#!/usr/bin/env python
# This program listens to an ethernet, filters on ARP packets, and builds a table of physical (Ethernet) addresses <=> IPv4 addresses

import dpkt
import sys
import socket
import pcap
import subprocess

hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
if hostname == 'jeffs-laptop\n' :
    pc = pcap.pcap('wlan0')       # set up for packet capture
else:
    pc = pcap.pcap('eth0')
pc.setfilter('arp')         # Use a kernel filter and just pass arp traffic

for ts, pkt in pc:
    # parse the packet.  Because the filter allows only ARP packets through, we don't have to decode the ethertype
    eth = dpkt.ethernet.Ethernet(pkt)
    arp = dpkt.arp(eth.data)
    print arp

    




