#!/usr/bin/env python
# This program listens to an ethernet, filters on ARP packets, and builds a table of physical (Ethernet) addresses <=> IPv4 addresses

import dpkt
import sys
import socket
import pcap
import subprocess
import binascii

def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon
separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r

hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
if hostname == 'jeffs-laptop\n' :
    pc = pcap.pcap('wlan0', promisc=True)       # set up for packet capture
else:
    pc = pcap.pcap('eth0', promisc=True)
pc.setfilter('arp')         # Use a kernel filter and just pass arp traffic

for ts, pkt in pc:
    # parse the packet.  Because the filter allows only ARP packets through, we don't have to decode the ethertype
    eth = dpkt.ethernet.Ethernet(pkt)
    arp = eth.arp
#    print arp.hrd
#    print arp.pro
    if arp.op==1 :
        print "request"
    elif arp.op==2 :
	print "reply"
    else :
	print "op has an unexpected value %d", arp.op
    print "source protocol address", socket.inet_ntoa(arp.spa)
    print "source hardware address", add_colons_to_mac( binascii.hexlify(arp.sha) )
    print "Target protocol address", socket.inet_ntoa(arp.tpa)	#IPv4 address
    print "target hardware address", add_colons_to_mac( binascii.hexlify(arp.tha) )



    




