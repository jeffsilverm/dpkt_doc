#!/usr/bin/env python
# This program listens to an ethernet, filters on ARP packets, and builds a table of physical (Ethernet) addresses <=> IPv4 addresses

import dpkt
import sys
import socket
import pcap
import subprocess
import binascii
import time

def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon
separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r


def main() :
    # This code allows this program to run equally well on my laptop and my desktop.  I did it this
    # way to demonstrate different interface names.  If I was really clever, I'd figure out how to this
    # under MS-Windows
    if sys.argv[1] == "-i" :
        pc = pcap.pcap( sys.argv[2] )
    elif sys.argv[1] == "-f" :
        pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    else :
        print """Use -i INTERFACE to [packet capture from an interface.
Use -f FILENAME to read a packet capture file"""
        sys.exit(2)

    pc.setfilter('arp')         # Use a kernel filter and just pass arp traffic
    start_time = time.time()    # Return the time as a floating point number expressed in seconds since the epoch
    arp_cache = dict()

    # a pcap.pcap object listens to the network and returns a packet object when it hears a packet.
    for ts, pkt in pc:
        # parse the packet.  Because the filter allows only ARP packets through, we don't have to decode the ethertype
        eth = dpkt.ethernet.Ethernet(pkt)
        arp = eth.arp
        print "From: ",add_colons_to_mac( binascii.hexlify(eth.src)),
        print " to: ", add_colons_to_mac( binascii.hexlify(eth.dst))	# Ethernet destination addresses may be broadcast addresses
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
        arp_cache[arp.spa] = arp.sha
        if arp.op==2 :          # reply
            if arp.tpa in arp_cache :
                if arp_cache[arp.tpa] != arp.tha :
                    print "Duplicate IP addresses detected: ", socket.inet_ntoa(arp.tpa), "is assigned to both ",
                    add_colons_to_mac( binascii.hexlify(arp.tha) ), " and ", add_colons_to_mac( binascii.hexlify(arp_cache[arp.tha] ) )
            arp_cache[arp.tpa] = arp.tha
    # The arp cache has to be refreshed every 30 seconds, so this will catch every machine on the ethernet at least twice.  However, you might want to
    # continuously monitor your network to catch machines surreptitiously.
        elapsed_time = time.time() - start_time
        if elapsed_time > 60.0 :
            break

    for ip in arp_cache.keys() :
        print socket.inet_ntoa(ip),": ", add_colons_to_mac( binascii.hexlify(arp_cache[ip]))

    
if __name__ == "__main__" :
    main()
    



    




