#!/usr/bin/env python

import dpkt
import sys

f = open(sys.argv[1])
pcap = dpkt.pcap.Reader(f)
print "counter\tsrc prt\tdst prt\tflags"
packet_cntr = 0

for ts, buf in pcap:
    packet_cntr += 1
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    fin_flag = ( tcp.flags & 0x01 ) != 0
    syn_flag = ( tcp.flags & 0x02 ) != 0
    rst_flag = ( tcp.flags & 0x04 ) != 0
    psh_flag = ( tcp.flags & 0x08 ) != 0
    ack_flag = ( tcp.flags & 0x10 ) != 0
    urg_flag = ( tcp.flags & 0x20 ) != 0
    ece_flag = ( tcp.flags & 0x40 ) != 0
    cwr_flag = ( tcp.flags & 0x80 ) != 0
    flags = (
            ( "C" if cwr_flag else " " ) +
            ( "E" if ece_flag else " " ) +
            ( "U" if urg_flag else " " ) +
            ( "A" if ack_flag else " " ) +
            ( "P" if psh_flag else " " ) +
            ( "R" if rst_flag else " " ) +
            ( "S" if syn_flag else " " ) +
            ( "F" if fin_flag else " " ) )
            
    print packet_cntr, "\t", tcp.sport, "\t", tcp.dport, "\t", flags
    
 
f.close()
