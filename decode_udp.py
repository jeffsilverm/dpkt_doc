#! /usr/bin/python
#
# This program decodes DNS packets from the wire

import dpkt
import sys
import socket
import pcap
import subprocess


# This code allows this program to run equally well on my laptop and my desktop.  I did it this
# way to demonstrate different interface names.  If I was really clever, I'd figure out how to do  this
# under MS-Windows
hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
if hostname == 'jeffs-laptop\n' :
    pc = pcap.pcap('wlan0', promisc=True)       # set up for packet capture
else:
    pc = pcap.pcap('eth0', promisc=True)

# a pcap.pcap object listens to the network and returns a packet object when it hears a packet
for ts, pkt in pc:
    # parse the packet.  Decode the ethertype
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP :
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_UDP :
            udp = ip.data
            print "from ", socket.inet_ntoa(ip.src),":",udp.sport, " to ", socket.inet_ntoa(ip.dst),":",udp.dport

            
