#! /usr/bin/python
#
# This program decodes UDP packets from the wire

import dpkt
import sys
import socket
import pcap
import subprocess



def decode_udp ( pc ) :
    """decode_udp is a generator function that listens to a pcap.pcap object and returns a UDP object when it hears a packet"""
    for ts, pkt in pc:
        # parse the packet.  Decode the ethertype
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP :
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_UDP :
# This doesn't deal with IP fragments                
                udp = ip.data
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data)

            
def main() :
# This code allows this program to run equally well on my laptop and my desktop.  I did it this
# way to demonstrate different interface names.  If I was really clever, I'd figure out how to do  this
# under MS-Windows 
#    hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
#    if hostname == 'jeffs-laptop\n' :
#        pc = pcap.pcap('wlan0', promisc=True)       # set up for packet capture
#    else:
#        pc = pcap.pcap('eth0', promisc=True)
    if sys.argv[1] == "-i" :
        pc = pcap.pcap( sys.argv[2] )
    elif sys.argv[1] == "-f" :
        pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    else :
        print """Use -i INTERFACE to [packet capture from an interface.
Use -f FILENAME to read a packet capture file"""
        sys.exit(2)

    for src, sport, dst, dport, data in decode_udp( pc ) :
        print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport


if __name__ == "__main__" :
    main()

