#! /usr/bin/python
#
# This program decodes UDP packets from the wire

import dpkt
import sys
import socket
import pcap




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
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data, ip.v)
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6 :
            ip = eth.data
            if ip.nxt == dpkt.ip.IP_PROTO_UDP :
# This doesn't deal with IP fragments                
                udp = ip.data
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data, ip.v)
        else :
# If the packet is something else, then I need to figure out a better way of handling it.
            pass
            
def main() :
    if sys.argv[1] == "-i" :
        pc = pcap.pcap( sys.argv[2] )
    elif sys.argv[1] == "-f" :
        pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    else :
        print """Use -i INTERFACE to packet capture from an interface.
Use -f FILENAME to read a packet capture file"""
        sys.exit(2)

    for src, sport, dst, dport, data, ip_version in decode_udp( pc ) :
        if ip_version == 4 :
            print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport
        else :
            print "from ", socket.inet_ntop(AF_INET6, src),".",sport, " to ", socket.inet_ntop(AF_INET6, dst), ".", dport



if __name__ == "__main__" :
    main()

