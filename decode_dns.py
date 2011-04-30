#! /usr/bin/python
#
# This program decodes DNS packets from the wire

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess



def udp_iterator(pc):
    """pc is a pcap.pcap object that listens to the network and returns a packet object when it hears a packet go by"""
    for ts, pkt in pc:
        # parse the packet.  Decode the ethertype.  If it is IP (IPv4) then process it further
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP :
            ip = eth.data
            # If the IP protocol is UDP, then process it further
            if ip.p == dpkt.ip.IP_PROTO_UDP :
                udp = ip.data
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data)
            

def decode_dns_response ( answer ) :
    """This subroutine decodes a DNS response packet.  The packet may have more than one answer"""
    r_type = answer.type
    r_data = answer.rdata
    if r_type == dpkt.dns.DNS_CNAME :
        print "Response is a CNAME ", r_data
    elif r_type == dpkt.dns.DNS_A :
        print "response is an IPv4 address", socket.inet_ntoa( r_data )
    elif r_type == dpkt.dns.DNS_AAAA :
        print "response is an IPv6 address", socket.inet_ntop( socket.AF_INET6, r_data )
    elif r_type == dpkt.dns.DNS_PTR :
        print "response is a hostname from an IP address", r_data 
    else :
        print "Response type is something other than a CNAME, PTR, IPv4 address, or IPv6 address", r_type


def main() :
    # This code allows this program to run equally well on my laptop and my desktop.  I did it this
    # way to demonstrate different interface names.  If I was really clever, I'd figure out how to do  this
    # under MS-Windows
    hostname = subprocess.Popen("hostname", stdout=subprocess.PIPE).communicate()[0]
    if hostname == 'jeffs-laptop\n' :
        pc = pcap.pcap('wlan0', promisc=True)       # set up for packet capture
    else:
        pc = pcap.pcap('eth0', promisc=True)

    for (src, sport, dst, dport, data ) in udp_iterator(pc) :
# Uncomment if you want to see all UDP packets
#        print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport
        if dport == 53 :
            # UDP/53 is a DNS query
            dns = dpkt.dns.DNS(data)
            if dns.opcode != dpkt.dns.DNS_QUERY :
                print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode
            if dns.qr != dpkt.dns.DNS_Q :
                print "A DNS packet was sent to the name server, but dns.qr is not 0 and should be.  It is %d" % dns.qr
            print "query for ", dns.qd[0].name, "ID is ", dns.id, "dns.qr is ", dns.qr
        elif sport == 53 :
            # UDP/53 is a DNS response
            dns = dpkt.dns.DNS(data)
            print "responding to ", dns.id, "dns.qr is ", dns.qr
            if dns.qr != dpkt.dns.DNS_R :
                print "A DNS packet was received from a name server, but dns.qr is not 1 and should be.  It is %d" % dns.qr
            if dns.get_rcode() == dpkt.dns.DNS_RCODE_NOERR :
                print "Response has no error"
            elif dns.get_rcode() == dpkt.dns.DNS_RCODE_NXDOMAIN :
                print "There is no name in this domain"
            else :
                print "Response is something other than NOERR or NXDOMAIN %d - this software is incomplete" % dns.get_rcode()
            print "The response packet has %d answers" % len(dns.an)
            for answer in dns.an :
                decode_dns_response ( answer )
                


if __name__ == "__main__" :
    main()
    
