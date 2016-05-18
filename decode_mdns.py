#! /usr/bin/python
#https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_dns.py
#
# This program decodes DNS packets from the wire or from a capture file
# A simple MDNS decoder is in https://gist.github.com/m-mizutani/1188242
# -*- coding: utf-8 -*-

import dpkt, dpkt.dns
import sys
import socket
import pcap
import subprocess
import datetime

type_table={}       # This is a lookup table for DNS query types

def initialize_tables() :
    global type_table


# From http://www.networksorcery.com/enp/protocol/dns.htm    
    type_table = {1:"A",        # IP v4 address, RFC 1035
                  2:"NS",       # Authoritative name server, RFC 1035
                  5:"CNAME",    # Canonical name for an alias, RFC 1035
                  6:"SOA",      # Marks the start of a zone of authority, RFC 1035
                 12:"PTR",      # Domain name pointer, RFC 1035
                 13:"HINFO",    # Host information, RFC 1035
                 15:"MX",       # Mail exchange, RFC 1035
                 16:"TXT",      # 
                 28:"AAAA",     # IP v6 address, RFC 3596
                  33:"SRV",     # RFC 2782
                 255:"ANY",     # all cached records, RFC 1035
                 }
                
def hexify(x):
    "The strings from DNS resolver contain non-ASCII characters - I don't know why.  This function investigates that"
    toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)

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
            

def decode_dns_response ( rr, response_type ) :
    """This subroutine decodes a DNS response packet.  The packet may have more than one rr"""
    r_type = rr.type
    r_data = rr.rdata
    if rr.cls >32768:
        print 'Cache-Flush:1',
        rr.cls -= 32768 #MSB of rclass repurposed in mdns
    if rr.cls != 1 :
        print "Response class is %d, not class IN, might be Hesiod, chaos, or qclass (all of which are anachronisms)"%rr.cls
    print "Response Type:", response_type ,r_type,type_table[r_type],
    if r_type == dpkt.dns.DNS_CNAME :
        print "CNAME ", r_data," in hex: ",  hexify(r_data)
    elif r_type == dpkt.dns.DNS_A  : #for mdns response print host name too
        print "IPv4 address", socket.inet_ntoa( r_data ),' for ',rr.name
    elif r_type == dpkt.dns.DNS_NS :
       #print "Response is a NS name", r_data," in hex: ",  hexify(r_data) 
        print "Response is a NS name", rr.nsname
    elif r_type == dpkt.dns.DNS_AAAA :
        print "IPv6 address", socket.inet_ntop( socket.AF_INET6, r_data ),' for ',rr.name
    elif r_type == dpkt.dns.DNS_PTR :
       #
        print 'Name ',rr.ptrname,"for IPv4 address", rr.name
    elif r_type == dpkt.dns.DNS_SOA :
        print rr.mname,rr.rname,rr.serial,rr.refresh,rr.retry,rr.expire, rr.minimum 
    elif r_type == dpkt.dns.DNS_MX :
        print rr.mxname,rr.preference
    elif r_type == dpkt.dns.DNS_HINFO :
        print rr.text
    elif r_type == dpkt.dns.DNS_TXT :
        print "TEXT",rr.text
    elif r_type == dpkt.dns.DNS_SRV :
        print rr.srvname,rr.port,rr.priority,rr.weight
    else :
        print "Response type is something other than a CNAME, PTR, IPv4 address, or IPv6 address", r_type,
        if r_type in type_table :
            print type_table[r_type]
            print "r-data is ",'%r'% r_data," in hex: ",  hexify(r_data)
        else :
            print "Unknown"

def print_hdr(dns):
   print 'HDR: id=%5d op=%5d Q/R=%1d AA:%1d TC:%1d RD:%1d RA:%1d opcode=%2d rcode=%2d QC=%2d AC=%2d NC=%2d AR%2d'%\
    (dns.id,dns.op,dns.qr,(dns.op & dpkt.dns.DNS_AA)>>10,(dns.op & dpkt.dns.DNS_TC)>>9,(dns.op & dpkt.dns.DNS_RD)>>8,(dns.op & dpkt.dns.DNS_RA)>>7,dns.opcode,dns.rcode,len(dns.qd),len(dns.an),len(dns.ns),len(dns.ar))


def main() :
    # This code allows this program to run equally well on my laptop and my desktop.  I did it this
    # way to demonstrate different interface names.  If I was really clever, I'd figure out how to do  this
    # under MS-Windows
    if sys.argv[1] == "-i" :
        pc = pcap.pcap( sys.argv[2] )
    elif sys.argv[1] == "-f" :
        pc = dpkt.pcap.Reader( open ( sys.argv[2] ) )
    else :
        print """Use -i INTERFACE to [packet capture from an interface.
Use -f FILENAME to read a packet capture file"""
        sys.exit(2)
    initialize_tables()
    mdns_ip=socket.inet_aton('224.0.0.251');
    
    for (src, sport, dst, dport, data ) in udp_iterator(pc) :
# Uncomment if you want to see all UDP packets
       #print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport
        if src != mdns_ip and dst != mdns_ip and dport != 5353 and sport != 5353:continue
        assert dport == 5353 or sport == 5353
        dns = dpkt.dns.DNS(data)
        print '\n',datetime.datetime.now(),  socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport
        print_hdr(dns)
       #print dns.__repr__()
       #print '%r' % data
        if dns.qr == 0:
           #print "from ", socket.inet_ntoa(src),":",sport, " to ", socket.inet_ntoa(dst),":",dport,type(data),len(data),'%r' % data
            # UDP/53 is a DNS query
            if dns.opcode != dpkt.dns.DNS_QUERY :
                print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode,'dns.id is',dns.id
            if dns.qr != dpkt.dns.DNS_Q :
                print "A DNS packet was sent to the name server, but dns.qr is not 0 and should be.  It is %d" % dns.qr
            if (len(dns.qd)>0):
              for i in range(len(dns.qd)):
                print "query for ", dns.qd[i].name, "query type is ", dns.qd[i].type, type_table[dns.qd[i].type]
            else:
             print "query for ", '????'
        if dns.qr == 1 or len(dns.an)>0:
            # UDP/53 is a DNS response
            if dns.qr != dpkt.dns.DNS_R : #this is not an error, a query packet may contain answers
                print "A DNS packet was received from a name server, but dns.qr is not 1 and should be.  It is %d" % dns.qr
            if dns.rcode == dpkt.dns.DNS_RCODE_NOERR :
                pass#print "no error",
            elif dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN :
                print "There is no name in this domain"
            else :
                print "Response is something other than NOERR or NXDOMAIN %d - this software is incomplete" % dns.get_rcode()
# Decode the RR records in the NS section
            for rr in dns.ns :
                decode_dns_response ( rr, "NS")
# Decode the answers in the DNS answer
            i=0
            for rr in dns.an :
               #print 'RR[%d]:%r'%(i,rr);i +=1
                decode_dns_response ( rr, "AN" )
# Decode the additional responses
            for rr in dns.ar :
                decode_dns_response ( rr, "AR" )                


if __name__ == "__main__" :
    main()
    
