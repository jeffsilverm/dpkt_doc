#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This program uses decode_tcp_iterator_2.py to get data for HTTP parsing.  That way,
# the input strings can be longer than what will fit into a single packet.


import dpkt
import sys
import decode_tcp_iterator_2P as d
import socket



def main(pc) :
    """This is the outer loop that prints strings that have been captured from the TCP streams, terminated by a packet that
has the PUSH flag set."""
    for cid, received_string, ip_version in d.decode_tcp(pc) :      # cid = connection_id
# This next line is for debugging only 
#        print d.connection_id_to_str (cid, ip_version), received_string 
        if cid[3] == 80 :         # cid[3] is the destination port
# This is a message going to the server, a request
            src_addr = socket.inet_ntoa(cid[0]) if ip_version == 4 else socket.inet_ntop(socket.AF_INET6, cid[0])
            print "HTTP request from ", src_addr
            http_req = dpkt.http.Request(received_string)
            print "URI is ", http_req.uri
            for header in http_req.headers.keys() :
                print header, http_req.headers[header]          
# ['_Request__methods', '_Request__proto', '__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__getitem__', '__hash__', '__hdr_defaults__', '__init__', '__len__', '__metaclass__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'body', 'data', 'headers', 'method', 'pack', 'pack_hdr', 'unpack', 'uri', 'version']
            print "method is ", http_req.method
# 'body', 'data', 'headers', 'method', 'pack', 'pack_hdr', 'unpack', 'uri', 'version'        
            print "HTTP headers, packed ", http_req.pack()
            print "HTTP version", http_req.version
#            print "HTTP data ", http_req.data       # I think this is valid if the method is POST

        elif cid[1] == 80 :       # cid[1] is the source port
            try :
                http = dpkt.http.Response(received_string)
                print "HTTP version is ", http.version
                print "Status code is ", http.status
                print "Status reason is ", http.reason
                for header in http.headers.keys() :
                    print header, " is ", http.headers[header]
#            print "date", http.headers['date']
#            print "accept-ranges", http.headers['accept-ranges']
#            print "content-type", http.headers['content-type']
#            print "connection", http.headers['connection']
#            print "server", http.headers['server']
            except dpkt.dpkt.UnpackError :
                print "Encounted an unpacking error"
        else :
            print "skipping ", d.connection_id_to_str( cid, ip_version )


if __name__ == "__main__" :
    if len(sys.argv) < 2 :
        decode_tcp_help()
# create an interator to return the next packet.  The source can be either an interface using the libpcap library or it can be a file in pcap
# format such as created by tcpdump.
    if sys.argv[1] == "eth0" :                  # wired ethernet interface
        pc = pcap.pcap("eth0", promisc=True )
    elif sys.argv[1] == "wlan0" :               # wireless interface
        pc = pcap.pcap("wlan0", promisc=True )
    elif sys.argv[1] == "sixxs" :               # IPv6 tunnel pseudo device
        pc = pcap.pcap("sixxs", promisc=True )
    else :
        pc = dpkt.pcap.Reader ( open(sys.argv[1] ) )    # file interface
    main(pc)

