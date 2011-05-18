#! /usr/bin/python
#
# A simple UDP packet receiver with a twist.  This gets a potentially very large
# packet to demonstrate fragmentation of a UDP packet, so we can test packet
# reassembly

import socket

UDP_IP=""    # listen to anything IPv4 or IPv6
UDP_PORT=50005

sock = socket.socket( socket.AF_INET6, # Internet IPv4 or IPv6
                      socket.SOCK_DGRAM ) # UDP
sock.bind( (UDP_IP,UDP_PORT) )

while True:
    data, addr = sock.recvfrom( 1048576 ) # buffer size huge
    print "received message from ", addr,  "Lenth of data: ", len(data)
