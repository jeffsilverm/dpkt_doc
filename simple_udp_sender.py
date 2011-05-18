#! /usr/bin/python
#
# A simple UDP packet sender with a twist.  This sends a very large packet to demonstrate fragmentation
# of a UDP packet, so we can test packet reassembly
import socket

UDP_IP="192.168.1.104"
UDP_PORT=50005

message=""
while len(message) <= 16384 :
    message = message + str(len(message)) + " " + 16*"+" + "\n"

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT
print "message:", message, "Length: ", len(message)

sock = socket.socket( socket.AF_INET, # Internet
                      socket.SOCK_DGRAM ) # UDP
sock.sendto( message, (UDP_IP, UDP_PORT) )

