#!/usr/bin/env python
#
# This module implements a TCP receiver.  Refer to RFC 793 http://www.rfc-editor.org/rfc/rfc793.txt for details.

import dpkt
import sys
import socket

def connection_id_to_str (cid, v=4) :
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
destination_tcp_port) to a string.  v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4 :
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1])+"<=>"+dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6 :
        src_ip_addr_str = socket.inet_ntop(AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1])+"<=>"+dst_ip_addr_str + "." + str(cid[3])
    else :
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

def decode_tcp(pcap):
    """This function decodes a packet capture file f and breaks it up into tcp connections"""
    print "counter\tsrc prt\tdst prt\tflags"
    packet_cntr = 0
    connection_table = {}   # the keys of the table are the connection ID strings: source IP,
                            # source port, destination IP, destination port.  The values are a tuple which is the
                            # sequence number and a string which is the assembled stream

    for ts, buf in pcap:
        packet_cntr += 1
        eth = dpkt.ethernet.Ethernet(buf)
# Also, this changes a little bit with IPv6.  To tell the difference between IPv4 and IPv6, you have to look
# at the ethertype field, which is given by http://www.iana.org/assignments/ethernet-numbers.  IPv4 is 0x800 or 2048
# and IPv6 is 0x86DD or 34525
# This is simplistic - IPv4 packets can be fragmented.  Also, this only works for IPv4.  IPv6 has a different Ethertype    
        if eth.type == dpkt.ethernet.ETH_TYPE_IP :
            ip = eth.data
            if ip.v != 4 :
                raise ValueError, "In packet %d, the ether type is IPv4 but the IP version number is %d not 4" % (
                    packet_cntr, ip.v )
           # Deal with fragmentation here
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6 :
            ip = eth.data
            if ip.v != 6 :
                raise ValueError, "In packet %d, the ether type is IPv6 but the IP version number is %d not 6" % (
                    packet_cntr, ip.v )
            # IPv6 packets don't fragment            
        else
            print "packet %d is neither IPv4 nor IPv6" % packet_cntr
            continue    # Not going to deal with anything other than IP
        if ip.p == dpkt.ip.IP_PROTO_TCP :
            fin_flag = ( tcp.flags & 0x01 ) != 0
            syn_flag = ( tcp.flags & 0x02 ) != 0
            rst_flag = ( tcp.flags & 0x04 ) != 0
            psh_flag = ( tcp.flags & 0x08 ) != 0
            ack_flag = ( tcp.flags & 0x10 ) != 0
            urg_flag = ( tcp.flags & 0x20 ) != 0
            ece_flag = ( tcp.flags & 0x40 ) != 0
            cwr_flag = ( tcp.flags & 0x80 ) != 0
# The flags string is really for debugging
            flags = (
                ( "C" if cwr_flag else " " ) +
                ( "E" if ece_flag else " " ) +
                ( "U" if urg_flag else " " ) +
                ( "A" if ack_flag else " " ) +
                ( "P" if psh_flag else " " ) +
                ( "R" if rst_flag else " " ) +
                ( "S" if syn_flag else " " ) +
                ( "F" if fin_flag else " " ) )
        if syn_flag and not ack_flag :
## Each TCP connection is forming.  The new connection is stored as a dictionary
 # whose key is the tuple (source_ip_address, source_tcp_port, destination_ip_address, destination_tcp_port)
 # The connection is stored in a dictionary.  The key is the connection_id, value of each key is a list of tcp packets
 # Note that there are two connections, one from the client to the server and one from the server to the client.  This becomes
 # important when the connection is closed, because one side might FIN the connection well before the other side does.
            print "Forming a new connection " + connection_id_to_str( connection_id, ip.v )
            connection_table[connection_id].seq = tcp.seq
            connection_table[connection_id].string = ""
            connection_table[connection_id].starting_byte = 0
        elif syn_flag and ack_flag :
            print "Server responding to a new connection " + connection_id_to_str( connection_id, ip.v )
            connection_table[connection_id]
    # This is where I am having a little confusion.  My instinct tells me that the connection from the client to the server and the
    # connection from the server back to the client should be connected somehow.  But they aren't, except for the SYN-ACK
    # packet.  Otherwise, the source IP, destination IP, source port and destination port are mirror images, but the streams
    # are separate.  The acknowlegement numbers are related, but we don't need to worry about acknowlegements
        elif not syn_flag and ack_flag :
            sequence_number = tcp.seq
            byte_offset = connection_table[connection_id].seq - sequence_number
            connection_table[connection_id].string[byte_offset] = tcp.data
            connection_table[connection_id].seq = sequence_number
# if the push flag is set, then return the string to the caller, along with identifying information so that the
# caller knows which connection is getting data returned.
            if psh_flag != 0 :
                yield ( connection_id, connection_table[connection_id].string[starting_byte:],


