#!/usr/bin/env python

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

def main(f):
    """This function decodes a packet capture file f and breaks it up into tcp connections"""
    pcap = dpkt.pcap.Reader(f)
    print "counter\tsrc prt\tdst prt\tflags"
    packet_cntr = 0
    connection_table = {}

    for ts, buf in pcap:
        packet_cntr += 1
        eth = dpkt.ethernet.Ethernet(buf)
    # This is simplistic - IP packets can be fragmented    
        ip = eth.data
    # This is also simplistic - TCP packets can be fragmented, and also retransmitted
    #
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
        connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if syn_flag and not ack_flag :
    # Each TCP connection is forming.  The new connection is stored as a dictionary
    # whose key is the tuple (source_ip_address, source_tcp_port, destination_ip_address, destination_tcp_port)
    # The connection is stored in a dictionary.  The key is the connection_id, value of each key is a list of tcp packets
    # Note that there are two connections, one from the client to the server and one from the server to the client.  This becomes
    # important when the connection is closed, because one side might FIN the connection well before the other side does.
            print "Forming a new connection " + connection_id_to_str( connection_id, ip.v )
            connection_table[connection_id] = []
        elif syn_flag and ack_flag :
            print "Server responding to a new connection " + connection_id_to_str( connection_id, ip.v )
            connection_table[connection_id] = []
    # This is where I am having a little confusion.  My instinct tells me that the connection from the client to the server and the
    # connection from the server back to the client should be connected somehow.
        elif not syn_flag and ack_flag :
            connection_table[connection_id].append(tcp.data)
        elif fin_flag :
            pass
    # Also need to think about the RESET flag
            
    f.close()
    for connection in connection_table.keys() :
        print "Connection "+ str(connection)
        print connection_table[connection]

        

if __name__ == "__main__" :
    f = open(sys.argv[1])
    main(f)

    
