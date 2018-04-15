#!/usr/bin/python
#
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
# 1) number of the packets (use number_of_packets),
# 2) list distinct source IP addresses and number of packets for each IP address, in descending order
# 3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
# 4) The number of distinct source IP, destination TCP port pairs, in descending order

import dpkt
import socket
import argparse
import operator

# this helper method will turn an IP address into a string


def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code


def main():
    number_of_packets = 0             # you can use these structures if you wish
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client
    parser = argparse.ArgumentParser(
        description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f', '--filename',
                        help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing
    input_data = dpkt.pcap.Reader(open(filename, 'rb'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:
        number_of_packets += 1

        eth = dpkt.ethernet.Ethernet(packet)

        if type(eth.data) != dpkt.ip.IP:
           continue
            
        ip = eth.data

        src_ip = str(socket.inet_ntoa(ip.src))

        if src_ip in list_of_ips.keys():
            list_of_ips[src_ip] += 1
        else:
            list_of_ips[src_ip] = 1

        if type(ip.data) != dpkt.tcp.TCP:
            continue

        dst_tcp = str(ip.data.dport)

        if dst_tcp in list_of_tcp_ports.keys():
            list_of_tcp_ports[dst_tcp] += 1
        else:
            list_of_tcp_ports[dst_tcp] = 1

        if (src_ip, dst_tcp) in list_of_ip_tcp_ports.keys():
            list_of_ip_tcp_ports[(src_ip, dst_tcp)] += 1
        else:
            list_of_ip_tcp_ports[(src_ip, dst_tcp)] = 1

    print('CS 352 Wireshark, part 1')
    print('Total number of packets, ' + str(number_of_packets))

    sorted_ips = sorted(list_of_ips.items(), key=operator.itemgetter(1),reverse=True)
    sorted_tcps = sorted(list_of_tcp_ports.items(), key=operator.itemgetter(1),reverse=True)
    sorted_ips_tcps = sorted(list_of_ip_tcp_ports.items(), key=operator.itemgetter(1),reverse=True)

    print('Source IP addresses, count')
    for cur_ip in sorted_ips:
        print(cur_ip[0] + ', ' + str(cur_ip[1]))

    print('Destination TCP ports, count')
    for cur_tcp in sorted_tcps:
        print(cur_tcp[0] + ', ' + str(cur_tcp[1]))

    print('Source IPs/Destination TCP ports, count')
    for cur_ip_tcp in sorted_ips_tcps:
        print(str(cur_ip_tcp[0][0]) + ':' + str(cur_ip_tcp[0][1]) + ', ' + str(cur_ip_tcp[1]))

        # execute a main function in Python
if __name__ == "__main__":
    main()
