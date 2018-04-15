#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
import operator
from collections import Counter

# convert IP addresses to printable strings
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.
def get_probes(pkt_list, width, min_num):
    #sort list and filter out packets whose port has an occurrence less than min_num
    pkt_list.sort(key=operator.itemgetter(1, 0))
    counts = Counter(pkt[1] for pkt in pkt_list)
    pkt_list = [pkt for pkt in pkt_list if counts[pkt[1]] >= min_num]

    list_len = len(pkt_list)
    added = [0] * list_len
    probes = []
    cur_probe = []

    idx_a = 0
    idx_b = 1

    while idx_a < list_len - 1 and idx_b < list_len:
        pkt_a = pkt_list[idx_a]
        pkt_b = pkt_list[idx_b]

        if pkt_a[1] == pkt_b[1] and (pkt_b[0] - pkt_a[0]).seconds <= width:
            if (added[idx_a] == 0):
                cur_probe += [pkt_list[idx_a]]
                added[idx_a] = 1
            if (added[idx_b] == 0):
                cur_probe += [pkt_list[idx_b]]
                added[idx_b] = 1
        elif len(cur_probe) >= min_num:
            probes += [cur_probe]
            cur_probe = []
        idx_a += 1
        idx_b += 1

    if len(cur_probe) >= min_num:
        probes += [cur_probe]

    return probes

def get_scans(pkt_list, width, min_num):
    pkt_list.sort(key=operator.itemgetter(1))

    list_len = len(pkt_list)
    added = [0] * list_len
    scans = []
    cur_scan = []

    idx_a = 0
    idx_b = 1

    while idx_a < list_len - 1 and idx_b < list_len:
        pkt_a = pkt_list[idx_a]
        pkt_b = pkt_list[idx_b]

        if (pkt_b[1] - pkt_a[1] <= width):
            if (added[idx_a] == 0):
                cur_scan += [pkt_list[idx_a]]
                added[idx_a] = 1
            if (added[idx_b] == 0):
                cur_scan += [pkt_list[idx_b]]
                added[idx_b] = 1
        elif len(cur_scan) >= min_num:
            scans += [cur_scan]
            cur_scan = []
        idx_a += 1
        idx_b += 1

    if len(cur_scan) >= min_num:
        scans += [cur_scan]
    
    return scans

def print_pkt_list(pkt_list, trace_type):
    trace = ' probes' if trace_type == 0 else ' scans'
    print('Found ' + str(len(pkt_list)) + trace)
    plural = ''
    trace = 'Probe: [' if trace_type == 0 else 'Scan: ['
    for cur_trace in pkt_list:
        trace_len = len(cur_trace)
        plural = '' if trace_len == 1 else 's'
        print (trace + str(trace_len) + ' Packet' + plural + ']')
        
        for cur_packet in cur_trace:
            print('\tPacket [Timestamp: ' + str(cur_packet[0]) + ', Port: ' + str(cur_packet[1]) + ', Source IP: ' + cur_packet[2] + ']')

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(
        description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str,
                        help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str,
                        help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name, 'rb'))
    tcp_list = []
    udp_list = []

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        # your code goes here ...
        eth = dpkt.ethernet.Ethernet(packet)

        if type(eth.data) != dpkt.ip.IP:
            continue

        ip = eth.data
        
        if (inet_to_str(ip.dst) == target_ip):
            src_ip = inet_to_str(ip.src)
            if type(ip.data) == dpkt.tcp.TCP:
                tcp_list += [(time_string, ip.data.dport, src_ip)]
            elif type(ip.data) == dpkt.udp.UDP:
                udp_list += [(time_string, ip.data.dport, src_ip)]

    tcp_probes = get_probes(tcp_list, W_p, N_p)
    tcp_scans = get_scans(tcp_list, W_s, N_s)
    udp_probes = get_probes(udp_list, W_p, N_p)
    udp_scans = get_scans(udp_list, W_s, N_s)

    print('CS 352 Wireshark (Part 2)\nReports for TCP')
    print_pkt_list(tcp_probes, 0)
    print_pkt_list(tcp_scans, 1)
    print('Reports for UDP')
    print_pkt_list(udp_probes, 0)
    print_pkt_list(udp_scans, 1)
        
# execute a main function in Python
if __name__ == "__main__":
    main()
