#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show)


def main(): 
    sniff("eth0")


if __name__ == '__main__':
    main()