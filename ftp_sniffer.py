#!/usr/bin/python3
#_*_ coding: utf8 _*_

import argparse
from scapy.all import *

parse = argparse.ArgumentParser()
parse.add_argument("-i","--interface",help="-i Interfaz de red")
parse = parse.parse_args()

def sniffer_ftp(pkt):
    if  pkt[TCP].dport == 21:
        data = pkt.sprintf("%Raw.load%")  ## %op1.op2% Hace que si no encuentra Raw cargue load sin errores

        if "USER" in data:
            print("FTP IP: " + pkt[IP].dst )
            data = data.split(" ")
            data = data[1]
            print("[+] Posible ftp user: " + data)
        elif "PASS" in data:
            data = data.split(" ")
            data = data[1]
            print("[+] Password: " + data)


def main():
    if parse.interface:
        print("runing")
        sniff(iface=parse.interface, store=False, filter="tcp and port 21", prn=sniffer_ftp)
    else:
        print("Ingrese interfaz de red")


if __name__ == "__main__":

    main()