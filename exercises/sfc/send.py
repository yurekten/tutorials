#!/usr/bin/env python

import socket
import random
import argparse

from scapy.all import sendp, get_if_list, get_if_hwaddr
from nsh_header import NSH

from scapy.layers.inet import Ether, IP, TCP, UDP


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--spi', type=int, default=None, help='The spi to use, if unspecified then NSH header will not be included in packet')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    spi = args.spi
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    ip_p = IP(src="10.0.1.1", dst=addr)
    pkt = pkt / ip_p / UDP(dport=1234, sport=random.randint(49152, 65535)) / args.message

    """
    if (spi is not None):
        print "sending on interface {} to spi {}".format(iface, str(spi))
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        ip_p = IP(src="10.0.1.11", dst=addr)
        #NSH(spi=spi, si=100, ch1=10, ch2=20, ch3=30, ch4=40) /
        pkt = pkt / ip_p / UDP(dport=1234, sport=random.randint(49152, 65535)) / args.message
    else:
        print "sending on interface {} to IP addr {}".format(iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / args.message
    """
    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
