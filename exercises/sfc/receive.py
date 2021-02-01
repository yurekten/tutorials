#!/usr/bin/env python
import os
import sys
from scapy.all import sniff, get_if_list
from scapy.layers.inet import TCP, UDP, IP

from nsh_header import NSH


def get_if():
    ifs = get_if_list()
    interface = None
    for i in get_if_list():
        if "eth0" in i:
            interface = i
            break
    if not interface:
        print "Cannot find eth0 interface"
        exit(1)
    return interface


def handle_pkt(pkt):
    if NSH in pkt or (IP in pkt):
        print("got a packet")
        pkt.show2()
        #        hexdump(pkt)
        #        print "len(pkt) = ", len(pkt)
        sys.stdout.flush()


def main():
    interfaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    interface = interfaces[0]
    print("sniffing on %s" % interface)
    sys.stdout.flush()
    sniff(iface=interface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
