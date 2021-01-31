from scapy.all import *

from scapy.layers.inet import Ether, IP
from scapy.layers.inet6 import IPv6

TYPE_NSH = 0x894F
TYPE_IPV4 = 0x0800


class NSH(Packet):
    """
    bit<2> version;
    bit<1> oam;
    bit<1> unused1;
    bit<6> ttl;
    bit<6> length;
    bit<4> unused2;
    bit<4> mdType;
    bit<8> nextProtocol;
    bit<24> spi;
    bit<8> si;
    bit<32> ch1;
    bit<32> ch2;
    bit<32> ch3;
    bit<32> ch4;
    """
    name = "NSH"
    fields_desc = [
        BitField("version", 0, 2),
        BitField("oam", 0, 1),
        BitField("unused1", 0, 1),
        BitField("ttl", 0x3F, 6),
        BitField("length", 0x6, 6),
        BitField("unused2", 0, 4),
        BitField("mdType", 1, 4),
        BitField("nextProtocol", 1, 8),
        BitField("spi", 0, 24),
        BitField("si", 0xFF, 8),
        IntField("ch1", 0),
        IntField("ch2", 0),
        IntField("ch3", 0),
        IntField("ch4", 0)
    ]

    def mysummary(self):
        return self.sprintf("pid=%pid%, dst_id=%dst_id%")


bind_layers(Ether, NSH, type=TYPE_NSH)
bind_layers(NSH, IP, nextProtocol=1)
bind_layers(NSH, IPv6, nextProtocol=2)
bind_layers(NSH, Ether, nextProtocol=3)
bind_layers(NSH, NSH, nextProtocol=4)
