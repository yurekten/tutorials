
#ifndef _ROUTER_PARSER_P4_
#define _ROUTER_PARSER_P4_

#include <core.p4>
#include <v1model.p4>

parser ParserImpl(packet_in packet,
                out headers hdr,
                inout custom_metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            ICMP_PROTO : parse_icmp;
            TCP_PROTO : parse_tcp;
            UDP_PROTO : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            VXLAN_GPE_PORT: parse_vxlan_gpe;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_vxlan_gpe {
        packet.extract(hdr.vxlan_gpe);
        transition select(hdr.vxlan_gpe.next_protocol) {
            VXLAN_GPE_NSH_PROTO: parse_nsh;
            default: accept;
        }
    }

    state parse_nsh {
        packet.extract(hdr.nsh);
        transition select(hdr.nsh.nextProtocol) {
            TYPE_NSH_ETHERNET: parse_inner_ethernet;
            default: accept;
        }
    }
    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol){
            ICMP_PROTO : parse_inner_icmp;
            TCP_PROTO : parse_inner_tcp;
            UDP_PROTO : parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }


}
#endif