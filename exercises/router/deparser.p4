#ifndef _ROUTER_DEPARSER_P4_
#define _ROUTER_DEPARSER_P4_

#include <core.p4>
#include <v1model.p4>

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan_gpe);
        packet.emit(hdr.nsh);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_icmp);
        packet.emit(hdr.inner_udp);
    }
}
#endif