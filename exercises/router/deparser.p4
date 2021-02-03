#ifndef _ROUTER_DEPARSER_P4_
#define _ROUTER_DEPARSER_P4_

#include <core.p4>
#include <v1model.p4>
control DeparserImpl(packet_out packet,
                 in headers hdr) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}
#endif