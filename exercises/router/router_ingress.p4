#ifndef _ROUTER_INGRESS_P4_
#define _ROUTER_INGRESS_P4_

#include <core.p4>
#include <v1model.p4>

control RouterIngress(inout headers hdr,
                inout custom_metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(ip4Addr_t nextHopIP, egressSpec_t port) {
        meta.routing.nhop_ipv4 = nextHopIP;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            @defaultonly NoAction;
        }
    }

    apply {
        routing_table.apply();
    }

}

#endif