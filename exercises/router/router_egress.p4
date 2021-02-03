#ifndef _ROUTER_EGRESS_P4_
#define _ROUTER_EGRESS_P4_

#include <core.p4>
#include <v1model.p4>

control RouterEgress(inout headers hdr,
               inout custom_metadata_t meta,
               inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_dst_mac(macAddr_t dst_mac) {
        hdr.ethernet.dstAddr = dst_mac;
    }

    action set_port_mac(macAddr_t mac) {
        hdr.ethernet.srcAddr = mac;
    }

    table switching_table {
        key = {
            meta.routing.nhop_ipv4 : exact;
        }
        actions = {
            set_dst_mac;
            drop;
        }
        default_action = drop();
    }

    table port_mac_table {

        key = {
            standard_metadata.egress_port: exact;
        }

        actions = {
            set_port_mac;
            drop;
        }
        default_action = drop();

    }

    apply {
        switching_table.apply();
        port_mac_table.apply();
    }

}

#endif