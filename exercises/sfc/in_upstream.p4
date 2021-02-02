#include <core.p4>
#include <v1model.p4>

control IngressUpstreamPipe(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    direct_meter<bit<32>>(MeterType.packets) nf_meter;


    action set_nf_instance_id(nfInstanceId_t nf_instance_id) {
        meta.nf_instance_id = nf_instance_id;
    }

    action sfc_forward(egressSpec_t port) {
         standard_metadata.egress_spec = port;
         meta.updated_nsh.ttl = meta.updated_nsh.ttl - 1;
    }

    action sfc_decap() {
        hdr.ethernet.etherType = TYPE_IPV4;
        meta.updated_nsh.setInvalid();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table t_nsh_lookup {
        key = {
            meta.updated_nsh.spi: exact;
            meta.updated_nsh.si: exact;
        }
        actions = {
            set_nf_instance_id;
            sfc_forward;
            sfc_decap;
            drop;
        }
        size = 4096;
        default_action = drop();
    }

    action set_nf_instance(ip4Addr_t ip, macAddr_t mac, egressSpec_t to_port, egressSpec_t from_port, ip4Addr_t next_nf_ip) {
            meta.forward_to_nf = true;
            standard_metadata.egress_spec = to_port;
            meta.nf_instance_ip = ip;
            meta.nf_instance_mac = mac;
            meta.to_nf_instance_port = to_port;
            meta.from_nf_instance_port = from_port;
            meta.nextnf_instance_ip = next_nf_ip;
            nf_meter.read(meta.meter_tag);
    }

    action set_sfc_aware_nf(ip4Addr_t ip, macAddr_t mac, egressSpec_t port, ip4Addr_t next_nf_ip) {
            meta.sfc_aware_nf = true;
            set_nf_instance(ip, mac, port, port, next_nf_ip);
    }
    action set_sfc_unaware_nf(ip4Addr_t ip, macAddr_t mac, egressSpec_t to_port, egressSpec_t from_port, ip4Addr_t next_nf_ip) {
            meta.sfc_aware_nf = false;
            set_nf_instance(ip, mac, to_port, from_port, next_nf_ip);
    }

    table t_connected_nf {
        key = {
            meta.nf_instance_id: exact;
        }
        actions = {
            set_sfc_aware_nf;
            set_sfc_unaware_nf;
            drop;
        }
        size = 256;
        meters = nf_meter;
        default_action = drop();
    }


    apply {

        switch(t_nsh_lookup.apply().action_run) {
            set_nf_instance_id: {
                t_connected_nf.apply();

                if(meta.forward_to_nf && meta.meter_tag == 0)  {
                    standard_metadata.egress_spec = meta.to_nf_instance_port;
                    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                    hdr.ethernet.dstAddr = meta.nf_instance_mac;

                    meta.updated_nsh.ttl = meta.updated_nsh.ttl - 1;
                } else {
                    //V1MODEL_METER_COLOR_YELLOW: no ops
                    //V1MODEL_METER_COLOR_RED
                }

            }
            sfc_forward: {}
            default: { }
        }
    }
}