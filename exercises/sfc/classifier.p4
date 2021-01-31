#include <core.p4>
#include <v1model.p4>

control IngressClassifierPipe(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    action sfc_encap(bit<24> spi, bit<8> si, bit<32> ch1, bit<32> ch2, bit<32> ch3, bit<32> ch4) {
        meta.classifier_match = true;
        meta.updated_nsh.setValid();
        //hdr.updated_nsh.version = 0;
        //hdr.updated_nsh.oam = 0;
        //hdr.updated_nsh.unused1 = 0;
        meta.updated_nsh.ttl = 63;
        meta.updated_nsh.len = 6;
        //hdr.updated_nsh.unused2 = 0;
        meta.updated_nsh.mdType = 1;
        meta.updated_nsh.nextProtocol = TYPE_NSH_IPV4;
        meta.updated_nsh.spi = spi;
        meta.updated_nsh.si = si;
        meta.updated_nsh.ch1 = ch1;
        meta.updated_nsh.ch2 = ch2;
        meta.updated_nsh.ch3 = ch3;
        meta.updated_nsh.ch4 = ch4;
    }

    table t_sfc_src_classifier {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            sfc_encap;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    table t_sfc_dst_classifier {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            sfc_encap;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        t_sfc_src_classifier.apply();
        if(!meta.classifier_match) {
            t_sfc_dst_classifier.apply();
        }
    }
}