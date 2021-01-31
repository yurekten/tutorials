#include <core.p4>
#include <v1model.p4>

register<bit<24>>(REGISTER_SIZE) reg_sfc_proxy_spi;
register<bit<8>>(REGISTER_SIZE) reg_sfc_proxy_si;
register<bit<48>>(REGISTER_SIZE) reg_sfc_proxy_time;
register<bit<9>>(REGISTER_SIZE) reg_sfc_proxy_waiting_port;
register<bit<48>>(1) reg_proxy_threshold;


control SfcProxyEncapPipe(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action sfc_encap(bit<24> spi, bit<8> si, bit<32> ch1, bit<32> ch2, bit<32> ch3, bit<32> ch4) {
        meta.encap_proxy_match = true;
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

    apply {

        bit<16> index_data = 0;
        bit<24> spi = 0;
        bit<8> si = 0;
        bit<48> in_time = 0;
        bit<9> input_port = 0;

        reg_sfc_proxy_waiting_port.read(input_port, meta.reg_packet_checksum);

        if (standard_metadata.ingress_port == input_port) {

            reg_sfc_proxy_time.read(in_time, meta.reg_packet_checksum);
            bit<48> delta = (standard_metadata.ingress_global_timestamp - in_time);
            bit<48> threshold = 0;

            reg_proxy_threshold.read(threshold, 0);
            //if threshold is not set, define default value
            if(threshold == 0) {
                threshold = 10000; // 10 ms
            }
            if(spi > 0 && si > 0 && delta <= threshold) {
                reg_sfc_proxy_spi.read(spi, meta.reg_packet_checksum);
                reg_sfc_proxy_si.read(si, meta.reg_packet_checksum);
                //decrement service index
                sfc_encap(spi, si - 1, 0, 0, 0,0);
            } else  {
                //reset registers
                reg_sfc_proxy_spi.write(meta.reg_packet_checksum, 0);
                reg_sfc_proxy_si.write(meta.reg_packet_checksum, 0);
                reg_sfc_proxy_time.write(meta.reg_packet_checksum, 0);
                reg_sfc_proxy_waiting_port.write(meta.reg_packet_checksum, 0);
            }
        }

    }
}


control SfcProxyDecapPipe(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    apply {

        if (meta.forward_to_nf && !meta.sfc_aware_nf) {
            hdr.ethernet.etherType = TYPE_IPV4;
            hdr.nsh.setInvalid();
            //use checksum as index of registers
            reg_sfc_proxy_spi.write(meta.reg_packet_checksum, meta.updated_nsh.spi);
            reg_sfc_proxy_si.write(meta.reg_packet_checksum, meta.updated_nsh.si);
            reg_sfc_proxy_time.write(meta.reg_packet_checksum, standard_metadata.ingress_global_timestamp);
            reg_sfc_proxy_waiting_port.write(meta.reg_packet_checksum, meta.from_nf_instance_port);

        }
    }
}
