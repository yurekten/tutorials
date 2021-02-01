/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parsers.p4"
#include "in_upstream.p4"
#include "in_downstream.p4"
#include "proxy.p4"
#include "classifier.p4"
#include "calc_checksum.p4"


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control ChecksumVerificationPipe(inout headers hdr, inout custom_metadata_t meta) {

    apply {

    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/




control IngressPipe(inout headers hdr,
                  inout custom_metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    IngressClassifierPipe() in_classifier;
    IngressUpstreamPipe() ingress_upstream;
    IngressDownStreamPipe() ingress_downstream;
    SfcProxyDecapPipe() sfc_proxy_decap;
    SfcProxyEncapPipe() sfc_proxy_encap;
    ChecksumCalculationPipe() checksum_calc;

    apply {
        if(!hdr.ipv4.isValid()) {
            return;
        }
        if(standard_metadata.instance_type == 4) {
            log_msg("Packet recirculated and spi {} si {}", {hdr.nsh.spi, hdr.nsh.si});
        }
        checksum_calc.apply(hdr, meta);

        meta.updated_nsh = hdr.nsh;

        if(meta.updated_nsh.isValid()) {
            meta.is_nsh_upstream = true;
        }

        // downstream flow processing. Firstly check proxy
        if(!meta.is_nsh_upstream) {
            sfc_proxy_encap.apply(hdr, meta, standard_metadata);
            if(!meta.encap_proxy_match) {
                in_classifier.apply(hdr, meta, standard_metadata);
            }
        }

        if (meta.updated_nsh.isValid()) {
             ingress_upstream.apply(hdr, meta, standard_metadata);
             sfc_proxy_decap.apply(hdr, meta, standard_metadata);
        }


        if(!meta.forward_to_nf && standard_metadata.egress_spec == 0) {
            ingress_downstream.apply(hdr, meta, standard_metadata);
        }


    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control EgressPipe(inout headers hdr,
                 inout custom_metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    action recirculate_packet() {
        // Send again the packet through both pipelines
        hdr.nsh.si = hdr.nsh.si - 1;
        recirculate({});
    }

    apply {

        hdr.nsh = meta.updated_nsh;
        if(meta.forward_to_nf) {
            recirculate_packet();
        }
        if(hdr.nsh.isValid())
            log_msg("NSH header is valid and spi {} si {}", {hdr.nsh.spi, hdr.nsh.si});

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control ChecksumComputationPipe(inout headers  hdr, inout custom_metadata_t meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserPipe(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.nsh);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    ParserImplementation(),
    ChecksumVerificationPipe(),
    IngressPipe(),
    EgressPipe(),
    ChecksumComputationPipe(),
    DeparserPipe()
) main;

