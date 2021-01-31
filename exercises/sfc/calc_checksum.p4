


control ChecksumCalculationPipe(inout headers hdr, inout custom_metadata_t meta) {

    action calculate_icmp_reg_index() {
          hash(meta.reg_packet_checksum,
                HashAlgorithm.crc16,
                BASE_INDEX,
                { hdr.ipv4.dstAddr,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.protocol
                },
                MAX_INDEX);
    }

    action calculate_tcp_reg_index() {
        hash(meta.reg_packet_checksum,
            HashAlgorithm.crc16,
            BASE_INDEX,
            { hdr.ipv4.dstAddr,
              hdr.ipv4.srcAddr,
              hdr.tcp.dstPort,
              hdr.tcp.srcPort,
              hdr.ipv4.protocol
            },
            MAX_INDEX);
    }

    action calculate_udp_reg_index() {
            hash(meta.reg_packet_checksum,
                HashAlgorithm.crc16,
                BASE_INDEX,
                { hdr.ipv4.dstAddr,
                  hdr.ipv4.srcAddr,
                  hdr.udp.dstPort,
                  hdr.udp.srcPort,
                  hdr.ipv4.protocol
                },
                MAX_INDEX);
    }

    apply {
        if(!hdr.ipv4.isValid()) {
            return;
        }

        switch(hdr.ipv4.protocol) {
            1: {
                calculate_icmp_reg_index();
            }
            6: {
                calculate_udp_reg_index();
            }
            17: {
                calculate_udp_reg_index();
            }
            default: {
                meta.reg_packet_checksum = 0;
            }
        }
    }
}