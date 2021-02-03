#ifndef _ROUTER_CHECKSUM_P4_
#define _ROUTER_CHECKSUM_P4_

#include <core.p4>
#include <v1model.p4>

control VerifyChecksumImpl(inout headers hdr, inout metadata meta) {
    apply {  }
}

control ComputeChecksumImpl(inout headers hdr, inout metadata meta) {
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

#endif