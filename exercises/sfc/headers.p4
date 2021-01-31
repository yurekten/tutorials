#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_NSH = 0x894F;
const bit<16> TYPE_IPV4 = 0x800;

const bit<8> TYPE_NSH_IPV4 = 0x1;
const bit<8> TYPE_NSH_ETHERNET = 0x3;

const bit<32> REGISTER_SIZE = (bit<32>)65535;
const bit<32> BASE_INDEX = (bit<32>)0;
const bit<32> MAX_INDEX = REGISTER_SIZE;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> nfInstanceId_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header nsh_t {
    bit<2> version;
    bit<1> oam;
    bit<1> unused1;
    bit<6> ttl;
    bit<6> len;
    bit<4> unused2;
    bit<4> mdType;
    bit<8> nextProtocol;
    bit<24> spi;
    bit<8> si;
    bit<32> ch1;
    bit<32> ch2;
    bit<32> ch3;
    bit<32> ch4;
}


header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct custom_metadata_t {
    bool        is_nsh_upstream;
    bool        classifier_match;
    bool        encap_proxy_match;
    bit<32>     meter_tag;
    nsh_t  	updated_nsh;

    bit<32>     reg_packet_checksum;

    bool            forward_to_nf;
    nfInstanceId_t  nf_instance_id;
    ip4Addr_t       nf_instance_ip;
    macAddr_t       nf_instance_mac;
    bool            sfc_aware_nf;
    egressSpec_t    to_nf_instance_port;
    egressSpec_t    from_nf_instance_port;
    ip4Addr_t       nextnf_instance_ip;

}

struct headers {
    ethernet_t	ethernet;
    nsh_t  	nsh;
    ipv4_t	ipv4;
    tcp_t       tcp;
    udp_t       udp;
    icmp_t      icmp;
}