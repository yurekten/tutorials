#ifndef _ROUTER_P4_
#idefine _ROUTER_P4_

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"
#include "router_ingress.p4"
#include "router_egress.p4"
#include "deparser.p4"
#include "checksum.p4"



V1Switch(   ParserImpl(),
            VerifyChecksumImpl(),
            RouterIngress(),
            RouterEgress(),
            ComputeChecksumImpl(),
            DeparserImpl()
         ) main;

#endif