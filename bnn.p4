/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4    = 0x800;
const bit<8>  IP_PROT_UDP  = 0x11;

const bit<8>  OP_READ_REG  = 0x1;
const bit<8>  OP_WRITE_REG = 0x2;
const bit<16> UDP_PORT     = 1234;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header weightwriting_t {
    bit<32> idx;
    bit<120> val;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata { }

struct headers {
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    weightwriting_t   weightwriting;
    udp_t             udp;
    tcp_t             tcp;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            6:  parse_tcp;
            61: parse_weightwriting;
            default: accept;
        }
    }

    state parse_weightwriting {
        packet.extract(hdr.weightwriting);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }


    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

// functions for BNN
//////////////////////////////////////////
    register<bit<4>>(65536) flowCache;
    bit<32> key = 0;

    register<bit<120>>(1024) weights;
    bit<120> bnnInput = 0;
    bit<120> XNOROutput = 0;
    bit<120> NextLayerInput = 0;
    //bit<8> count = 0;
    bit<4> activated = 0;
    bit<128> m1 = 0x55555555555555555555555555555555;
    bit<128> m2 = 0x33333333333333333333333333333333;
    bit<128> m4 = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    bit<128> m8 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
    bit<128> m16= 0x0000ffff0000ffff0000ffff0000ffff;
    bit<128> m32= 0x00000000ffffffff00000000ffffffff;
    bit<128> m64= 0x0000000000000000ffffffffffffffff;

    bit<16> L4src = 0;
    bit<16> L4dst = 0;

    // input from 5-tuple and packet length
    action BuildInput(){
        bnnInput = ((bit<120>)hdr.ipv4.totalLen)<<8;
        bnnInput = (bnnInput + (bit<120>)hdr.ipv4.protocol)<<32;
        bnnInput = (bnnInput + (bit<120>)hdr.ipv4.srcAddr)<<32;
        bnnInput = (bnnInput + (bit<120>)hdr.ipv4.dstAddr)<<16;
        bnnInput = (bnnInput + (bit<120>)L4src)<<16;
        bnnInput = bnnInput + (bit<120>)L4dst;
    }

    action XNOR(bit<120> weight){
        XNOROutput = weight^bnnInput;
        XNOROutput = ~XNOROutput;
    }

    action BitCount(bit<120> bitInput){
        bit<128> x= (bit<128>)bitInput;
	x = (x & m1 ) + ((x >>  1) & m1 ); 
	x = (x & m2 ) + ((x >>  2) & m2 );
	x = (x & m4 ) + ((x >>  4) & m4 );
	x = (x & m8 ) + ((x >>  8) & m8 );
	x = (x & m16) + ((x >> 16) & m16);
	x = (x & m32) + ((x >> 32) & m32);
        x = (x & m64) + ((x >> 64) & m64);
        activated = (x>60) ? (bit<4>)1 : 0;
        NextLayerInput = NextLayerInput<<1;
        NextLayerInput = NextLayerInput + (bit<120>)activated;
        //NextLayerInput=(bit<120>)x;
    }

    action LayerProcess(bit<10> offset){
        bit<120 > weight = 0;
        NextLayerInput = 0;
        weights.read( weight, (bit<32>)offset+0);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+1);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+2);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+3);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+4);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+5);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+6);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+7);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+8);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+9);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+10);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+11);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+12);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+13);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+14);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+15);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+16);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+17);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+18);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+19);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+20);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+21);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+22);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+23);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+24);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+25);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+26);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+27);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+28);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+29);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+30);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+31);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+32);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+33);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+34);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+35);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+36);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+37);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+38);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+39);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+40);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+41);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+42);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+43);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+44);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+45);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+46);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+47);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+48);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+49);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+50);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+51);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+52);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+53);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+54);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+55);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+56);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+57);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+58);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+59);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+60);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+61);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+62);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+63);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+64);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+65);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+66);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+67);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+68);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+69);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+70);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+71);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+72);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+73);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+74);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+75);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+76);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+77);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+78);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+79);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+80);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+81);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+82);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+83);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+84);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+85);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+86);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+87);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+88);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+89);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+90);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+91);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+92);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+93);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+94);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+95);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+96);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+97);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+98);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+99);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+100);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+101);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+102);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+103);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+104);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+105);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+106);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+107);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+108);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+109);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+110);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+111);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+112);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+113);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+114);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+115);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+116);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+117);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+118);
        XNOR(weight);
        BitCount(XNOROutput);
        weights.read( weight, (bit<32>)offset+119);
        XNOR(weight);
        BitCount(XNOROutput);
    }

//////////////////////////////////////////


    action reply() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

 //       macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
 //       hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
 //       hdr.ethernet.srcAddr = tmpDstMac;

 //       ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
 //       hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
 //       hdr.ipv4.srcAddr = tmpDstIp;

 //       bit<16> tmpDstPort = hdr.udp.dstPort;
 //       hdr.udp.dstPort = hdr.udp.srcPort;
 //       hdr.udp.srcPort = tmpDstPort;
 //       hdr.udp.checksum = 0;

    }


    apply {

        // BNN process
        //////////////////////////////
        if (hdr.udp.isValid()){
            L4src=hdr.udp.srcPort;
            L4dst=hdr.udp.dstPort;
        }

        if (hdr.tcp.isValid()){
            L4src=hdr.tcp.srcPort;
            L4dst=hdr.tcp.dstPort;
        }

        if (L4src!=0){
            key=(bit<32>)(hdr.ipv4.srcAddr[31:28]+hdr.ipv4.srcAddr[27:24]);
            key=key+(bit<32>)L4dst;
            flowCache.read(activated,key);
	}

	    if (activated!=0){
		hdr.ipv4.diffserv=(bit<8>)activated-1;
		hdr.ipv4.dstAddr=(bit<32>)115;
	    }
	    else{
		    BuildInput();
		    LayerProcess(0);
		    bnnInput=NextLayerInput;
		    NextLayerInput=0;

		    bit<120> weight=0;
		    weights.read( weight, (bit<32>)120);
		    XNOR(weight);
		    BitCount(XNOROutput);

		    hdr.ipv4.diffserv=(bit<8>)activated;
		    hdr.ipv4.dstAddr=(bit<32>)114;

		    flowCache.write( key, (bit<4>)activated+1 );
	    }


        if (hdr.weightwriting.isValid()){
            weights.write((bit<32>)hdr.weightwriting.idx, hdr.weightwriting.val);
        }

        //////////////////////////////

        reply();

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.weightwriting);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
