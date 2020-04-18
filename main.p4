// Headers: Eth, IP, and UDP headers.
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
// 20 byte header.
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

// 20 byte tcp header. 20 + 20 + 14 = 54 bytes of network headers.
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type weightwriting_t {
    fields {
        idx : 32;
        val : 120;
    }
}


parser parse_ethernet {
    extract(ethernet);
    return parse_ipv4;
}
parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        17:         parse_udp;
        6:          parse_tcp;
        61:         parse_weightwriting;
        default:    parse_custom;
    }
}

parser parse_udp {
    extract(udp);
    return parse_custom;
}

parser parse_tcp {
    extract(tcp);
    return parse_custom;
}

parser parse_weightwriting {
    extract(weightwriting);
    return parse_custom;
}



header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;
header weightwriting_t weightwriting;

parser start { return parse_ethernet; }
parser parse_custom { return ingress; }

control ingress {
    forwarding_logic();
}

control forwarding_logic {
    apply(forward_table);
}

// forward packets out of a port.
table forward_table {
    reads { standard_metadata.ingress_port: exact; }
    actions { do_forward; }
}

primitive_action bnn_process();

action do_forward(egress_port) {   
    bnn_process();
    modify_field(standard_metadata.egress_spec, egress_port); 
}