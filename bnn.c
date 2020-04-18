#include <nfp.h>
#include <pif_plugin.h>

//__shared uint64_t counter[256];

__shared uint64_t weight_upper[121];  // first 64 bits
__shared uint64_t weight_lower[121];  // second 56 bits

const uint64_t m1  = 0x5555555555555555; //binary: 0101...
const uint64_t m2  = 0x3333333333333333; //binary: 00110011..
const uint64_t m4  = 0x0f0f0f0f0f0f0f0f; //binary:  4 zeros,  4 ones ...
const uint64_t m8  = 0x00ff00ff00ff00ff; //binary:  8 zeros,  8 ones ...
const uint64_t m16 = 0x0000ffff0000ffff; //binary: 16 zeros, 16 ones ...
const uint64_t m32 = 0x00000000ffffffff; //binary: 32 zeros, 32 ones
const uint64_t h01 = 0x0101010101010101; //the sum of 256 to the power of 0,1,2,3...

int popcount64a(uint64_t x)
{
    x = (x & m1 ) + ((x >>  1) & m1 ); //put count of each  2 bits into those  2 bits 
    x = (x & m2 ) + ((x >>  2) & m2 ); //put count of each  4 bits into those  4 bits 
    x = (x & m4 ) + ((x >>  4) & m4 ); //put count of each  8 bits into those  8 bits 
    x = (x & m8 ) + ((x >>  8) & m8 ); //put count of each 16 bits into those 16 bits 
    x = (x & m16) + ((x >> 16) & m16); //put count of each 32 bits into those 32 bits 
    x = (x & m32) + ((x >> 32) & m32); //put count of each 64 bits into those 64 bits 
    return x;
}

int bnn_infer(uint64_t input_upper, uint64_t input_lower)
{
    int hidden_layer_output=0;
    uint64_t hidden_layer_upper=0;
    uint64_t hidden_layer_lower=0;
    int final_output = 0;
    int threshold=60;
    int i=0;

    // reset empty bits
    input_lower = input_lower | ((uint64_t)0xff<<56);

    // hidden layer processing
    for(i=0;i<56;i++){
        hidden_layer_output = popcount64a( ~(input_lower^weight_lower[i]) ) + popcount64a( ~(input_upper^weight_upper[i]) );
        hidden_layer_lower = hidden_layer_lower<<1 + (hidden_layer_output>threshold);
    }
    for(i=56;i<120;i++){
        hidden_layer_output = popcount64a( ~(input_lower^weight_lower[i]) ) + popcount64a( ~(input_upper^weight_upper[i]) );
        hidden_layer_upper = hidden_layer_upper<<1 + (hidden_layer_output>threshold);
    }

    // output layer processing
    hidden_layer_lower = hidden_layer_lower | ((uint64_t)0xff<<56);
    final_output = popcount64a( ~(hidden_layer_lower^weight_lower[120]) ) + popcount64a( ~(hidden_layer_upper^weight_upper[120]) );
    return final_output>threshold;
}

int pif_plugin_bnn_process(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    uint64_t input_upper=0;
    uint64_t input_lower=0;

    if (! pif_plugin_hdr_ipv4_present(headers)) {
        return PIF_PLUGIN_RETURN_DROP;
    }
    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    // weight writing
    if (pif_plugin_hdr_weightwriting_present(headers)) {
        PIF_PLUGIN_weightwriting_T *weightheader = pif_plugin_hdr_get_weightwriting(headers);
        int idx = weightheader->idx;

        weight_upper[idx]=(uint64_t)(weightheader->__val_0)<<32+(uint64_t)(weightheader->__val_1);
        weight_upper[idx]=(uint64_t)(weightheader->__val_2)<<32+(uint64_t)(weightheader->__val_3);

        return PIF_PLUGIN_RETURN_FORWARD;
    }


    // BNN infer - input generation
    if (pif_plugin_hdr_udp_present(headers)) {
        PIF_PLUGIN_udp_T *udpheader = pif_plugin_hdr_get_udp(headers);
        input_lower = (uint64_t)(ipv4->dstAddr)<<32 + (uint64_t)(udpheader->srcPort)<<16 + (uint64_t)(udpheader->dstPort);
        input_upper = (uint64_t)(ipv4->totalLen)<<48 + (uint64_t)(ipv4->protocol)<<40 + (uint64_t)(ipv4->srcAddr)<<8 + (uint64_t)(ipv4->dstAddr)>>24;
    }
    else if (pif_plugin_hdr_tcp_present(headers)) {
        PIF_PLUGIN_tcp_T *tcpheader = pif_plugin_hdr_get_tcp(headers);
        input_lower = (uint64_t)(ipv4->dstAddr)<<32 + (uint64_t)(tcpheader->srcPort)<<16 + (uint64_t)(tcpheader->dstPort);
        input_upper = (uint64_t)(ipv4->totalLen)<<48 + (uint64_t)(ipv4->protocol)<<40 + (uint64_t)(ipv4->srcAddr)<<8 + (uint64_t)(ipv4->dstAddr)>>24;
    }
    else {
        return PIF_PLUGIN_RETURN_DROP;
    }
    // BNN infer - DSCP field modification
    ipv4->diffserv = bnn_infer(input_upper,input_lower);

    return PIF_PLUGIN_RETURN_FORWARD;

}