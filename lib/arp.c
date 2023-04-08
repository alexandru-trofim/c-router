#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>



char* create_arp_packet(uint8_t* sender_mac, uint32_t sender_ip, uint32_t dest_ip) {

    //don't forget to free the buf 
    char* buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));

    //now create the eth header 
    struct ether_header eth_hdr;
    memcpy(&eth_hdr.ether_shost, sender_mac, 6);
    for (int i = 0; i < 6; ++i) {
        eth_hdr.ether_dhost[i] = 0xFF;
    }
    eth_hdr.ether_type = htons(0x0806);

    //now create arp header
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(1);
    arp_hdr.ptype =htons(0x0800);
    arp_hdr.hlen = 6;
    arp_hdr.plen = 4;
    arp_hdr.op = htons(1);
    memcpy(arp_hdr.sha, sender_mac, 6);
    arp_hdr.spa = sender_ip;
    for (int i = 0; i < 6; ++i) {
        arp_hdr.tha[i] = 0;
    }
    arp_hdr.tpa = dest_ip;
    
    //copy header and packet in buffer
    memcpy(buf, &eth_hdr, sizeof(eth_hdr));
    memcpy(buf + sizeof(eth_hdr), &arp_hdr, sizeof(arp_hdr));

    return buf;

}