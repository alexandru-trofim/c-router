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

char* create_icmp_good_packet(char* packet, size_t packet_len) {

	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct icmphdr* icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    char *new_packet = malloc(sizeof(char) * MAX_PACKET_LEN);
    memcpy(new_packet, packet, packet_len);
	struct ether_header *new_eth_hdr = (struct ether_header *) new_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	struct icmphdr* new_icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    //fill ip packet
    new_ip_hdr->ttl = 64;
	new_ip_hdr->daddr = ip_hdr->saddr;
    new_ip_hdr->saddr = ip_hdr->daddr;

    new_ip_hdr->check = 0;
    new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));
    
    //fill hdr_packet
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);

    new_icmp_hdr->type = 0;
    new_icmp_hdr->code = 0;
    new_icmp_hdr->checksum = 0;

    new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr)));


    return new_packet;
}

char* create_icmp_bad_packet(char* packet, size_t packet_len, uint8_t type, int interface) {

	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct icmphdr* icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    char *new_packet = malloc(sizeof(char) * MAX_PACKET_LEN);
    memcpy(new_packet, packet, packet_len);
	struct ether_header *new_eth_hdr = (struct ether_header *) new_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	struct icmphdr* new_icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));



    //fill ip packet
    new_ip_hdr->ihl = 5;
    new_ip_hdr->version = 4;
    new_ip_hdr->tos= 0;
    new_ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
    new_ip_hdr->id = htons(1);
    new_ip_hdr->frag_off = 0;
    new_ip_hdr->ttl = 64;
    new_ip_hdr->protocol = 1;
	new_ip_hdr->daddr = ip_hdr->saddr;
    //source address should be the router
    uint32_t converted_router_ip;
	char* router_ip = get_interface_ip(interface);
	inet_pton(AF_INET, router_ip, &converted_router_ip);
    new_ip_hdr->saddr = converted_router_ip;

    new_ip_hdr->check = 0;
    new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));
    
    //fill eth_hdr_packet

    uint8_t router_mac[6];
	get_interface_mac(interface, router_mac);
    new_eth_hdr->ether_type = htons(0x0800);
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(new_eth_hdr->ether_shost, router_mac, 6);

    new_icmp_hdr->type = type;
    new_icmp_hdr->code = 0;
    new_icmp_hdr->checksum = 0;

    new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr)));

    packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    memcpy(new_packet + packet_len, packet + sizeof(struct ether_header), sizeof(struct iphdr));
    packet_len += sizeof(struct iphdr);
    memcpy(new_packet + packet_len, packet + sizeof(struct ether_header) + sizeof(struct iphdr), 8);
    packet_len += 8;

    return new_packet;


}