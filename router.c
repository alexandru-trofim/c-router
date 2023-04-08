#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"
#include <arpa/inet.h>
#include <string.h>

/* Routing table */
struct route_table_entry *rtable;
struct arp_entry *arp_table;
struct queue* packet_queue;
int rtable_len;
int arp_table_len = 0;

struct arp_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	for (int i = 0; i < arp_table_len; ++i) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int interface;
	char packet[MAX_PACKET_LEN];
	size_t packet_len;

	printf("ARGV[0] %s\n", argv[1]);

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	packet_queue = queue_create();
	DIE(packet_queue == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	// mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	struct TrieNode* rt_table_trie = fill_trie_with_ip(rtable, rtable_len);

	while (1) {
		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "get_message");
		printf("We have received a packet\n");
		struct iphdr *ip_hdr = NULL;
		struct arp_header *arp_hdr = NULL;
		struct ether_header *eth_hdr = (struct ether_header *) packet;

		//check if our packet is ARP
		if (eth_hdr->ether_type == htons(0x0806)) {
			arp_hdr = (struct arp_header*)(packet + sizeof(struct ether_header));
	 		if (arp_hdr->op == htons(1)) { // request 
				//if I get an arp request to the router I should send back the packet with
				fprintf(stderr, "We've got an arp request packet\n");
				uint8_t router_mac[6];
				get_interface_mac(interface, router_mac);

				uint32_t router_ip = arp_hdr->tpa;

				//now change the sender addresses to dest addresses
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);

				arp_hdr->tpa = arp_hdr->spa;

				memcpy(arp_hdr->tha, arp_hdr->sha, 6);

				arp_hdr->spa = router_ip;

				memcpy(arp_hdr->sha, router_mac, 6);
				
				memcpy(eth_hdr->ether_shost, router_mac, 6);
				
				arp_hdr->op = htons(2);
				fprintf(stderr, "ARP request sent.\n");
				send_to_link(interface, packet, packet_len);

			} else if (arp_hdr->op == htons(2)) { // reply 
				fprintf(stderr, "We've got an ARP reply\n");
				struct queue* new_packet_queue = queue_create();
				//add to arp table 
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				// Go through ARP queue and send the packets with the corrensponding next hop	
				while (!queue_empty(packet_queue)) {
					fprintf(stderr, "We dequeued a packet");
					struct packet* queue_element = queue_deq(packet_queue);
					struct ether_header *packet_eth_hdr = (struct ether_header *) queue_element->buf;

					if (queue_element->next_hop == arp_table[arp_table_len].ip) {
						memcpy(packet_eth_hdr->ether_dhost, arp_table[arp_table_len].mac, 6);
						get_interface_mac(queue_element->interface, packet_eth_hdr->ether_shost);

						fprintf(stderr, "Packet sent.\n");
						send_to_link(queue_element->interface, queue_element->buf, queue_element->buf_len);
					} else {
						//the packet waits for another mac address
						queue_enq(new_packet_queue, queue_element);
					}
				}
				free(packet_queue);
				packet_queue = new_packet_queue;
				//increase the arp_table len
				arp_table_len++;
			}



		} else if (eth_hdr->ether_type == htons(0x0800)) {

			ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

			//Compute checksum
			uint16_t old_check = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t check_sum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			if (check_sum != old_check) {
				fprintf(stderr, "Bad checksum ... dropping\n");
				continue;
			}

			struct route_table_entry* best_route = get_best_route_trie(ip_hdr->daddr, rt_table_trie);

			if (best_route == NULL) {
				fprintf(stderr, "NULL route... dropping\n");
				continue;
			}

			fprintf(stderr, "Interface: %d\n", best_route->interface);

			if (ip_hdr->ttl < 1) {
				fprintf(stderr, "TTL less than one... dropping\n");
				continue;
			}

			ip_hdr->check = 0;
			ip_hdr->check = ~(~old_check + ~((uint16_t)ip_hdr->ttl) + (uint16_t)(ip_hdr->ttl - 1)) - 1;
			ip_hdr->ttl -= 1;

			//here will search in our arp table 
			struct arp_entry* entry = get_mac_entry(best_route->next_hop); 

			if (entry == NULL) {
				//if entry is null we have to create an arp request to find the mac
				
				uint8_t sender_mac[6];
				uint32_t converted_router_ip;
				struct packet* new_packet = malloc(sizeof(struct packet));
				uint32_t arp_request_len = sizeof(struct ether_header) + sizeof(struct arp_header);
				char* router_ip = get_interface_ip(best_route->interface);
				inet_pton(AF_INET, router_ip, &converted_router_ip);
				get_interface_mac(best_route->interface, sender_mac);
				// printf("packet we enqueue has len %ld best route interface %d and next hop %u\n", packet_len, best_route->interface, best_route->next_hop);
				new_packet->buf = malloc(packet_len);
				memcpy(new_packet->buf, packet, packet_len);
				new_packet->buf_len = packet_len;
				new_packet->interface = best_route->interface;
				new_packet->next_hop = best_route->next_hop;
				queue_enq(packet_queue, new_packet);

				char* arp_request = create_arp_packet(sender_mac, converted_router_ip, best_route->next_hop);
				send_to_link(best_route->interface, arp_request, arp_request_len);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, entry->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			fprintf(stderr, "Packet sent.\n");
			send_to_link(best_route->interface, packet, packet_len);

		}


	}
}



