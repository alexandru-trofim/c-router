#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"
#include <arpa/inet.h>
#include <string.h>


/* Routing table */
struct route_table_entry *rtable;
struct arp_entry *mac_table;
int rtable_len;
int mac_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
  struct route_table_entry *get_best_route(uint32_t ip_dest) {
    uint32_t max_mask = 0;
    int32_t idx_max = -1;
    for (int i = rtable_len - 1; i >= 0; --i) {
        if ((rtable[i].prefix == (ip_dest & rtable[i].mask) )&& rtable[i].mask > max_mask) {
            max_mask = rtable[i].mask;
            idx_max = i;
        }
    }

    return idx_max > 0 ? &rtable[idx_max] : NULL;
}

struct arp_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	for (int i = 0; i < mac_table_len; ++i) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
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

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct  arp_entry) * 100);
	DIE(mac_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	while (1) {
		/* We call get_packet to receive a packet. get_packet returns
		the interface it has received the data from. And writes to
		len the size of the packet. */
		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "get_message");
		printf("We have received a packet\n");
		
		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.payload + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *) packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

		if (eth_hdr->ether_type != htons(0x0800)) {
			fprintf(stderr, "Not IP ... dropping\n");
			continue;
		}

		uint16_t old_check = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t check_sum = htons( checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if (check_sum != old_check) {
			fprintf(stderr, "Bad checksum ... dropping\n");
			continue;
		}

		struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);

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

		struct arp_entry* entry = get_mac_entry(best_route->next_hop);

		if (entry == NULL) {
			fprintf(stderr, "MAC not found in table... dropping\n");
			continue;
		}

		memcpy(eth_hdr->ether_dhost, entry->mac, 6);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		fprintf(stderr, "Packet sent.\n");
		send_to_link(best_route->interface, packet, packet_len);
	}
}



