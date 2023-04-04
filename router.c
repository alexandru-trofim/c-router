#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"
#include <arpa/inet.h>
#include <string.h>

/* MAC Table Entry */
struct mac_entry {
	int32_t ip;
	uint8_t mac[6];
};


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct mac_entry *mac_table;
int mac_table_len;


/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry* rtable) {
	for (int i = 0; i < rtable_len; ++i) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			return &rtable[i];
		}
	}

	return NULL;
}

struct mac_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	for (int i = 0; i < mac_table_len; ++i) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}

	return NULL;
}

size_t read_mac_table(struct mac_entry *nei_table)
{
	fprintf(stderr, "Parsing neighbors table\n");

	FILE *f = fopen("arp_table.txt", "r");
	DIE(f == NULL, "Failed to open nei_table.txt");

	char line[100];
	size_t i;

	for (i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];

		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IPv: %s MAC: %s\n", ip_str, mac_str);

		int rc = inet_pton(AF_INET, ip_str, &nei_table[i].ip);
		DIE(rc != 1, "invalid IPv4");

		rc = hwaddr_aton(mac_str, nei_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}

	fclose(f);
	fprintf(stderr, "Done parsing neighbors table.\n");

	return i;
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

	mac_table = malloc(sizeof(struct  mac_entry) * 70000);
	DIE(mac_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = read_mac_table(mac_table);

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

		/* Check if we got an IPv4 packet */
		// if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
		// 	printf("Ignored non-IPv4 packet\n");
		// 	continue;
		// }

		uint16_t old_check = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t check_sum = htons( checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if (check_sum != old_check) {
			fprintf(stderr, "Bad checksum ... dropping\n");
			continue;
		}

		struct route_table_entry* best_route = get_best_route(ip_hdr->daddr, rtable);

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

		struct mac_entry* entry = get_mac_entry(best_route->next_hop);

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



