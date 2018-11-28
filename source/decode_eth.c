#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include <linux/if_ether.h>

#include "decode.h"

void decode_ethernet(const u_char *header_start) {
	int i;
	unsigned short type;

	struct ethhdr *ethernet_header;
	ethernet_header = (struct ethhdr *)header_start;
	V_printf(LOW_VERBOSITY,BLUE,"[[  Layer 2 :: Ethernet Header  ]]\n");

	V_printf(LOW_VERBOSITY,YELLOW,"\tSource: %02x", ethernet_header->h_source[0]);
	for(i=1; i < ETH_ALEN; i++)
		V_printf(LOW_VERBOSITY,YELLOW,":%02x", ethernet_header->h_source[i]);
	printf("\n");

	V_printf(LOW_VERBOSITY,YELLOW,"\tDest: %02x", ethernet_header->h_dest[0]);
	for(i=1; i < ETH_ALEN; i++)
		V_printf(LOW_VERBOSITY,YELLOW,":%02x", ethernet_header->h_dest[i]);
	printf("\n");

	type = ntohs(ethernet_header->h_proto);

	V_printf(MEDIUM_VERBOSITY,YELLOW,"\tType: 0x%x \n", type);
	switch (type) {
	case ETH_P_IP:
		decode_ip(header_start + sizeof(struct ethhdr));
		break;
	case ETH_P_ARP:
		decode_arp(header_start + sizeof(struct ethhdr));
		break;
	default:
		break;
		/* not implemeted */
	}
}
