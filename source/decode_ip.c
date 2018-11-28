#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include <netinet/ip.h>

#include "decode.h"

#define ICMP 1
#define TCP  6
#define UDP  17

void decode_ip(const u_char *header_start) {
	struct in_addr ip_addr;
	struct iphdr *ip_header;
	unsigned char type;

	ip_header = (const struct iphdr *)header_start;

	V_printf(LOW_VERBOSITY,CYAN,"\t((  Layer 3 ::: IP Header  ))\n");
	ip_addr.s_addr = ip_header->saddr;
	V_printf(LOW_VERBOSITY,GREEN,"\t\tSource : %s\t", inet_ntoa(ip_addr));
	ip_addr.s_addr = ip_header->daddr;
	printf("\n");
	V_printf(LOW_VERBOSITY,GREEN,"\t\tDestination : %s )\n", inet_ntoa(ip_addr));
	type = ip_header->protocol;
	V_printf(MEDIUM_VERBOSITY,GREEN,"\t\tType : %u\t", (u_int) type);
	V_printf(MEDIUM_VERBOSITY,GREEN,"ID : %hu\tLength : %hu \n", ntohs(ip_header->id), ntohs(ip_header->tot_len));

	V_printf(HIGH_VERBOSITY,GREEN,"\t\tChecksum : 0x%04X\n",ntohs(ip_header->check));
	V_printf(HIGH_VERBOSITY,GREEN,"\t\tTTL : %d\n",ntohs(ip_header->ttl));




	const struct ip *ip_t;
	ip_t = (struct ip *)(header_start);
	int OFFSET = ip_t->ip_hl * 4;

	V_printf(HIGH_VERBOSITY,GREEN,"\t\tOFFSET : %d bytes\n",OFFSET);
	
	switch (type) {
	case ICMP:
		break;
	case TCP:
		decode_tcp(header_start + OFFSET, ntohs(ip_t->ip_len) - OFFSET);
		break;
	case UDP:
			decode_udp(header_start + OFFSET);
		break;
	default:
		break;
	}
}
