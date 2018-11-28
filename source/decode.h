#include <netinet/in.h>

#define LOW_VERBOSITY 1
#define MEDIUM_VERBOSITY 2
#define HIGH_VERBOSITY 3

#define BLACK "30"
#define RED "31"
#define GREEN "32"
#define YELLOW "33"
#define BLUE "34"
#define MAGENTA "35"
#define CYAN "36"


void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

void V_printf(int verbosity_program,char* color , char *fmt, ...);
int getverbosity();

void live_scan(char* device,char* filter_exp);
void offline_scan(char * file, char * filter);

void decode_ethernet(const u_char *header_start);
void decode_ip(const u_char *header_start);
void decode_tcp(const u_char *header_start,uint16_t size);
void decode_udp(const u_char *header_start);
void decode_arp(const u_char *header_start);
void decode_dns(const u_char *header_start);
void decode_http(const u_char *header_start,uint16_t size);
void decode_ftp(const u_char *header_start,uint16_t size);
void decode_bootp(const u_char *header_start);
void decode_smtp(const u_char *header_start,uint16_t size);
