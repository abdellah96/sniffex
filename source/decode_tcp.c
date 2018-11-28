#include <stdio.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <linux/tcp.h>

#include "decode.h"


void decode_tcp(const u_char *header_start,uint16_t size) {
   u_int header_size;
   struct tcphdr *tcp_header = (struct tcphdr *)header_start;
   header_size = 4 * tcp_header->doff;
   V_printf(LOW_VERBOSITY,CYAN,"\t\t{{  Layer 4 :::: TCP Header  }}\n");
   V_printf(LOW_VERBOSITY,MAGENTA,"\t\t\tSource Port: %hu\t\n", ntohs(tcp_header->source));
   V_printf(LOW_VERBOSITY,MAGENTA,"\t\t\tDestination Port: %hu \n", ntohs(tcp_header->dest));
   V_printf(MEDIUM_VERBOSITY,MAGENTA,"\t\t\tSequence #: %u\t", ntohl(tcp_header->seq));
   V_printf(MEDIUM_VERBOSITY,MAGENTA,"Acknowledge #: %u \n", ntohl(tcp_header->ack_seq));
   V_printf(HIGH_VERBOSITY,MAGENTA,"\t\t\tHeader Size: %u\t\tFlags: ", header_size);


   if(tcp_header->fin)
      V_printf(HIGH_VERBOSITY,RED,"FIN ");
   if(tcp_header->syn)
    V_printf(HIGH_VERBOSITY,RED,"SYN ");
   if(tcp_header->rst)
    V_printf(HIGH_VERBOSITY,RED,"RST ");
   if(tcp_header->psh)
    V_printf(HIGH_VERBOSITY,RED,"PUSH ");
   if(tcp_header->ack)
    V_printf(HIGH_VERBOSITY,RED,"ACK ");
   if(tcp_header->urg)
    V_printf(HIGH_VERBOSITY,RED,"URG ");

   if (ntohs(tcp_header->dest) == 21 || ntohs(tcp_header->source == 21)) {
     decode_ftp(header_start + header_size , size - header_size);
   }else if (ntohs(tcp_header->dest) == 25 || ntohs(tcp_header->source == 25)) {
     decode_smtp(header_start + header_size, size - header_size);
   }else if ((ntohs(tcp_header->source) == 80) || (ntohs(tcp_header->dest == 80))) {
     decode_http(header_start + header_size , size - header_size);
   }else if (ntohs(tcp_header->source) == 110 || ntohs(tcp_header->dest == 110)) {
     printf("POP");
   }else if (ntohs(tcp_header->source) == 143 || ntohs(tcp_header->dest == 143)) {
     printf("IMAP");
   }
   printf("\n");



}
