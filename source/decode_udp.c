#include <stdio.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/udp.h>

#include "decode.h"

void decode_udp(const u_char *header_start){

  u_int header_size;

  struct udphdr *udp_header = (struct udphdr *)header_start;

  header_size = *(int *)(header_start + 4);


  uint16_t sourceport = ntohs(udp_header->source);
  uint16_t destport = htons(udp_header->dest);
  uint16_t len = htons(udp_header->len);
  uint16_t check = htons(udp_header->check);
  /*u_int16_t source = ntohs(udp_header->source);
  u_int16_t dest = ntohs(udp_header->dest);
*/
  V_printf(LOW_VERBOSITY,CYAN,"\t\t{{  Layer 4 :::: UDP Header  }}\n");
  V_printf(LOW_VERBOSITY,MAGENTA,"\t\t\tSource Port: %d\n", sourceport);
  V_printf(LOW_VERBOSITY,MAGENTA,"\t\t\tDestination Port: %d \n", destport );
  V_printf(MEDIUM_VERBOSITY,MAGENTA,"\t\t\tLength #: %u bytes\t", len);
  V_printf(MEDIUM_VERBOSITY,MAGENTA,"Cheksum #: 0x%X \n", check);
  V_printf(HIGH_VERBOSITY,MAGENTA,"\t\t\tHeader Size: %u\t\n: ", header_size);

  /*if(source == 0x35 || dest == 0x35) {
    decode_dns(packet + sizeof(struct udphdr));
  }else if(source == 0x43 || dest == 0x43) {
    decode_dhcp(packet + sizeof(struct udphdr));
  }*/

  if(sourceport == 0x35 || destport == 0x35){
      /*printf("protocoltype:-------DNS\n");*/
      decode_dns(header_start + sizeof(struct udphdr) );
  }else if(sourceport == 0x44 || destport == 0x43 ){
      decode_bootp(header_start + sizeof(struct udphdr));

  }



}
