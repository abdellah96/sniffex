#include <stdio.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <net/if_arp.h>


#include "decode.h"

#define ARP_PROTOCOL_TYPE_IPV4        0x0800

#define ARP_MAC_LENGTH				  6
#define ARP_IPv4_LENGTH				  4



void decode_arp(const u_char *header_start){


  char *opcodeStrings[] = {"ARP REQUEST",
										  "ARP REPLY",
										  "RARP REQUEST",
										  "RARP RAPLY",
										  "DRARP REQUEST",
										  "DRARP REPLY",
										  "DRARP ERROR",
										  "INARP REQUEST",
                      "INARP REPLY"};

  struct arphdr *arp_header;
  arp_header = (struct arphdr*)header_start;

  unsigned short int hardwaretype = ntohs(arp_header->ar_hrd);
  unsigned short int protocoltype = ntohs(arp_header->ar_pro);
  unsigned short int opcode = ntohs(arp_header->ar_op);

  V_printf(LOW_VERBOSITY,CYAN,"\t((  Layer 3 ::: ARP Header  ))\n");


  switch(hardwaretype){
    case ARPHRD_ETHER: {
			V_printf(LOW_VERBOSITY,GREEN,"\t\tHardware Type:  Ethernet\n");
			break;
		}
		default: {
			V_printf(LOW_VERBOSITY,GREEN,"\t\tARP hardware type not implemented yet.\n");
			break;
    }
  }

  switch(protocoltype){
	    case ARP_PROTOCOL_TYPE_IPV4: {
	        V_printf(LOW_VERBOSITY,GREEN,"\t\tHardware Type:  IPV4\t\n");
			break;
	    }
	    default: {
	    	V_printf(LOW_VERBOSITY,GREEN,"\t\tARP protocol type not implemented yet.\n");
			return;
	    }
  }

  if(opcode >= 1 && opcode <=9 ){
        V_printf(MEDIUM_VERBOSITY,GREEN,"\t\tOperation ---- %s\n", opcodeStrings[opcode-1]);
  }


  V_printf(HIGH_VERBOSITY,GREEN,"\t\tHardware Length ---- %u\n",arp_header->ar_hln);
  V_printf(MEDIUM_VERBOSITY,GREEN,"\t\tprotocol Length ---- %u\n",arp_header->ar_pln);


  /*switch(arp_header->ar_hln){
		case ARP_MAC_LENGTH: {
      for(int i = 0; i < ETH_ALEN; i++) {
        if (i > 0) printf(":");
        printf("%hhX", arp_header->ar_tha[i]);
			break;
		}
		/*default: {
			printf("(\tHardware length [%s] not implemented yet.)\n",arp_header->ar_hln);
			return;
		}
  }*/



}
