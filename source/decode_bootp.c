#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>



#include <netinet/in.h>

#include "decode.h"
#include "decode_bootp.h"


void decode_bootp(const u_char *header_start){
  struct bootp* bootp_header;
  bootp_header = (struct bootp*)header_start;
  printf("\t\t\t----\n");
  V_printf(LOW_VERBOSITY,CYAN,"\t\t\t###  Layer 5 :::: BOOTP Header  ###\n");
  if(bootp_header->bp_op == BOOTREPLY ){
    V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tOpcode : REPLY ");
  }else if (bootp_header->bp_op == BOOTREQUEST ){
    V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tOpcode : REQUEST ");
  }

  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tHardware type : %d ",bootp_header->bp_htype);
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tHardware address length : %d octets",bootp_header->bp_hlen);
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tHop count : %d |\n",bootp_header->bp_hops);
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tTransaction ID : %.2x\n",bootp_header->bp_xid);
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tNumber of seconds since boot began : %d s|\n",bootp_header->bp_secs);
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tClient IP addr : %s |\n",inet_ntoa(bootp_header->bp_ciaddr));
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tYour IP addr : %s |\n",inet_ntoa(bootp_header->bp_yiaddr));
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tServer IP addr : %s |\n",inet_ntoa(bootp_header->bp_siaddr));
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tGateway IP addr : %s |\n",inet_ntoa(bootp_header->bp_giaddr));
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tClient Hardware addr : %s |\n",bootp_header->bp_chaddr);
  V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tServer Host name : %s |\n",bootp_header->bp_sname);
  V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tBoot filename : %s ",bootp_header->bp_file);

  u_char *vendor;
  vendor = bootp_header->bp_vend;

  //On verifie qu'il s'agit d'une magique cookie pour voir les fonction dhcp
  if(vendor[0]==((u_int8_t)  99) && vendor[1]==((u_int8_t)  130) && vendor[2]==((u_int8_t)  83) && vendor[3]==((u_int8_t)  99)){
 		 V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tMAgic cookie : ");
     for(int k=0;k<4;k++){
       V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\t%x ", vendor[k]);
     }
     printf(" |\n");
     printf("\t\t\t| Fonctions DHCP :  ");

     if(vendor[4] == TAG_DHCP_MESSAGE){
   			switch (vendor[6]){
   				case DHCPDISCOVER :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tDISCOVER|\n");
   					break;
   				case DHCPOFFER :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tOFFER|\n");
   					break;
   				case DHCPDECLINE :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tDECLINE|\n");
   					break;
   				case DHCPACK :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tACK|\n");
   					break;
   				case DHCPNAK :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tNACK|\n");
   					break;
   				case DHCPRELEASE :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tRELEASE|\n");
   					break;
   				case DHCPINFORM :
   					V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tINFORM|\n");
   					break;
   			}
      }
    }
  }
