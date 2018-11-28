#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>



#include <netinet/in.h>
#include "decode.h"

#include "decode_dns.h"

void decode_dns(const u_char *header_start){
  struct sniff_dns *dns_header;
  dns_header = (struct dns_hdr *)(header_start);

  uint16_t id = ntohs(dns_header->dh_id);
	uint16_t flags = htons(dns_header->dh_flags);
	uint16_t questionCount = ntohs(dns_header->dh_question_count);
	uint16_t answerCount = ntohs(dns_header->dh_answer_count);
	uint16_t nameServerCount = ntohs(dns_header->dh_name_server_count);
  uint16_t additionalRecordCount = ntohs(dns_header->dh_additional_record_count);

  V_printf(LOW_VERBOSITY,CYAN,"\t\t\t###  Layer 5 :::: DNS Header  ###\n");

  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tID : 0x%X\n", id);

  //printf("Flags : %hx\n",id);
  //printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 0, 0);
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tResponse or Query?----------->");
  if(DH_IS_RESPONSE(flags)){
		V_printf(LOW_VERBOSITY,RED," Response");
	}
	else{
		V_printf(LOW_VERBOSITY,RED,"Query");
  }
  printf("\n");
  //operation code
  V_printf(LOW_VERBOSITY,YELLOW,"\t\t\tOperation code--------------->");
  uint16_t opcode = DH_OPCODE(flags);
  switch(opcode){
		case DH_OPCODE_QUERY: {
			V_printf(LOW_VERBOSITY,RED," Standard Query");
			break;
		}
		case DH_OPCODE_IQUERY: {
			V_printf(LOW_VERBOSITY,RED," Inverse Query");
			break;
		}
		case DH_OPCODE_STATUS: {
			V_printf(LOW_VERBOSITY,RED," Status Query");
			break;
		}
		case DH_OPCODE_RESERVED: {
			V_printf(LOW_VERBOSITY,RED," Unnasigned operation code");
			break;
		}
		case DH_OPCODE_NOTIFY: {
			V_printf(LOW_VERBOSITY,RED," Notify Query");
			break;
		}
		case DH_OPCODE_UPDATE: {
			V_printf(LOW_VERBOSITY,RED," Update Query");
			break;
		}
		default: {
			V_printf(LOW_VERBOSITY,RED," Operation code %u unknown", opcode);
			break;
		}
	}
  printf("\n");

  //Authoritative flag
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tAuthority:------------------->");

  if(DH_IS_AUTHORITATIVE(flags)){
		V_printf(MEDIUM_VERBOSITY,RED," Authoritative");
	}
	else{
		V_printf(MEDIUM_VERBOSITY,RED," Not authoritative");
  }
  printf("\n");
  //Truncation Flag
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tTruncation Flag-------------->");

  if(DH_IS_TRUNC(flags)){
		V_printf(MEDIUM_VERBOSITY,RED," Truncated");
	}
	else{
		V_printf(MEDIUM_VERBOSITY,RED," Not truncated");
  }
  printf("\n");

  //Recursion desired flag
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tRecursion desired flag------->");

	if(DH_REC_DESIRED(flags)){
		V_printf(MEDIUM_VERBOSITY,RED," Recursion desired");
	}
	else{
		V_printf(MEDIUM_VERBOSITY,RED," Recursion not desired");
	}
  printf("\n");
  //Recursion available flag
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tRecursion available flag----->");

	if(DH_REC_AVAILABLE(flags)){
		V_printf(MEDIUM_VERBOSITY,RED," Recursion available");
	}
	else{
		V_printf(MEDIUM_VERBOSITY,RED," Recursion not available");
	}
  printf("\n");
  //Zero bits

  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tZero bits ? ----------------->");


	if(DH_RESERVED(flags)){
		V_printf(MEDIUM_VERBOSITY,RED," Reserved bits not zeroed");
	}
	else{
		V_printf(MEDIUM_VERBOSITY,RED," Reserved bits zeroed (as they should be)");
	}
  printf("\n");
  //Response code
  V_printf(MEDIUM_VERBOSITY,YELLOW,"\t\t\tResponse Code---------------->");

  uint16_t rcode = DH_RCODE(flags);
  switch(rcode){
		case DH_RCODE_NO_ERR: {
			V_printf(MEDIUM_VERBOSITY,RED," No error occured");
			break;
		}
		case DH_RCODE_FMT_ERR: {
			V_printf(MEDIUM_VERBOSITY,RED," Format error");
			break;
		}
		case DH_RCODE_SERV_ERR: {
			V_printf(MEDIUM_VERBOSITY,RED," Server Failure");
			break;
		}
		case DH_RCODE_NAME_ERR: {
			V_printf(MEDIUM_VERBOSITY,RED," Non-existant domain");
			break;
		}
		case DH_RCODE_NOT_IMPL: {
			V_printf(MEDIUM_VERBOSITY,RED," Not implemented");
			break;
		}
		case DH_RCODE_REFUSED: {
			V_printf(MEDIUM_VERBOSITY,RED," Query refused");
			break;
		}
		default: {
			V_printf(MEDIUM_VERBOSITY,RED,"Response code %u not implemented yet",rcode);
		}
  }

  printf("\n");
  
  V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tNS Count ----- %u\n", nameServerCount);
  V_printf(HIGH_VERBOSITY,YELLOW,"\t\t\tAR Count ----- %u\n", additionalRecordCount);


  // Print questions
  V_printf(HIGH_VERBOSITY,RED,"\t\t\t--------------------Questions------------------\n");

  if(getverbosity() == HIGH_VERBOSITY){
    int i = 0;
    char *payload = ((char *)dns_header) + 12;
    for(i=0; i<questionCount; i++){
  		printf("\t\t\t#%d. ", i+1);		//Print out the question number
  		while(*payload <= 31){					//Skip every byte until you get a valid ascii character
  			payload++;
  		}
  		//Print out a dot if the character is not an ascii character
  		while(*payload != 0){
  			if(*payload >= 32){
  				putchar(*payload);
  			}
  			else{
  				putchar('.');
  			}
  			payload++;
  		}
  		payload++;
  		putchar('\n');
  		payload += 4;	//Skip the 2 byte type field and the 2 byte class field
    }

  V_printf(HIGH_VERBOSITY,RED,"\t\t\t--------------------Responses------------------\n");
  if(answerCount > 0){
    for(i=0; i<answerCount; i++){
      uint16_t name = ntohs(*((uint16_t *)payload));
      payload += 2;

      uint16_t type = ntohs(*((uint16_t *)payload));
      payload += 2;

      uint16_t dnsClass = ntohs(*((uint16_t *)payload));
      payload += 2;

      uint32_t ttl = ntohl(*((uint32_t *)payload));
      payload += 4;

      uint16_t length = ntohs(*((uint16_t *)payload));
      payload += 2;

      printf("\t\t\t#%d:\n", i+1);
      printf("\t\t\tName -- ");
      char *nameptr = (char *)dns_header;
      if(DH_IS_POINTER(name)){
        nameptr += DH_NAME_OFFSET(name);
      }
      while((*nameptr) != 0){
        // First Check if the next 2 characters are actually a pointer
        name = *((uint16_t *)nameptr);
        name = ntohs(name);
        if(DH_IS_POINTER(name)){
          nameptr = ((char *)dns_header) + DH_NAME_OFFSET(name);
        }

        char c = *nameptr;
        putchar(IS_PRINTABLE(c) ? c : '.');
        nameptr++;
      }
      putchar('\n');
      printf("\t\t\tType -- ");
      switch(type){
        case DH_RECORD_A: {
          if(length == 4){
            char address[INET_ADDRSTRLEN];
            printf("A: %s\n", inet_ntop(AF_INET, payload, address, sizeof(address)));
          }
          break;
        }
        case DH_RECORD_CNAME: {
          //printf("			#%d. CNAME, offset: 0x%X bytes.\n", i+1, ntohs(name & 0x3FFF));
          printf("CNAME: ");
          int i = 0;
          while(i < length-2){
            char c = payload[i];
            putchar(IS_PRINTABLE(c) ? c : '.');
            i++;
          }
          name = *((uint16_t *)(payload + i));
          name = ntohs(name);
          if(DH_IS_POINTER(name)){
            char *cnameptr = (char *)dns_header + DH_NAME_OFFSET(name);
            while((*cnameptr) != 0){
              // First Check if the next 2 characters are actually a pointer
              name = *((uint16_t *)cnameptr);
              name = ntohs(name);
              if(DH_IS_POINTER(name)){
                cnameptr = ((char *)dns_header) + DH_NAME_OFFSET(name);
              }

              char c = *cnameptr;
              putchar(IS_PRINTABLE(c) ? c : '.');

              cnameptr++;
            }
          }
          putchar('\n');
          break;
        }
      }
      printf("\t\t\tClass - [%u] ", dnsClass);
      switch(dnsClass){
        case DNS_CLASS_IN:{
          printf("(Internet)");
          break;
        }
        default: {
          printf(" (Unknown)");
          break;
        }
      }
      putchar('\n');

      printf("\t\t\tTTL --- %u seconds\n", ttl);

      printf("\t\t\tLen --- %u bytes\n", length);
      payload += length;
    }
  }
}



}
