#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <ctype.h>

#include <netinet/in.h>

#include "decode.h"

void decode_ftp(const u_char *header_start,uint16_t size){
  int i = 0 ;

  V_printf(LOW_VERBOSITY,CYAN,"\t\t\t###  Layer 5 :::: DNS Header  ###\n");

  if(size == 0){
		V_printf(LOW_VERBOSITY,RED,"\t\t\tThis packet contains no more data\n");
		return;
  }

if(getverbosity() == HIGH_VERBOSITY){
  while (i<size){
    if (i%47==0)
      printf("\n\t\t\t");
    if(isprint(header_start[i]))
      printf("%c", header_start[i]);
    else
      printf(".");
    i++;
  }
  printf("\n");

}


}
