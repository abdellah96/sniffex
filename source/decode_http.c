#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>

#include "decode.h"

void decode_http(const u_char *header_start,uint16_t size){
  int n;			//number of characters read
  int i = 0; //index into data


  V_printf(LOW_VERBOSITY,CYAN,"\t\t\t###  Layer 5 :::: HTTP Header  ###\n");

  if(size == 0){
		V_printf(LOW_VERBOSITY,RED,"\t\t\tThis packet contains no more data\n");
		return;
  }
  if(strncmp(header_start, "GET", 3) == 0 || strncmp(header_start, "HTTP", 4) == 0 ){
    if(getverbosity() >= MEDIUM_VERBOSITY){
      bool firstLineRead = false;
      do{
        n = 0;
        printf("\t\tt");
              if(firstLineRead == false){
                  while(header_start[i] != '\r'){
                      putchar(header_start[i]);
                      i++;
                      n++;
                  }
                  firstLineRead = true;
              }
              else{
                  while(header_start[i] != '\r'){
                      putchar(header_start[i]);
                      i++;
                      n++;
                  }
              }
        printf("\n");
        i += 2;
      }while(n > 0);
    }
  }

	else{
    if(getverbosity()==HIGH_VERBOSITY){
      V_printf(HIGH_VERBOSITY,RED,"\t\t\t\t\t\t[[HTTP Data]]\n");
  		i = 0;
  		n = 1;
  		printf("\t\t\t");
  		while(i < size){
  			if(header_start[i] >= 32 && header_start[i] <= 126){
  				putchar(header_start[i]);
  			}
  			else{
  				putchar('.');
  			}

  			//printbyte(data[i]);
  			if((n & 0x3F) == 0){
  				printf("\n\t\t\t");
  			}
  			n++;
  			i++;
  		}
  		putchar('\n');
    }
  }
}
