#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>

#include <netinet/in.h>
#include <ctype.h>

#include "decode.h"


void decode_smtp(const u_char *header_start,uint16_t size){
  int i = 0 ;
  if(size == 0){
		V_printf(LOW_VERBOSITY,RED,"\t\t\tThis packet contains no more data\n");
		return;
  }
  // les 5 commandes SMTP pour envoyer le courier
  /*const char EHLO[] = ; //Le client s’identifie avec la commande EHLO
  const char mail[] = MAIL; // La commande MAIL identifie l ’expéditeur originaire du message
  const char rcpt[] = RCPT; //La commande RCPT identifie le destinataire
  const char data[] = DATA; //Le contenu du message est envoyé en utilisant la commande DATA(la fin du message est spécifiée par le client en envoyant une ligne contenant juste un point
  const char QUIT[] = QUIT;*/




  if(getverbosity() == HIGH_VERBOSITY){
    printf("\n\t\t\tSMTP DATA\n");

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
