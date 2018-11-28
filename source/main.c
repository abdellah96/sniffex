#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include <pcap.h>

#include "decode.h"

int verbosity_user;


void usage(char *program_nam) {
  printf("Usage : %s (-i <interface> | -o <file>) [-f <BPF filter>] [-v <1|2|3>(verbosity)>]\n", program_nam);
  exit(2);
}



int main(int argc, char * argv[]) {

	char* device = NULL;
	char* file = NULL;
	char* filter = NULL;
	char* verbosity = NULL;

	char c;

	while((c = getopt(argc, argv, "i:o:f:v:")) != -1) {
	 switch(c) {
		 case 'i':
			 device = optarg;
			 break;
		 case 'o':
			 file = optarg;
			 break;
		 case 'f':
			 filter = optarg;
			 break;
		 case 'v':
			 verbosity = optarg;
	 	}
	}

	if(verbosity) {
		verbosity_user = atoi(verbosity);
		if(verbosity_user < 1 || verbosity_user > 3) {
			fprintf(stderr, "Verbosity level must be between 1 and 3\n");
			usage(argv[0]);
		}
		printf("Level of verbosity %d\n",verbosity_user);
	}

	if(!verbosity){
		printf("Verbosity degree by default is LOW \n");
		verbosity_user = LOW_VERBOSITY;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	if(!device){
		device = pcap_lookupdev(errbuf);
		if(device == NULL){
			fprintf(stderr, "pcap_lookupdev: %s", errbuf);
			exit(EXIT_FAILURE);
		}

	}

	printf("Sniffing on device %s\n", device);

	char filter_exp[64] = { 0 };

	if (filter) {
			strncpy(filter_exp, filter, sizeof(filter_exp));
			printf("Filter: %s\n",filter_exp);
	}

	if(!file){
		live_scan(device,filter_exp);
	}

	else{
		offline_scan(file,filter_exp);
	}

}
