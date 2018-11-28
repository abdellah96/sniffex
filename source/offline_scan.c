#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include <pcap.h>

#include "decode.h"


void offline_scan(char * file, char * filter_exp){
  pcap_t *pcap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  struct bpf_program fp;			/* compiled filter program (expression) */

  if((pcap_handle = pcap_open_offline(file, errbuf)) == NULL) {
    fprintf(stderr, "Failed to open file %s : %s\n", file, errbuf);
    exit(-1);
  }

  if (pcap_compile(pcap_handle, &fp, filter_exp, 0, 0) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(pcap_handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE);
  }

  pcap_loop(pcap_handle, 0, caught_packet, NULL);

  pcap_freecode(&fp);

  pcap_close(pcap_handle);

  printf("\nCapture complete.\n");
}
