#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include <pcap.h>

#include "decode.h"


void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	/*printf("==== Got a %d byte packet ====\n", cap_header->len);*/
	decode_ethernet(packet);
}


void live_scan(char* device,char* filter_exp){
  struct pcap_pkthdr cap_header;
  const u_char *packet, *pkt_data;
  pcap_t *pcap_handle;

  char errbuf[PCAP_ERRBUF_SIZE];

  struct bpf_program fp;			/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */



  if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
        device, errbuf);
    exit(EXIT_FAILURE);
    net = 0;
    mask = 0;

  }

  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if(pcap_handle == NULL)
    fprintf(stderr, "pcap_open_live: %s", errbuf);


  if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
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
