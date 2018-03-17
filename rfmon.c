#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include<net/ethernet.h>


void got_packet(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header *eth_header;
    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
		printf("source: %x:%x:%x:%x:%x:%x\n", eth_header->ether_shost[0],eth_header->ether_shost[1],eth_header->ether_shost[2],eth_header->ether_shost[3],eth_header->ether_shost[4],eth_header->ether_shost[5]);
    }



}

int main(int argc, char **argv) {

	int status;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;

	dev = pcap_lookupdev(errbuf);

	if(dev == NULL) {
		fprintf(stderr, "[ERROR] dev: %s\n", errbuf);
		exit(1);
	}

	printf("interface : %s\n", dev);

	pcap_t *handler = pcap_create(dev, errbuf);

	if(handler == NULL) {
		fprintf(stderr, "[ERROR] handler: %s\n", errbuf);
		exit(1);
	}

	status = pcap_set_rfmon(handler, 1);

	if(status == 0) {
		fprintf(stdout, "%s in Monitor mode\n", dev);
	}

	pcap_set_snaplen(handler, 2048);  // Set the snapshot length to 2048
    pcap_set_promisc(handler, 1); // Turn promiscuous mode off
    pcap_set_timeout(handler, 1000); // Set the timeout to 512 milliseconds
    status = pcap_activate(handler);

	pcap_loop(handler, -1, got_packet, NULL);

	return 0;

}
