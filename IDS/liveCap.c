#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/*
##############################################
Credit for original syntax: https://www.devdungeon.com/content/using-libpcap-c
##############################################
*/
void packetHandler ( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    print_packet_info(packet_body, *packet_header);
    return;
}

//void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}