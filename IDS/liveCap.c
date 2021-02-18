#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

/*
##############################################
Credit for original code: 

https://www.devdungeon.com/content/using-libpcap-c
https://elf11.github.io/2017/01/22/libpcap-in-C.html
https://www.codeproject.com/Tips/465850/Scanning-a-PCAP-dump-to-find-DNS-and-NETBIOS-queri

##############################################
*/

void packetProcessor(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{

    int icmpCount = 0;
    int udpCount = 0;
    int dnsCount = 0;
    int dnsCountLimit = 20;

    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    const struct tcphdr* tcpHeader;
    const struct DNShdr* dnshdr;
    u_char data;
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    u_int srcPort, dstPort;
    u_int size_tcp;
    u_int size_udp;

    ethernetHeader = (struct ether_header*)packet;

    
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
        } 
        
        if (ipHeader->ip_p == IPPROTO_UDP) {
            //http://www.ietf.org/rfc/rfc768.txt
            //http://tools.ietf.org/html/rfc1035

            udpCount = udpCount + 1;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            srcPort = ntohs(udpHeader->source);

            u_char *udpPayload = (u_char *)(packet
                + sizeof(struct ether_header)
                + sizeof(struct ip)
                + sizeof(struct udphdr)
            );
            
            
            if (srcPort == 53 || dstPort == 53) {

                struct dnshdr *DNShdr = (struct dnshdr *)&udpHeader;
                uint8_t *query = udpPayload +32;
                char fqdn[256];
                uint8_t len;
                fqdn[0] = '\0'; /* ensure starting with empty string */
                char label[64];
                int dnsRequestType;
                
                for( len = *query++ ; len >= *query; len=*query++ ) {
                    strncpy( label, query, len );
                    label[len] = '\0'; /* puts zero byte at end */
                    query += len; /* move pointer to end of string */
                    
                    
                // strcat(fqdn, " ");
                // strcat(fqdn, label);
                // printf(fqdn);

                printf(label);
                
                //lots of duplicates and responce packets?

                // if(dnsType==0) {
                //     printf("Request");
                // }
                // printf(querycount);
                    
                // dnsCount = dnsCount + 1;
                // strcat(dstIP, '\n');
                // printf(srcIP);
                // printf(" : ");
                // printf(dstIP);

                

                
                
                //it breaks with simple print statements! It is slow and delayed - messes up easily
                // if(dnsCount == dnsCountLimit) {
                //     printf("Excessive DNS!");
                //     dnsCountLimit = dnsCountLimit + 10;
                // } 

                //dnsHeader = (packet + sizeof(struct ether_header) +  sizeof(ipHeader) + sizeof(udpHeader));
                //printf((u_char *)(packet + sizeof(struct ether_header) + sizeof(ipHeader) + sizeof(udpHeader) + sizeof(dnsHeader)));
                }

            
        } 
        //else if (ipHeader->ip_p == IPPROTO_ICMP) {
        //     icmpCount = icmpCount + 1;
        //     printf("ICMP:", icmpCount);
        // }

        // else if (ipHeader->ip_p == IPPROTO_TCP) {
        //     tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        // }       
    }

}



// void print_packet_info(const u_char *packet, struct pcap_packetHeader packet_header) {
    
//     printf("Packet capture length: %d\n", packet_header.caplen);
//     printf("Packet total length %d\n", packet_header.len);
// }

//Understand and rename and restructure to what makes most sense and only what is needed - justify use of code, transformative
//bc of udp, we must use port as indicator, and can see if it fits the structure
// excess flow of packets can cause denial of service, it might not keep up

//https://stackoverflow.com/questions/6682884/interpretting-payload-using-libpcap -- size check!