#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pcap.h>
#include "vars.c"

#define PCAP_BUF_SIZE 1024
#define PCAP_SRC_FILE 2

int packetCount;
int periodThreshold = 3;

char captureLog[] = "rawCap.log";

/*
##############################################
Credit for original code: 
https://www.devdungeon.com/content/using-libpcap-c
https://elf11.github.io/2017/01/22/libpcap-in-C.html
https://www.codeproject.com/Tips/465850/Scanning-a-PCAP-dump-to-find-DNS-and-NETBIOS-queri

##############################################
*/

void packetProcessor(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)  //strips each DNS packet down and parses them into different labels to be written into a temporary log file
{
    packetCount += 1;
    int fqdnLen = 0;
    bool normalReq = true;

    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct udphdr *udpHeader;

    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];

    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    u_char *udpDNSPayload = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    //-------------------------------------------------------------------------------------------

    FILE *f = fopen("rawCap.log", "a");

    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    uint8_t *DNSquery = udpDNSPayload + 13;
    char fqdn[255] = {NULL};
    uint8_t len;
    int periodCount = 0;

    // /https://stackoverflow.com/questions/34037559/how-to-extract-domain-name-from-this-dns-message -- parsing packets is hard!

    for (int z = 0; z <= 254; z++) //255 is the max for a fqdn
    {
        if (DNSquery[z] == NULL)
        {
            break;
        }

        else if (DNSquery[z]) //wierd splitting -- maybe a  break or newline is actuually between segments somehow
        {
            if (DNSquery[z] == 61) //is =?
            {
                fqdn[z] = 61; //replaces to a period delimter
                fqdnLen += 1;
            }
            else if (DNSquery[z] == 43) //is +?
            {
                fqdn[z] = 43; //replaces to a period delimter
                fqdnLen += 1;
            }
            else if (DNSquery[z] == 47) //is /?
            {
                fqdn[z] = 47; //replaces to a period delimter
                fqdnLen += 1;
            }
            else if (isalpha(DNSquery[z]) || isdigit(DNSquery[z])) // is a-Z or 0-9 or
            {
                fqdn[z] = DNSquery[z];
                fqdnLen += 1;
            }
            else if (!ispunct(DNSquery[z]))   //replaces to a period delimter - seems the data stream doesnt have . as an actual char - so i'll wildcard it out to allow other symbols
            {                                 
                fqdn[z] = 46;
                periodCount += 1;
                fqdnLen += 1;
            }
            else
            {
                fqdn[z] = DNSquery[z];
                fqdnLen += 1;
            }
        }
    }

    if (fqdn[fqdnLen - 1] == 46) //if last char is a . - likely a non-conforming domain
    {
        normalReq = false;
    }

    //need to put nicely into fqdn with identifier, seem to only half requests now as the others are blank, will use a filter also!
    if (fqdn[0] != NULL && periodCount <= periodThreshold && periodCount != 0 && normalReq == true)
    {
        fprintf(f, fqdn);
        fprintf(f, ":");
        fprintf(f, srcIP);
        fprintf(f, ":");
        fprintf(f, dstIP);
        fprintf(f, ":");
        fprintf(f, "%u\n", (unsigned)time(NULL)); //https://stackoverflow.com/questions/11765301/how-do-i-get-the-unix-timestamp-in-c-as-an-int
    }
    
    fclose(f);

    //-------------------------------------------------------------------------------------------
    if (pcapUsed == false)
    {
        pcap_dump(pcapCapFile, pkthdr, packet); //https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut7.html
    }

    return;
}
