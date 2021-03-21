#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "liveCap.c"

char dnsFilter[] = "udp[10:2] == 0x0100";   //https://www.tcpdump.org/manpages/pcap-filter.7.html there are issues if there are other flags I suppose - might add more dns scoping too!
bpf_u_int32 net;
struct bpf_program fp;


int bindInt(char *interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *conn;
    int timeout_limit = 100; /* In milliseconds */

    if (interface == NULL)
    {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    conn = pcap_open_live(
        interface,
        BUFSIZ,
        0,
        timeout_limit,
        error_buffer);
    if (conn == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", interface, error_buffer);
        return 2;
    }

    pcap_compile(conn, &fp, dnsFilter, 0, net);
    pcap_setfilter(conn, &fp);

    printf("Interface Connected Successfully: %s\n", interface);
    printf("Scanning...\n");

    pcap_loop(conn, 0, packetProcessor, NULL);
    //make conditional on other flags

    return 0;
}

int readPCAP(char *pcapFile)
{
    //used for pcap file usage sytnax
    //https://www.devdungeon.com/content/using-libpcap-c

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *conn = pcap_open_offline(pcapFile, error_buffer);


    if (conn == NULL)
    {
        fprintf(stderr, "Could not open file %s: %s\n", pcapFile, error_buffer);
        return 2;
    }

    printf("PCAP Added Successfully: %s\n", pcapFile);
    printf("Scanning File...\n");

    pcap_compile(conn, &fp, dnsFilter, 0, net);
    pcap_setfilter(conn, &fp);

    pcap_dispatch(conn, 0, packetProcessor, NULL);
    printf("\nFiltered Packets: ");
    printf("%d", packetCount);
    printf("\n");

    return 0;
}