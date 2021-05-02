#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "captureEngine.c"

char dnsFilter[] = "udp[10:2] == 0x0100"; //https://www.tcpdump.org/manpages/pcap-filter.7.html DNS Request Filter
bpf_u_int32 net;
struct bpf_program fp;

int bindInt(char *interface)  //Attaches to chosen interface and starts libpcap bindings
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *conn;
    int timeout_limit = 100; //Tick cycle for detection

    if (interface == NULL)
    {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

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
    printf("Scanning... CTRL+C To Stop Filtered Packet Capture \n");

    pcapCapFile = pcap_dump_open(conn, "dnsCap.pcap"); //https://stackoverflow.com/questions/10133017/stop-capture-data-with-libpcap-and-save-it-in-a-file

    pcap_loop(conn, 0, packetProcessor, NULL); //I use distpatch for one and not the other??
    pcap_dump_close(pcapCapFile);

    return 0;
}

int readPCAP(char *pcapFile)  //reads an inputted pcap file and processes the contents similarly to live capture.
{
    //used for pcap file usage sytnax
    //https://www.devdungeon.com/content/using-libpcap-c

    pcapUsed = true;
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