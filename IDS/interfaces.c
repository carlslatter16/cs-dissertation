#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "liveCap.c"


int bindInt(char *interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *conn;
    if (interface == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    //Credit
    //https://stackoverflow.com/questions/36597189/libpcap-delay-between-receiving-frames-and-call-of-callback-function
    //https://man7.org/linux/man-pages/man3/pcap_create.3pcap.html

    //pcap_create and activate is faster than pcap_open_live  - find out why

    /* conn = pcap_open_live(
            interface,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        ); */

    conn = pcap_create(interface, error_buffer);
    pcap_set_promisc(conn, 1); //To be able to capture traffic not destinted directly for this device.
    pcap_set_immediate_mode(conn, 1);
    //pcap_set_snaplen(conn, 2048); /* Snapshot length */
    pcap_set_timeout(conn, 1000); /* Timeout in milliseconds */
    
    pcap_activate(conn);

    if (conn == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", interface, error_buffer);
         return 2;
    }

    
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

    if (conn == NULL) {
         fprintf(stderr, "Could not open file %s: %s\n", pcapFile, error_buffer);
         return 2;
    }

    printf("PCAP Added Successfully: %s\n", pcapFile);
    printf("Scanning File...\n");

    pcap_loop(conn, 0, packetProcessor, NULL);

    return 0;
}
