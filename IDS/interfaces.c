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
    int timeout_limit = 10000; /* In milliseconds */

    if (interface == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    conn = pcap_open_live(
            interface,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
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

