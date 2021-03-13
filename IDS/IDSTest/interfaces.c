#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "liveCap.c"


/*
##############################################
Credit for original syntax: https://www.devdungeon.com/content/using-libpcap-c
##############################################
*/

// int printInterfaces()
// {
//     char *interface;
//     char ipAddr[13]; //numbers + null terminator
//     char subnetMask[13];
//     bpf_u_int32 rawIPAddr; /* IP address as integer */
//     bpf_u_int32 rawSubnetMask; /* Subnet mask as integer */
//     char errorBuffer[PCAP_ERRBUF_SIZE];
//     struct in_addr tempAddress ;
//     int lookup_return_code;

//     interface = pcap_lookupdev(errorBuffer);
   
//     lookup_return_code = pcap_lookupnet( //gets device info raw
//         interface,
//         &rawIPAddr,
//         &rawSubnetMask,
//         errorBuffer
//     );

//     if (lookup_return_code == -1) {
//         printf("%s\n", errorBuffer);
//     }

//     //---------------- Human Readable Addressing --------------------

//     tempAddress.s_addr = rawIPAddr;
//         perror("inet_ntoa");
//     }

//     tempAddress.s_addr = rawSubnetMask;
//     strncpy(subnetMask, inet_ntoa(tempAddress), 13);
//     if (subnetMask == NULL) {
//         perror("inet_ntoa");
//     }

//     printf("Interface Found: %s\n", interface);
//     printf("IP Network Address: %s\n", ipAddr);
//     printf("Subnet Mask: %s\n", subnetMask);
//     printf("\n");
//     return 0;
// }
//   strncpy(ipAddr, inet_ntoa(tempAddress), 13);
//     if (ipAddr == NULL) {
//         perror("inet_ntoa");
//     }

//     tempAddress.s_addr = rawSubnetMask;
//     strncpy(subnetMask, inet_ntoa(tempAddress), 13);
//     if (subnetMask == NULL) {
//         perror("inet_ntoa");
//     }

//     printf("Interface Found: %s\n", interface);
//     printf("IP Network Address: %s\n", ipAddr);
//     printf("Subnet Mask: %s\n", subnetMask);
//     printf("\n");
//     return 0;
// }


int bindInt(char *interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *conn;
    int timeout_limit = 1000; /* In milliseconds - how long between each packet *?

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

