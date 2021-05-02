/* Compile with: gcc args.c -o IDS -lpcap */
//Requires - sudo apt-get install libpcap-dev

/*
Future TOOD:
Add prototypes and split into header files
Add requirements for mapping of switches
*/


#include <stdio.h>
#include <unistd.h>
#include "interfaces.c"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <stdbool.h>

struct addr;

void printUsage()
{
    printf("################################# USAGE ###################################\n");
    printf("-b = bind to chosen interface\n");
    printf("-f = pcap file for input\n");
    printf("###########################################################################\n");
}

void switchHandler(int argCount, char *argText[])
{
    int argSwitch;

    if (argCount < 2)
    {
        printUsage();
    }

    while ((argSwitch = getopt(argCount, argText, "dfb")) != -1)
    {
        switch (argSwitch)
        {
        case 'f':
            pcapUsed = true;
            readPCAP(argText[2]);
            break;
        case 'b':
            pcapUsed = false;
            bindInt(argText[2]);
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    if (remove(captureLog) == 0)  //avoids comflicting logs
    {
        printf("Previous Session Detected - Removing Prior Log!\n");
    }

    switchHandler(argc, argv);
    return 0;
}
