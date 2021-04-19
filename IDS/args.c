/* Compile with: gcc args.c -o IDS -lpcap */
//Requires - sudo apt-get install libpcap-dev

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

bool dnsExfilMode = false;
bool ICMPMode = false;

/*
Add prototypes and split into header files
Add requirements for mapping of switches
Fix needing specific chars for getops
Tidy up code
*/

//Eventually required together
// sudo ./IDS -b eth0 -c

struct addr;

void printUsage()
{
    printf("################################# USAGE ###################################\n");
    printf("-i = list available interfaces\n");
    printf("-b = bind to chosen interface\n");
    printf("-d = look for DNS exfiltration behaviours\n");
    printf("-I = look for IMCP DoS behaviours\n");
    printf("-p = pcap file for input\n");
    printf("-c = capture live transmissions\n");
    printf("-o = output to pcap (requires -c)\n");
    printf("-l = threat logging to chosen file\n");
    printf("-v = Verbosity\n");
    printf("###########################################################################\n");
}

void switchHandler(int argCount, char *argText[])
{
    int argSwitch;

    if (argCount < 2)
    {
        printUsage();
    }

    while ((argSwitch = getopt(argCount, argText, "dfbi")) != -1)
    {
        switch (argSwitch)
        {
            //seemingly cannot use 'b' for example
            //compare the two examples, comment the other out

        case 'd':
            dnsExfilMode = true;
            break;
        case 'f':
            //printInterfaces();
            readPCAP(argText[2]);
            break;
        case 'b':
            //printInterfaces();
            bindInt(argText[2]);
            break;
        case 'i':
            //printInterfaces();
            bindInt(argText[2]);
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    if (remove(captureLog) == 0)
    {
        printf("Previous Session Detected - Removing Prior Log!\n");
    }

    switchHandler(argc, argv);
    return 0;
}
