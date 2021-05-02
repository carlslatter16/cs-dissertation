#include <pcap.h>
#include <stdbool.h>


pcap_dumper_t *pcapCapFile;
pcapUsed = false;  //important to avoid pcap input producing pcap output.