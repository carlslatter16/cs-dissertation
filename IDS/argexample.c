/* example usage of getopt 
 */

#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
	char opt;
	char iface[20];
	char file[20];
	int  ifid;
	char logfile[20];

	/* some flags to set to capture config from options */
	char /* boolean flags */
		capturef,
		outputf,
		verbosef;

	char /* some string like flags
	        explicitly set initial pointer values to NULL
	     */
		*ifacef=NULL,
		*filef=NULL,
		*logf=NULL;

	/* a struct might be better */
	enum { off, on } ; /* values for boolean flags */
	struct flags {
		char /* boolean flags */
			capture,
			output,
			verbose;

		char /* some string like flags */
			*iface,
			*pcap,
			*log;

		int ifaceid;  /* interface id */
	} config = {off,off,off,NULL,NULL,NULL};;

	while( (opt = getopt(argc, argv, "hib:p:col:v")) != -1 ) {
	/*in the option string, if an argument is expected (a filename) a colon follows the option letter*/
		switch(opt) {
			case 'h':
				printf("--- print some help\n");
				printf(
						"Usage: argexample [-hicov] [-b iface] [-p file] [-l file] \n"
						"  -i        list available interfaces \n"
						"  -b iface  bind to given interface \n "
						"  -p file   pcap file for input \n"
						"  -c        capture live data \n"
						"  -o        output to pcap (requires -c) \n"
						"  -l file   threat logging to given file \n"
						"  -v        be verbose \n"
					  );
				/* Not how the compiler strips out the white-space between
				   strings, and then concatinates them into one long string 
				   kind of like a here-document
				*/
				break;
			case 'i':
				printf("--- show interfaces \n");
				break;
			case 'b':
				printf("--- bind to interface");
				/* the argument to the option is pointed to by 'optarg'.
				   either fully process the sting here, or copy it into a 
				   defined string.  getopt changes the contents of argv, 
				   so a pointer to part of argv is not guaranteed to point to 
				   the same text after the next call to optarg!
				*/
				printf("Binding to %s \n", optarg);
				strcpy( iface, optarg ); /* strncpy might be better */
				ifid = atoi(optarg);/* will be zero if string did not parse as integer */
				ifacef = iface;
				config.iface = iface;
				config.ifaceid = atoi(iface);
				break;
			case 'p':
				printf("--- pcap file to use \n");
				strncpy(file, optarg, 19); /* 1 less than array size to allow for null terminating byte */
				filef = file;
				config.pcap = file;
				break;
			case 'c':
				printf("--- capture \n");
				capturef = 1;
				config.capture = on;
				break;
			case 'o':
				printf("--- output to pcap file \n");
				outputf = 1;
				config.output = on;
				break;
			case 'l':
				printf("--- log to threat file\n");
				strncpy(logfile, optarg, 19);
				logf = logfile;
				config.log = logfile;
				break;
			case 'v':
				printf("be verbose\n");
				verbosef = 1;
				config.verbose = on;
				break;
		}
	}

	/* now print summary */
	printf("Configuration \n");
	if (config.verbose) printf(" being verbose \n");
	if (config.capture) printf(" capturing data \n");
	if (config.pcap) {
		printf(" pcap data file is %s \n", config.pcap);
		if (config.output ) printf(" data output  to pcap file \n");
	}
	if (config.log) printf("Threats logged to file %s \n", config.log );
	if (config.ifaceid) printf("Bind to interface id %d\n", config.ifaceid);

	if ( config.iface && !config.ifaceid ) printf("Bind interface given as '%s', but an error occurred parsing to integer\n",config.iface );

}

