#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>
#define MAX_LEN 256

int main (int argc, char *argv[])
{   
    int lineCount = 0;
    char line[100];
    char domainList[] = "domainsFound.txt";
    char currentDomain[100]; 

    //----------------------------------- File Line Counter ------------------------------------//

    FILE* domainListFile;
    domainListFile = fopen(domainList, "r");

    if (domainListFile == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    while (fgets(line, 100, domainListFile)) {   
        lineCount++; //counts number of lines in file for later parsing
    }

    fclose(domainListFile);  //could go back to the top instead!

    //------------------------------- Duplicate Line Counter ------------------------------------------//

    domainListFile = fopen(domainList, "r");

    int z = 1;
    int i;
    bool domainMatched = true;

    fgets(line, 100, domainListFile);
    memcpy(currentDomain, line, sizeof(line));

    while (fgets(line, 100, domainListFile)) {
        printf(line);
        for (i = 0; line[i]; i++) { 
            if(line[i] != currentDomain[i]) {
                domainMatched = false;
            }
        }

        if(domainMatched!=false) {
            z++; //could be issues with it counting the first one too
        }
        
    }

    //now the issue is if it hits new domain, it needs to scan whole file before that - could turn it into a function

    printf(currentDomain);
    printf(":");
    printf("%d", z);
    printf("\n");
    z=0;

    fclose(domainListFile);
    return 0;
}