#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>

int main (int argc, char *argv[])
{
    char line[100];
    char Fileline[100];
    char subdomain[50];
    char domainSource[50];

    char domainList[] = "domainsFound.txt";

    FILE *domainListFile = fopen(domainList, "a+");


    char dnsTrafficLog[] = "file.txt";
    
    int domSrcIndex;
    int lenThreshold = 8;


    int capThreshold = 3;
    int capCount;
    bool capThresholdBool = false;
    
    int numThreshold = 2;
    int numCount;
    bool numThresholdBool = false;

    bool base64Bool = false;
   
    int domainSourceNum; //tricky to assign to a specific domain name when there will be multiple
    int domainSourceThreshold = 5;

    int abnormalityThreshold = 2;

    //can play around with the thresholds

    //-------------------------------- Session File Remover -----------------------------------------//

    //https://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c
    //https://www.geeksforgeeks.org/c-program-delete-file/
    if( access( domainList, F_OK ) == 0 ) {
        if (remove(domainList) == 0) {
            printf("Deleted the temporary files from the previous session   \n\n");
        }
        else {
        printf("Unable to delete the previous domain parsing log  \n\n");
        }
    }

    //-------------------------------- Collated Line Rule Booleans -----------------------------------------//

    FILE *f = fopen(dnsTrafficLog, "r");

    if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    while( fgets(line, 100, f) != NULL ) { //get each line
        int i;
        int x;
        
        for (i = 0; line[i] != '\0'; i++) { //cycle through each char of each line of log
            if(line[i]!=46) {  //collects the subdomain up till the '.'
                snprintf(subdomain, 50, "%c", line[i]); //assumption that the left most label is the malicous part, could be mixed up.
                
                if(line[i]==61) { //if '=' is found
                    base64Bool = true;
                }

                if(line[i] >= 65 && line[i] <= 90) { //if ascii "A-Z" is found
                    capCount++;
                    if(capCount >= capThreshold) {
                        capThresholdBool = true;
                    }
                }

                if(isdigit(line[i])) { //if a number is found
                    numCount++;
                    if(numCount >= numThreshold) {
                        numThresholdBool = true;
                    }
                }
            }
            else {
                domSrcIndex = i + 1; 
                break;
            }
            printf(subdomain);
        }

        printf("\n");

        int domSrcIndex = i + 1;

        

        if (domainListFile == NULL) { //stuff like this could be functioned down
            printf("Error opening file!\n");
            exit(1);
        }

        //-------------------------------- Root Domain Collector -----------------------------------------//

        for(domSrcIndex; line[domSrcIndex]!='\0'; domSrcIndex++) { //collects everything after the subdomain to check for a constant
            //printf('%d', domSrcIndex);
            snprintf(domainSource, 50, "%c", line[domSrcIndex]);
            printf(domainSource);
            fprintf(domainListFile, domainSource);
        }

        //-------------------------------- Rule Status -----------------------------------------//

        int abnormalityCount = 0;

        //could show end count?


    //can then delete original file used by IDS
    //link it so that on ctrl c its automatic for analysis somehow?

    fclose(domainListFile);
    fclose(f);
}