#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>

int main (int argc, char *argv[])
{
    char line[100];
    char subdomain[50];
    char domainSource[50];
    
    int domSrcIndex;
    int lenThreshold = 8;


    int capThreshold = 3;
    int capCount;
    bool capThresholdBool = false;
    
    int numThreshold = 2;
    int numCount;
    bool numThresholdBool = false;

    bool base64Bool = false;
   
    int abnormalityThreshold = 2;

    //can play around with the thresholds

    FILE *f = fopen("file.txt", "r");

    if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    while( fgets(line, 100, f) != NULL ) {
        int i;
        int x;
        
        for (i = 0; line[i] != '\0'; i++) {
            if(line[i]!=46) {  //collects the subdomain up till the '.'
                snprintf(subdomain, 50, "%c", line[i]); //assumption that the left most label is the malicous part, could be mixed up.
                
                if(line[i]==61) {
                    base64Bool = true;
                }

                if(line[i] >= 65 && line[i] <= 90) {
                    capCount++;
                    if(capCount >= capThreshold) {
                        capThresholdBool = true;
                    }
                }

                if(isdigit(line[i])) {
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

        for(domSrcIndex; line[domSrcIndex]!='\0'; domSrcIndex++) { //collects everything after the subdomain to check for a constant
            //printf('%d', domSrcIndex);
            snprintf(domainSource, 50, "%c", line[domSrcIndex]);
            printf(domainSource);
        }


        int abnormalityCount = 0;

        if(i-1>=lenThreshold) { //if too long to be normal
            printf("   Abnormal length of subdomain fragment!");
            abnormalityCount++;
        }

        if(base64Bool==true) { //if = was found
            base64Bool=false;
            printf("   Possible Base64!");
            abnormalityCount++;
        }

        if(capThresholdBool==true) { //if too many caps to be normal
            capThresholdBool = false;
            printf("   Abnormal occurances of capitals!");
            abnormalityCount++;
        }

        if(numThresholdBool==true) { //if too many numbers to be normal
            numThresholdBool = false;
            printf("   Abnormal occurances of numbers!");
            abnormalityCount++;
            printf("\n");
        }

        //could look at reused domains again - 
        //if there are lots of requests
        //if there are a lot of failed server responces - maybe need to log them or something to then analyse here!

        if(abnormalityCount>=abnormalityThreshold) {
            printf("   # THIS IS LIKELY A MALICIOUS UDP DNS PACKET! # ");
            printf("\n");
            //write to file?
            //read from pcap instead - might be a bit out there for now
        }


        printf("%c", '\n');
        capCount = 0;
        
        memset(subdomain, 0, sizeof(subdomain));
        memset(domainSource, 0, sizeof(domainSource));
    }
      
    fclose(f);
}