#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>
#define MAX_LEN 256

char domainList[] = "domainsFound.txt";
FILE* domainListFile;
FILE* domainListFileCount; //need seperate processes on the file
char line[100];
char currentDomain[100]; 
int z = 1; // the number of found 
    //------------------------------- Duplicate Line Counter ------------------------------------------//

int domainCounter(char* currentDomain)
{
    domainListFileCount = fopen(domainList, "r");
    int i;
    bool domainMatched = true;
    z=1;

    fgets(line, 100, domainListFileCount);
    //memcpy(currentDomain, line, sizeof(line));

    while (fgets(line, 100, domainListFileCount)) {
        for (i = 0; line[i]; i++) { 
            if(line[i] != currentDomain[i]) {
                    domainMatched = false;
            }
        }

        if(domainMatched!=false) {
                z++; //could be issues with it counting the first one too
        }

            domainMatched = true;   
    }

    //now the issue is if it hits new domain, it needs to scan whole file before that - could turn it into a function

    fclose(domainListFileCount);

    return z;
}

void printDomainNum(char* currentDomain) 
{
    printf("\n\n");
    printf(currentDomain);
    printf(":");
    printf("%d", domainCounter(currentDomain));
    printf("\n");
}

int main (int argc, char *argv[])
{   
    int lineCount = 0;
    //----------------------------------- File Line Counter ------------------------------------//
    domainListFile = fopen(domainList, "r");

    if (domainListFile == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    while (fgets(line, 100, domainListFile)) {   
        lineCount++; //counts number of lines in file for later parsing
    }

    fclose(domainListFile);  //could go back to the top instead!




    //----------------------------------- Dupe Checker ------------------------------------//
    char* domainSet[lineCount] ; //ensures that there are enough fields, even if everything is unique, possible off by one
    //memset(domainSet, "VOID", sizeof(domainSet)); //not properly setting as void, as it takes error messages as domains!
    int a;
    for (a=0;a>=7;a++) {
        domainSet[1] = "VOID";
    }

    bool newDomain = true;

    domainListFile = fopen(domainList, "r");

    strcpy(currentDomain, fgets(line, 100, domainListFile));
    domainSet[0] = line;
    int domIndex=0;
    int emptyIndex= lineCount/lineCount; //means empty files are handled

    while (fgets(line, 100, domainListFile)) { //a search through each line to find new domains
        for(domIndex=0; domIndex<lineCount; ++domIndex) { //for each potential domain array entry
            if(domainSet[domIndex]!="VOID") { //if not empty
                if(line != domainSet[domIndex]) { //if the line and current box are different 
                    newDomain = true;
                    //I have the problem of stuff being new in the future?     
                }
                else {
                    newDomain = false;
                }
            }
            else {
                emptyIndex++;
            }
            
        } 
        
        
        //when it gets through all boxes, if nothing is new, nothing happens, if it is, it is parsed and added - problems could arise if data is changed after the fact

        if(newDomain == true) {     //if still true after all the domain boxes are matched against.  
            if(domainSet[emptyIndex]==("\0")) {
                strcpy(currentDomain, line);      //make secure, memcopy etc..
                domainSet[emptyIndex] = line;
                printDomainNum(currentDomain);
                
            } 
            newDomain = false;   
        } 
    }

    fclose(domainListFile);

    return 0;
}