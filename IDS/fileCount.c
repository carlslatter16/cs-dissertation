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

int insertElement(char* stringToAdd, int size, char* array)
{
    int x=0;
    bool newValue;
    int emptyIndex=NULL;


    //https://stackoverflow.com/questions/2427336/why-cant-i-create-an-array-with-size-determined-by-a-global-variable
    //finds size based on overall size of the array, and then by a sample element

    for(x=0;x<size;++x) {
        if(array[x]!="\0") {
            if(array[x]!=stringToAdd) {
                newValue=true;
            }
            else {
                newValue=false;
            }
        }
        else{
            emptyIndex=x;
            break;
        }
    }

    if(newValue!=false) {
        array[emptyIndex] = stringToAdd;
        newValue=NULL;
        return 0;  
    }

    return 1;
}

int lineCounter()
{
    //----------------------------------- File Line Counter ------------------------------------//
    domainListFile = fopen(domainList, "r");

    int lineCount;

    if (domainListFile == NULL) {
        printf("Error opening file!\n");
        return 1;
    }

    while (fgets(line, 100, domainListFile)) {   
        lineCount++; //counts number of lines in file for later parsing
    }

    fclose(domainListFile);  //could go back to the top instead!

    return lineCount;
}

int main (int argc, char *argv[])
{   
    int lineCount = 0;
    char* array[lineCounter()]; //ensures that there are enough fields, even if everything is unique, possible off by one
    int size = sizeof(array) / sizeof(array[0]);
    
    for(z=0;z<size;++z)
    {
        array[z] = "\0";
    }

    //----------------------------------- Dupe Checker ------------------------------------//
    char* domainSet[lineCount] ; 
    domainListFile = fopen(domainList, "r");
    strcpy(currentDomain, fgets(line, 100, domainListFile));
    array[0] = currentDomain;

    while (fgets(line, 100, domainListFile)) { //a search through each line to find new domains
        insertElement(line, size, array);
        //when it gets through all boxes, if nothing is new, nothing happens, if it is, it is parsed and added - problems could arise if data is changed after the fact
    }

    int p;

    for(p=0;p<=size;++p) {
        if(array[p]!=NULL) {
            printDomainNum(array[p]);
        }
    }

    fclose(domainListFile);

    return 0;
}