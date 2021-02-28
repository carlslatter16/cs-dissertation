#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>

char* array[20];
bool firstRun = true;
int size = sizeof(array) / sizeof(array[0]);

int insertElement(char currentString[]) 
{
    int x=0;
    int z=0;
    bool newValue;
    int emptyIndex;

     
    //https://stackoverflow.com/questions/2427336/why-cant-i-create-an-array-with-size-determined-by-a-global-variable
    //finds size based on overall size of the array, and then by a sample element

    if(firstRun==true) {
        array[0] = currentString;
        firstRun=false;
    }

    for(z=0;z<size;++z)
    {
        array[z] = "\0";
    }

    for(x=0;x<size;++x) {
        if(array[x]!="\0") {
            if(array[x]!=currentString) {
                newValue=true;
            }
            
        }
        else{
            emptyIndex=x;
            break;
        }
    }

    if(newValue==true) {
        array[emptyIndex] = currentString;
        newValue=false;
        return 1;  
    }
}

int main (int argc, char *argv[]) 
{   
    if(insertElement("pokemon")==1) {
        if(insertElement("pikachu")==1) {
            if(insertElement("ash")==1) {
                return 1;
            }
        }
    }

    int p;

    for(p=0;p<=size;++p) {
        printf("%s",array[p]); //hard to print
    }

    return 0;
}