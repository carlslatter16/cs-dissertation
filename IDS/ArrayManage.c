#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>

char* array[20];
bool firstRun = true;

int insertElement(char* stringToAdd, int size)
{
    int x=0;
    bool newValue;
    int emptyIndex;


    //https://stackoverflow.com/questions/2427336/why-cant-i-create-an-array-with-size-determined-by-a-global-variable
    //finds size based on overall size of the array, and then by a sample element
    
    if(firstRun==true) {
        array[0] = stringToAdd; //could me moved to main
        firstRun=false;
    }

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
        return 1;  
    }

    return 0;
}

int main (int argc, char *argv[]) 
{   
    int size = sizeof(array) / sizeof(array[0]);
    char* currentString = "Pokemon";
    int z;
    
    for(z=0;z<size;++z)
    {
        array[z] = "\0";
    }

    insertElement(currentString, size);
    currentString = "Pikachu";
    insertElement(currentString, size);
    insertElement(currentString, size);
    currentString = "Eevee";
    insertElement(currentString, size);

    int p;

    for(p=0;p<=size;++p) {
        if(array[p]!=NULL) {
            printf("%s", array[p]); //hard to print
        }
    }
    return 0;
}