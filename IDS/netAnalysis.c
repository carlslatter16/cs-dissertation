#include <stdio.h>
#include <stdlib.h>
#include <regex.h> 

int main (int argc, char *argv[])
{
    int z = 0;
    char line[100];
    char subdomain[50];
    FILE *f = fopen("file.txt", "r");

    if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    while( fgets(line, 100, f) != NULL ) {
        int i;
        
        for (i = 0; line[i] != '\0'; i++) {
            if(line[i]!=46) {
                printf("%c", line[i]);
                //subdomain[z] = line[i];
                //z=z+1;

            }
            else {
                //z = 0;
                break;
            }
            
            //printf(subdomain);
            //subdomain[0] = "\0";
            
            
        }
        printf("%c", '\n');
        //fix dupe cocat of my subdomains!
    }
      
    fclose(f);
}