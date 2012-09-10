#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// simple dns library
#include "sdns.h"

int main(int argc, char **argv)
{
    // the hostname to search (google.com)
    unsigned char hostname[50];

    // to get the returned IP
    unsigned char ip[10][16];

    // zeroing all the positions to return
    memset(ip, '\0', 10*16);

    // the DNS server to request
    unsigned char server[50];
    
    if (argc == 3)
    {
        // getting the hostname to convert
        strncpy(hostname, argv[1], 50);

        // getting the DNS server
        strncpy(server, argv[2], 50);

        printf("Resolving this:\n");
        printf("Hostname: %s (%d)\n",hostname,strlen(hostname));
        printf("Server: %s (%d)\n",server,strlen(server));

        // getting the IP (Type A)
        sdns_getA(hostname, server, ip);

        int i = 0;
        while( strcmp(ip[i],"\0") )
        {
            printf("%s\n",ip[i]);
            i++;
        }
            
    }
    else
    {
        printf("Usage: %s host server\n",argv[0]);
    }

    return 0;
}
