#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "sdns.h"

// based on:
// http://www.binarytides.com/dns-query-code-in-c-with-winsock/

// convert the host name to a DNS domain format
//this will convert www.google.com to 3www6google3com0
void hostToDomain(unsigned char *host, unsigned char *domain)
{
    int i = 0;
    char *pch;
    int pchlen;

    // adding a dot in the end
    strcat((char *)host,".");

    // splitting the string by tokens of '.'
    pch = strtok(host, ".");
    while (pch != NULL)
    {
        // getting the size of the split
        pchlen = strlen(pch);
        // inserting the counting of split in the domain var
        domain[i] = pchlen;
        // next position
        i++;
        // copying the spli to the domain var
        strncpy(&domain[i], pch, pchlen);
        // looking for the next dot position
        i += pchlen;
        // pointing to the next dot
        pch = strtok (NULL, ".");
    }

    domain[strlen(domain)] = '\0';
}

// converto from domain format to host
void domainToHost(unsigned char *domain, unsigned char *host)
{
    unsigned char *pd;

    // point to the first count
    pd = domain;
    
    while (pd[0] != '\0')
    {
        strncat(host, pd+1, pd[0]);
        
        // adding the dot
        strcat(host, ".");

        // pointing to the next count
        pd += pd[0]+1;
    }
    
    // removing the final dot
    host[strlen(host)-1] = '\0';
}

// 
unsigned char *readName(unsigned char *reader, unsigned char *buf, int *move)
{
    // calculate the pointer of the compressed byte
    int offset;

    // boolean test if there is a jump by compression
    int jump = 0;

    // cleaning the move
    *move = 0;

    // temp
    unsigned char *tmp = malloc(256);
    unsigned char *ret;// = malloc(256);
    
    // reading the consecutive bytes
    while(*reader != 0x0)
    {
        // checking if the first 2 bits is set to 11
        // in case of compression
        if ( (*reader & 0xc0) == 0xc0) // 0b11000000
        {
            // removing the 2 first bits
            offset = *reader & 0x3f; // 0b00111111
            // positioning the offset and adding the 2nd byte of the jump
            offset = (offset << 8) | *(reader+1);

            // jumping the reader pointer to the buffer position of the jump
            reader = buf+offset;
        
            // there was a jump in the domain name
            jump = 1;
        }
        
        // in the case there is not compression
        if(!jump)
        {
            *move += 1;
        }

        // copying each character
        strncat(tmp, reader, 1);
    
        // moving the reader
        reader += 1;
    }

    // move only the 2 bytes of the jump to address
    if (jump)
    {
        *move += 2;
    }
    
    // preparing the memory area to store the converted hostname
    ret = malloc(strlen(tmp));
      
    // convert the domain to hostname
    domainToHost(tmp, ret);

    return ret;
}

// Preparing the UDP connection to the server
// Returns the socket file descriptor
int settingServer(unsigned char *server, struct sockaddr_in *dest)
{
    // the socket file descriptor
    int sockfd;

    // creating the socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // setting the DNS Server infos
    dest->sin_family = AF_INET;
    dest->sin_addr.s_addr = inet_addr(server);
    dest->sin_port = htons(53);
    memset(&(dest->sin_zero), '\0', sizeof(dest->sin_zero));

    return sockfd;
}

// Filling the fields of the packet to a DNS Type A Request
// Returns the buf (by reference) and its length by return
int settingRequestA(unsigned char *host, unsigned char *buf)
{
    // setting up the question fields
    HEADER      *dns;
    QUESTION    *q;

    // always need a first number
    unsigned char *domain = malloc(strlen(host)+2);
    
    // converting the hostname to DNS domain format
    hostToDomain(host, domain);
    
    // the size of message to send:
    // HEADER + strlen(domain)+1 + QUESTION
     
    // filling the HEADER fields
    // point to the HEADER portion
    dns = (HEADER *)buf;
    dns->id = (unsigned short)getpid(); // Random value
    dns->qr = 0;                // This is a query
    dns->opcode = 0;            // This is a standard query
    dns->aa = 0;                // Not Authoritative
    dns->tc = 0;                // This message is not truncated
    dns->rd = 1;                // Recursion Desired
    dns->ra = 0;                // Recursion not available!
    dns->z  = 0;                // Not used
    dns->ad = 0;                // Authenticated data
    dns->cd = 0;                // Checking disabled
    dns->rcode = 0;             // Response code
    dns->qdcount = htons(1);    // We have only 1 question
    dns->ancount = 0;           // Don't have answer
    dns->nscount = 0;           // Don't have authority records
    dns->arcount = 0;           // Don't have additional records
    
    // filling the domain field
    // pointing to the qname portion
    qname = (unsigned char *)(buf + (sizeof(HEADER)));
    strncpy(qname, domain, strlen(domain)+1);
    
    // pointing to the QUESTION portion
    q = (QUESTION *)(buf + sizeof(HEADER) + strlen(domain)+1);
    q->qtype  = htons(TYPE_A);  // Requesting the ipv4 address
    q->qclass = htons(1);       // Class internet

    return (sizeof(HEADER) + strlen(domain)+1 + sizeof(QUESTION));
}

// Send the DNS packet passed in buf argument
int sendDNSPacket(int sockfd, struct sockaddr_in dest, unsigned char *buf, int buflen)
{
    // sending packet
    int err = sendto(
            sockfd, 
            (void *)buf, 
            buflen, //sizeof(HEADER) + strlen(domain)+1 + sizeof(QUESTION),
            0,
            (struct sockaddr*)&dest,
            sizeof(dest)
            );
    
    return err;
}

// Receive the response of the server to the DNS request
int recvDNSPacket(int sockfd, struct sockaddr_in dest, 
        unsigned char *buf, int *dest_len)
{
    // cleaning up the buffer
    memset(buf, 0, BUFSIZE);

    int err = recvfrom(
            sockfd, 
            (char *)buf, 
            BUFSIZE, 
            0, 
            (struct sockaddr *)&dest,
            dest_len //&dest_len
            );

    return err;
}

// Extracting the answers of the received buffer
// Returns the number of answers
int gettingAnswers(unsigned char *buf, RR *answers, int questionlen)
{
    HEADER      *dns;
    QUESTION    *q;
    
    // pointing to the HEADER portion of the response
    dns = (HEADER *)buf;

    //printf("The response contains: \n");
    //printf("%d Questions\n",ntohs(dns->qdcount));
    //printf("%d Answers\n",ntohs(dns->ancount));
    //printf("%d Authoritative Servers\n",ntohs(dns->nscount));
    //printf("%d Additional records\n\n",ntohs(dns->arcount));

    // Getting the Resource Records

    // pointer to the resource records
    // - first to answer
    // - second to authoritative servers
    // - third to additional records
    unsigned char *reader;

    // to store the host converted from domain
    unsigned char *qhost;

    // moving to the position next the HEADER and QUESTION fields
    reader = buf + questionlen;
        //sizeof(HEADER) + strlen(domain)+1 + sizeof(QUESTION);

    int move = 0;

    int i;
    for(i = 0; i < ntohs(dns->ancount); i++)
    {
        // getting the first field of the answer (name)
        answers[i].name = readName(reader, buf, &move);

        // pointing to the next fields of answer
        reader += move;
        // getting the next fields of the answer (RR_SIZE)
        answers[i].res = (RR_SIZE *)reader;

        //printf("type: %x\n", ntohs(answers[i].res->type));
        //printf("class: %x\n", ntohs(answers[i].res->class));
        //printf("ttl: %x\n", ntohl(answers[i].res->ttl));
        //printf("rdlength: %x\n", ntohs(answers[i].res->rdlength));

        // pointing after the RR_SIZE, to rdata
        reader += sizeof(RR_SIZE);

        // getting the next field (rdata)
        // preparing the memory to store the rdata
        answers[i].rdata = malloc(ntohs(answers[i].res->rdlength)+1);

        if (ntohs(answers[i].res->type) == TYPE_A )
        {
            // copying the bytes of rdata
            strncpy(answers[i].rdata, reader, ntohs(answers[i].res->rdlength));
            // setting the last byte of rdata
            answers[i].rdata[ntohs(answers[i].res->rdlength)] = '\0';

        }
        else
        {
            //printf("veio type %d\n",ntohs(answers[i].res->type));
            answers[i].rdata = readName(reader, buf, &move);
        }

        // pointing to the next i answer, after rdata
        reader += ntohs(answers[i].res->rdlength);
        //reader += move;
    }

    // return the number of answers
    return ntohs(dns->ancount);

}

// Send a request to resolve the host name in the defined server
void sdns_getA(unsigned char *host, unsigned char *server, 
        unsigned char ip[][16])
{
    // TODO: try to improve this with malloc
    // Preparing Resource Records
    RR answers[20];

    // destination of the message (DNS server)
    struct sockaddr_in dest;
    
    // setting the server informations
    int sockfd = 0;
    
    sockfd = settingServer(server, &dest);
    
    // creating the memory space for the Question message
    unsigned char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);

    // filling the request packet
    int buflen = settingRequestA(host, buf);

    // send the request packet to the server
    if ( sendDNSPacket(sockfd, dest, buf, buflen) == -1 )
    {
        printf("Error on sending packet!\n");
    }
    
    // length of the received packet
    int dest_len;

    // receving the response of the server
    if ( recvDNSPacket(sockfd, dest, buf, &dest_len) == -1 )
    {
        printf("Error on receving the response packet!\n");
    }

    // extracting the answers of the received buffer
    int ansnum = gettingAnswers(buf, answers, buflen);

    int i, j;
    char tmp[3];

    for(i = 0; i < ansnum; i++)
    {
        for(j = 0; j < 4; j++)
        {
            sprintf(tmp, "%d", answers[i].rdata[j]);
            strcat(ip[i], tmp);
            strcat(ip[i], ".");
        }

        ip[i][strlen(ip[i])-1] = '\0';

    }

    // TODO: do the same as the answers to the authoritative servers and
    // additional records

    // closing the socket
    close(sockfd);
}
