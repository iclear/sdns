#ifndef SDNS_H
#define SDNS_H

// The TYPE values (most used ones):
#define TYPE_A      1   // host address
#define TYPE_NS     2   // authoritative server
#define TYPE_CNAME  5   // canonical name
#define TYPE_SOA    6   // start of authority zone
#define TYPE_PTR    12  // domain name pointer
#define TYPE_MX     15  // mail routing information

#define BUFSIZE     65536


// Defining headers
// According to RFC-1035
    
// we'll define the following packet                \
+---------------------+                             \
|        Header       |                             \
+---------------------+                             \
|       Question      |                             \
+---------------------+                             \
|        Answer       |                             \
+---------------------+                             \
|       Authority     |                             \
+---------------------+                             \
|      Additional     |                             \
+---------------------+             

// Header                                           \
                                1  1  1  1  1  1    \
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5    \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                      ID                       |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                    QDCOUNT                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                    ANCOUNT                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                    NSCOUNT                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                    ARCOUNT                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   

typedef struct
{
    unsigned short id;      // identification number (16 bits)
    // byte inverted by the network big-endianess
    unsigned char rd:1;     // recursion desired
    unsigned char tc:1;     // truncated message
    unsigned char aa:1;     // authoritative answer
    unsigned char opcode:4; // purpose of message
    unsigned char qr:1;     // query(0)/answer(1) flag
    // byte inverted by the network big-endianess
    unsigned char rcode:4;  // response code
    unsigned char cd:1;     // checking disabled (new rfc?)
    unsigned char ad:1;     // authenticated data (new rfc?)
    unsigned char  z:1;     // reserved
    unsigned char ra:1;     // recursion available
    // counts
    unsigned short qdcount; // number of questions
    unsigned short ancount; // number of answers
    unsigned short nscount; // number os authoritaty records
    unsigned short arcount; // number of additional records
} HEADER;

// Question                                         \
                                1  1  1  1  1  1    \
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5    \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                                               |   \
/                     QNAME                     /   \
/                                               /   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                     QTYPE                     |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                     QCLASS                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 

// qname wasn't kept in this structure due to 
// its variable size
unsigned char *qname;
typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

// Resource Record                                  \
                                1  1  1  1  1  1    \
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5    \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                                               |   \
/                                               /   \
/                      NAME                     /   \
|                                               |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                      TYPE                     |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                      CLASS                    |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                       TTL                     |   \
|                                               |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   \
|                    RDLENGTH                   |   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|   \
/                      RDATA                    /   \
/                                               /   \
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   

// name and rdata will be kept apart due to its 
// variable size
#pragma pack(push, 1)
typedef struct
{
    unsigned short type;
    unsigned short class;
    unsigned int ttl;           // 32 bits for time to live
    unsigned short rdlength;
} RR_SIZE;
#pragma pack(pop)

// adding the name and rdata fields
// useful for handling the answer data
typedef struct
{
    unsigned char *name;
    RR_SIZE * res;
    unsigned char *rdata;
} RR;

// returns the IP resolved from host name replied by the server passed
extern void sdns_getA(unsigned char *host, unsigned char *server, 
        unsigned char ip[][16]);

#endif
