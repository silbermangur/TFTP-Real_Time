#ifndef UDP_FILE_TRANSFER_H
#define UDP_FILE_TRANSFER_H

#define SERVER_PORT 6900
#define BUFFER_SIZE 512

// Operation codes
#define OP_READ  1   // Download request
#define OP_WRITE 2   // Upload request
#define OP_DELETE 3  // Delete request
#define OP_RECOVER 4  // Recover request

#pragma pack(push, 1)

// Define the packet structure
typedef struct {
    int op_code;              // Operation (read, write, delete)
    char filename[100];       // Filename (adjust size as needed)
    int seq_no;               // Sequence number for multi-packet transfer
    int eof;                  // End-of-file flag: 1 if this is the last packet, 0 otherwise
    char data[BUFFER_SIZE];   // Data payload
    int data_len;             // Length of the data in the packet
    char md5[33];             // MD5 hash as a hex string (32 chars + null terminator)
} Packet;

#pragma pack(pop)

#endif
