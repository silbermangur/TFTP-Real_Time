#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include "udp_file_transfer.h"

// Helper function to compute MD5 hash for a data buffer
void compute_md5(const unsigned char *data, size_t len, char *md5_str) {
    unsigned char md[MD5_DIGEST_LENGTH];
    MD5(data, len, md);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_str[i*2], "%02x", md[i]);
    }
    md5_str[32] = '\0';
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    Packet packet;
    char ack[] = "ACK";
    socklen_t addr_len = sizeof(client_addr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is running on port %d\n", SERVER_PORT);

    // Main loop to receive and process packets
    while (1) {
        int n = recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("Error receiving packet");
            continue;
        }
        
        // Process packet based on operation code
        printf("Received packet for op code: %d, filename: %s\n", packet.op_code, packet.filename);
        
        if (packet.op_code == OP_WRITE) {
            // For upload: write file and verify integrity
            FILE *fp = fopen(packet.filename, "wb");
            if (fp == NULL) {
                perror("Error opening file for writing");
            } else {
                fwrite(packet.data, 1, packet.data_len, fp);
                fclose(fp);
                printf("File '%s' saved on server.\n", packet.filename);
                // Compute MD5 of received data
                char computed_md5[33];
                compute_md5((unsigned char*)packet.data, packet.data_len, computed_md5);
                if (strcmp(computed_md5, packet.md5) == 0) {
                    printf("File integrity verified for '%s' (MD5: %s)\n", packet.filename, computed_md5);
                    strcpy(ack, "UPLOAD_SUCCESS");
                } else {
                    printf("File integrity check failed for '%s'!\nReceived MD5: %s\nComputed MD5: %s\n", packet.filename, packet.md5, computed_md5);
                    strcpy(ack, "UPLOAD_FAILED");
                }
                // Send ACK with result
                sendto(sockfd, ack, strlen(ack)+1, 0, (struct sockaddr *)&client_addr, addr_len);
            }
        } else if (packet.op_code == OP_READ) {
            printf("Processing read request for file '%s'\n", packet.filename);
            FILE *fp = fopen(packet.filename, "rb");
            if (fp == NULL) {
                perror("Error opening file for reading");
                // Optionally, send an error packet back.
                Packet errPacket;
                memset(&errPacket, 0, sizeof(errPacket));
                errPacket.op_code = OP_READ;
                strncpy(errPacket.filename, packet.filename, sizeof(errPacket.filename));
                errPacket.data_len = 0;
                sendto(sockfd, &errPacket, sizeof(errPacket), 0, (struct sockaddr *)&client_addr, addr_len);
            } else {
                Packet sendPacket;
                memset(&sendPacket, 0, sizeof(sendPacket));
                sendPacket.op_code = OP_READ;
                strncpy(sendPacket.filename, packet.filename, sizeof(sendPacket.filename));
                sendPacket.data_len = fread(sendPacket.data, 1, BUFFER_SIZE, fp);
                // Compute MD5 of the file data
                compute_md5((unsigned char*)sendPacket.data, sendPacket.data_len, sendPacket.md5);
                fclose(fp);
                sendto(sockfd, &sendPacket, sizeof(sendPacket), 0, (struct sockaddr *)&client_addr, addr_len);
                printf("Sent file '%s' to client (%d bytes, MD5: %s).\n", packet.filename, sendPacket.data_len, sendPacket.md5);
            }
        } else if (packet.op_code == OP_DELETE) {
            printf("Received delete request for file '%s'\n", packet.filename);
            if (remove(packet.filename) == 0) {
                printf("File '%s' deleted successfully.\n", packet.filename);
                char deleteAck[] = "DELETE_SUCCESS";
                sendto(sockfd, deleteAck, strlen(deleteAck)+1, 0, (struct sockaddr *)&client_addr, addr_len);
            } else {
                perror("Error deleting file");
                char deleteAck[] = "DELETE_FAILED";
                sendto(sockfd, deleteAck, strlen(deleteAck)+1, 0, (struct sockaddr *)&client_addr, addr_len);
            }
        }
    }

    close(sockfd);
    return 0;
}
