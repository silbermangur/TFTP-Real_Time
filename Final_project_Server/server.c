#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include "udp_file_transfer.h"
#include "encrypt.h"
#include <sys/stat.h>
#include <sys/types.h>

void recover_file(const char *filename) {
    char backup_filename[256];
    char recovery_filename[256];
    snprintf(backup_filename, sizeof(backup_filename), "backup/%s", filename);
    snprintf(recovery_filename, sizeof(recovery_filename), "%s", filename);

    FILE *src = fopen(backup_filename, "rb");
    if (!src) {
        perror("Error opening backup file for recovery");
        return;
    }
    FILE *dest = fopen(recovery_filename, "wb");
    if (!dest) {
        perror("Error opening destination file for recovery");
        fclose(src);
        return;
    }

    char buf[1024];
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), src)) > 0) {
        fwrite(buf, 1, bytes, dest);
    }

    fclose(src);
    fclose(dest);
    printf("Recovered file '%s' from backup.\n", filename);
}


void backup_file(const char *filename) {
    // Create backup directory if it doesn't exist
    struct stat st = {0};
    if (stat("backup", &st) == -1) {
        if (mkdir("backup", 0755) < 0) {
            perror("Error creating backup directory");
            return;
        }
    }
    
    char backup_filename[256];
    snprintf(backup_filename, sizeof(backup_filename), "backup/%s", filename);
    
    FILE *src = fopen(filename, "rb");
    if (!src) {
        perror("Error opening source file for backup");
        return;
    }
    FILE *dest = fopen(backup_filename, "wb");
    if (!dest) {
        perror("Error opening backup file for writing");
        fclose(src);
        return;
    }
    
    char buf[1024];
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), src)) > 0) {
        fwrite(buf, 1, bytes, dest);
    }
    
    fclose(src);
    fclose(dest);
    printf("Backup of '%s' stored as '%s'.\n", filename, backup_filename);
}

// Helper: Compute MD5 hash for a data buffer.
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
    char ack_msg[20];
    socklen_t addr_len = sizeof(client_addr);

    // Create UDP socket.
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket.
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Server is running on port %d\n", SERVER_PORT);

    // For multi-packet uploads, we assume a single transfer at a time.
    FILE *upload_fp = NULL;
    int expected_seq = 0;

    while (1) {
        int n = recvfrom(sockfd, &packet, sizeof(packet), 0,
                         (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("Error receiving packet");
            continue;
        }
        printf("Received packet (op: %d, file: %s, seq: %d, eof: %d)\n",
               packet.op_code, packet.filename, packet.seq_no, packet.eof);

               if (packet.op_code == OP_WRITE) {
                if (packet.seq_no == 0) {
                    upload_fp = fopen(packet.filename, "wb");
                    if (upload_fp == NULL) {
                        perror("Error opening file for writing");
                        continue;
                    }
                    expected_seq = 0;
                }
                if (packet.seq_no == expected_seq) {
                    unsigned char plaintext_buf[BUFFER_SIZE*2];
                    int plaintext_len = decrypt_data((unsigned char*)packet.data,
                                                     packet.data_len, aes_key, aes_iv,
                                                     plaintext_buf);
                    if (plaintext_len < 0) {
                        fprintf(stderr, "Decryption failed for packet %d\n", expected_seq);
                        continue;
                    }
                    
                    fwrite(plaintext_buf, 1, plaintext_len, upload_fp);
                    sprintf(ack_msg, "ACK:%d", expected_seq);
                    sendto(sockfd, ack_msg, strlen(ack_msg) + 1, 0,
                           (struct sockaddr *)&client_addr, addr_len);
                    expected_seq++;
                    if (packet.eof) {
                        fclose(upload_fp);
                        printf("Completed receiving file '%s'.\n", packet.filename);
                         // After successful upload, create a backup copy.
                        backup_file(packet.filename);
                    }
                } else {
                    sprintf(ack_msg, "ACK:%d", expected_seq - 1);
                    sendto(sockfd, ack_msg, strlen(ack_msg) + 1, 0,
                           (struct sockaddr *)&client_addr, addr_len);
                }
            }
            else if (packet.op_code == OP_RECOVER) {
                printf("Received recovery request for file '%s'\n", packet.filename);
                // Attempt to recover the file from backup
                recover_file(packet.filename);
                char recoverAck[] = "RECOVER_SUCCESS";
                sendto(sockfd, recoverAck, strlen(recoverAck)+1, 0,
                       (struct sockaddr *)&client_addr, addr_len);
            }
            
            
            else if (packet.op_code == OP_READ) {
                printf("Processing read request for file '%s'\n", packet.filename);
                FILE *fp = fopen(packet.filename, "rb");
                if (fp == NULL) {
                    // File not found in main directory; attempt recovery from backup.
                    printf("File '%s' not found in main directory. Checking backup folder...\n", packet.filename);
                    recover_file(packet.filename);  // This function should copy from "backup/filename" to "filename"
                    // Try opening the file again.
                    fp = fopen(packet.filename, "rb");
                    if (fp == NULL) {
                        perror("Error opening file for reading even after backup recovery");
                        // Send an error packet to the client.
                        Packet errPacket;
                        memset(&errPacket, 0, sizeof(errPacket));
                        errPacket.op_code = OP_READ;
                        strcpy(errPacket.data, "Error: File not found.");
                        errPacket.data_len = strlen(errPacket.data);
                        sendto(sockfd, &errPacket, sizeof(errPacket), 0,
                               (struct sockaddr *)&client_addr, addr_len);
                        continue;
                    }
                }
                
                // At this point, fp is valid.
                int seq_no = 0;
                while (1) {
                    Packet sendPacket;
                    memset(&sendPacket, 0, sizeof(sendPacket));
                    sendPacket.op_code = OP_READ;
                    strncpy(sendPacket.filename, packet.filename, sizeof(sendPacket.filename));
                    sendPacket.seq_no = seq_no;
            
                    unsigned char plaintext_buf[BUFFER_SIZE];
                    unsigned char ciphertext_buf[BUFFER_SIZE*2];
                    size_t bytes_read = fread(plaintext_buf, 1, BUFFER_SIZE, fp);
                    // Encrypt the plaintext chunk.
                    int ciphertext_len = encrypt_data(plaintext_buf, bytes_read,
                                                      aes_key, aes_iv, ciphertext_buf);
                    if (ciphertext_len < 0) {
                        fprintf(stderr, "Encryption failed\n");
                        break;
                    }
                    memcpy(sendPacket.data, ciphertext_buf, ciphertext_len);
                    sendPacket.data_len = ciphertext_len;
                    if (bytes_read < BUFFER_SIZE)
                        sendPacket.eof = 1;
                    else {
                        int c = fgetc(fp);
                        if (c == EOF) {
                            sendPacket.eof = 1;
                        } else {
                            ungetc(c, fp);
                            sendPacket.eof = 0;
                        }
                    }
                    compute_md5((unsigned char*)sendPacket.data, sendPacket.data_len, sendPacket.md5);
                    if (sendto(sockfd, &sendPacket, sizeof(sendPacket), 0,
                               (struct sockaddr *)&client_addr, addr_len) < 0) {
                        perror("Error sending packet");
                        break;
                    }
                    char ack_buf[20];
                    int n = recvfrom(sockfd, ack_buf, sizeof(ack_buf), 0,
                                     (struct sockaddr *)&client_addr, &addr_len);
                    if (n < 0) {
                        perror("Error receiving ACK");
                        break;
                    }
                    ack_buf[n] = '\0';
                    int ack_seq;
                    if (sscanf(ack_buf, "ACK:%d", &ack_seq) != 1 || ack_seq != seq_no) {
                        printf("Incorrect ACK: %s. Resending packet %d.\n", ack_buf, seq_no);
                        continue;
                    }
                    seq_no++;
                    if (sendPacket.eof)
                        break;
                }
                fclose(fp);
                printf("Completed sending file '%s'.\n", packet.filename);
            }
            
        else if (packet.op_code == OP_DELETE) {
            printf("Received delete request for file '%s'\n", packet.filename);
            if (remove(packet.filename) == 0) {
                printf("File '%s' deleted successfully.\n", packet.filename);
                char deleteAck[] = "DELETE_SUCCESS";
                sendto(sockfd, deleteAck, strlen(deleteAck)+1, 0,
                       (struct sockaddr *)&client_addr, addr_len);
            } else {
                perror("Error deleting file");
                char deleteAck[] = "DELETE_FAILED";
                sendto(sockfd, deleteAck, strlen(deleteAck)+1, 0,
                       (struct sockaddr *)&client_addr, addr_len);
            }
        }
    }

    close(sockfd);
    return 0;
}
