#include <stdio.h>          // Standard I/O functions (printf, scanf, etc.)
#include <stdlib.h>         // Standard library functions (exit, malloc, etc.)
#include <string.h>         // String manipulation functions (strcpy, strcmp, etc.)
#include <unistd.h>         // POSIX API (close, read, write, etc.)
#include <arpa/inet.h>      // Functions for handling Internet addresses (inet_addr, htons, etc.)
#include <openssl/md5.h>    // OpenSSL library for computing MD5 hash
#include "udp_file_transfer.h" // Custom header for handling UDP file transfers
#include "encrypt.h"        // Custom encryption header
#define MAX_INPUT_SIZE 256  // Define the maximum input size

// Helper function to compute the MD5 hash of a given buffer and return a 32-character hex string.
void compute_md5(const unsigned char *data, size_t len, char *md5_str) {
    unsigned char md[MD5_DIGEST_LENGTH];  // Buffer to store the MD5 hash
    MD5(data, len, md);  // Compute the MD5 hash of the data
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_str[i * 2], "%02x", md[i]);  // Convert hash to hexadecimal format
    }
    md5_str[32] = '\0';  // Null-terminate the MD5 string
}

int main() {
    int sockfd;  // File descriptor for the UDP socket
    struct sockaddr_in server_addr; // Structure to hold server address
    Packet packet;  // Structure to store data packets
    char buffer[100];  // Buffer for ACK messages
    socklen_t addr_len = sizeof(server_addr); // Size of server address structure
    int choice;  // Variable to store user choice from menu
    char filename[100];  // Variable to store the filename entered by user

    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed"); // Print error if socket creation fails
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr)); // Zero out the structure
    server_addr.sin_family = AF_INET;  // Use IPv4 address family
    server_addr.sin_port = htons(SERVER_PORT);  // Set the server port (convert to network byte order)
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Set server IP address

    // Display menu options for the user
    printf("Select operation:\n");
    printf("1) Download (Read) file\n");
    printf("2) Upload (Write) file\n");
    printf("3) Delete file\n");
    printf("4) Recover file\n");
    printf("Enter your choice: ");
    
    // Read user input
    if (scanf("%d", &choice) != 1) {  
        fprintf(stderr, "Invalid input.\n"); // Print error if input is invalid
        close(sockfd);  // Close socket before exiting
        exit(EXIT_FAILURE);
    }
    getchar();  // Consume newline character left by scanf

    memset(&packet, 0, sizeof(packet)); // Initialize packet structure to zero

    if (choice == 1) {  // Download (Read)
        packet.op_code = OP_READ;  // Set operation code for reading
        printf("Enter filename to download: ");
        fgets(filename, sizeof(filename), stdin); // Get filename from user
        filename[strcspn(filename, "\n")] = '\0'; // Remove newline character
        strncpy(packet.filename, filename, sizeof(packet.filename)); // Copy filename to packet
        
        // Send read request to server
        if (sendto(sockfd, &packet, sizeof(packet), 0,
                   (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Error sending read request");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        char localFilename[120]; // Variable for the downloaded file's name
        snprintf(localFilename, sizeof(localFilename), "downloaded_%s", filename); // Format filename
        FILE *fp = fopen(localFilename, "wb"); // Open file for writing
        if (fp == NULL) {
            perror("Error opening local file for writing");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        int expected_seq = 0;  // Expected sequence number for packets
        while (1) {
            Packet recvPacket;  // Structure to receive packet
            int n = recvfrom(sockfd, &recvPacket, sizeof(recvPacket), 0,
                             (struct sockaddr *)&server_addr, &addr_len);
            if (n < 0) {
                perror("Error receiving file packet");
                fclose(fp);
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            // Check for out-of-order packets
            if (recvPacket.seq_no != expected_seq) {
                printf("Out-of-order packet (expected %d, got %d). Ignoring.\n",
                       expected_seq, recvPacket.seq_no);
                continue;
            }

            unsigned char plaintext_buf[BUFFER_SIZE * 2];  // Buffer for decrypted data
            int plaintext_len = decrypt_data((unsigned char*)recvPacket.data,
                                             recvPacket.data_len, aes_key, aes_iv,
                                             plaintext_buf);  // Decrypt received data
            if (plaintext_len < 0) {
                fprintf(stderr, "Decryption failed for packet %d\n", expected_seq);
                fclose(fp);
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            fwrite(plaintext_buf, 1, plaintext_len, fp); // Write decrypted data to file
            sprintf(buffer, "ACK:%d", expected_seq); // Format ACK message
            if (sendto(sockfd, buffer, strlen(buffer) + 1, 0,
                       (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Error sending ACK");
            }
            expected_seq++;  // Increment expected sequence number
            if (recvPacket.eof) // If EOF flag is set, stop receiving
                break;
        }
        fclose(fp); // Close file
        printf("File '%s' downloaded successfully as '%s'.\n", filename, localFilename);
    }
    
    else if (choice == 2) {  // Upload (Write)
        packet.op_code = OP_WRITE;  // Set operation code for writing
        printf("Enter filename to upload: ");
        fgets(filename, sizeof(filename), stdin);  // Get filename from user
        filename[strcspn(filename, "\n")] = '\0';  // Remove newline character
        strncpy(packet.filename, filename, sizeof(packet.filename));  // Copy filename to packet
    
        FILE *fp = fopen(filename, "rb");  // Open file for reading
        if (fp == NULL) {
            perror("Error opening file for reading");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        int seq_no = 0;  // Initialize sequence number
        while (1) {
            unsigned char plaintext_buf[BUFFER_SIZE];  // Buffer for reading file
            unsigned char ciphertext_buf[BUFFER_SIZE * 2];  // Buffer for encrypted data
            size_t bytes_read = fread(plaintext_buf, 1, BUFFER_SIZE, fp);  // Read file
            if (bytes_read < 0) {
                perror("Error reading file");
                fclose(fp);
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            int ciphertext_len = encrypt_data(plaintext_buf, bytes_read, aes_key, aes_iv, ciphertext_buf);  // Encrypt data
            if (ciphertext_len < 0) {
                fprintf(stderr, "Encryption failed\n");
                fclose(fp);
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            memset(&packet, 0, sizeof(packet));  // Clear packet structure
            packet.op_code = OP_WRITE;  // Set operation code
            strncpy(packet.filename, filename, sizeof(packet.filename));  // Copy filename
            packet.seq_no = seq_no;  // Set sequence number
            memcpy(packet.data, ciphertext_buf, ciphertext_len);  // Copy encrypted data
            packet.data_len = ciphertext_len;  // Set data length

            compute_md5((unsigned char*)packet.data, packet.data_len, packet.md5);  // Compute MD5 hash for verification

            if (bytes_read < BUFFER_SIZE) {  // If end of file is reached, set EOF flag
                packet.eof = 1;
            } else {
                packet.eof = 0;
            }

            if (sendto(sockfd, &packet, sizeof(packet), 0,
                       (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Error sending packet");
                fclose(fp);
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            seq_no++;  // Increment sequence number
            if (packet.eof)
                break;
        }
        fclose(fp);  // Close file
        printf("File '%s' uploaded successfully.\n", filename);
    }

    close(sockfd);  // Close socket
    return 0;  // Exit program
}
