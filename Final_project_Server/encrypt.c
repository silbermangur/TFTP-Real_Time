#include <openssl/evp.h>  // Include OpenSSL EVP (Encryption and Decryption) library
#include "encrypt.h"      // Include custom header file for encryption functions
#include <stdio.h>        // Include standard I/O library for debugging output

// Define AES encryption key (16 bytes for AES-128)
const unsigned char aes_key[16] = "0123456789abcdef"; 

// Define AES initialization vector (IV) (16 bytes)
const unsigned char aes_iv[16]  = "abcdef9876543210"; 

// Function to encrypt data using AES-128 in CTR mode
int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;  // Pointer to OpenSSL cipher context
    int len;  // Variable to store the length of processed data
    int ciphertext_len;  // Variable to store total ciphertext length

    // Create and initialize the encryption context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed"); // Print error if creation fails
        return -1;  // Return error code
    }

    // Initialize encryption operation with AES-128 in CTR mode
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        perror("EVP_EncryptInit_ex failed"); // Print error if initialization fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }

    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("EVP_EncryptUpdate failed"); // Print error if encryption fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }
    ciphertext_len = len;  // Store the number of bytes encrypted so far

    // Finalize encryption (handle any remaining bytes)
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        perror("EVP_EncryptFinal_ex failed"); // Print error if finalization fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }
    ciphertext_len += len;  // Add any additional bytes encrypted in finalization

    // Debug print for encryption result
    printf("Encryption complete: plaintext_len=%d, ciphertext_len=%d\n", plaintext_len, ciphertext_len);
    printf("Ciphertext (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]); // Print each byte of ciphertext in hexadecimal format
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx); // Free cipher context

    return ciphertext_len; // Return total ciphertext length
}

// Function to decrypt data using AES-128 in CTR mode
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;  // Pointer to OpenSSL cipher context
    int len;  // Variable to store the length of processed data
    int plaintext_len;  // Variable to store total plaintext length

    // Create and initialize the decryption context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed"); // Print error if creation fails
        return -1;  // Return error code
    }

    // Initialize decryption operation with AES-128 in CTR mode
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        perror("EVP_DecryptInit_ex failed"); // Print error if initialization fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        perror("EVP_DecryptUpdate failed"); // Print error if decryption fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }
    plaintext_len = len;  // Store the number of bytes decrypted so far

    // Finalize decryption (handle any remaining bytes)
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        perror("EVP_DecryptFinal_ex failed"); // Print error if finalization fails
        EVP_CIPHER_CTX_free(ctx); // Free cipher context
        return -1;
    }
    plaintext_len += len;  // Add any additional bytes decrypted in finalization

    // Debug print for decryption result
    printf("Decryption complete: ciphertext_len=%d, plaintext_len=%d\n", ciphertext_len, plaintext_len);
    printf("Decrypted plaintext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%c", plaintext[i]); // Print each character of the decrypted text
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx); // Free cipher context

    return plaintext_len; // Return total plaintext length
}
