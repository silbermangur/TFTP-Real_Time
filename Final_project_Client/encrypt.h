#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/evp.h>
#include <stdio.h>

extern const unsigned char aes_key[16];
extern const unsigned char aes_iv[16];

int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *ciphertext);

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *plaintext);

#endif // ENCRYPT_H
