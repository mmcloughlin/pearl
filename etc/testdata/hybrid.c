#include <stdio.h>
#include <inttypes.h>

#include "crypto.h"

#define BYTES_PER_LINE 12

void print_bytes(char *name, char *data, int n)
{
    printf("var %s = []byte{\n", name);
    for(int i = 0; i < n; i++) {
        printf("0x%02x, ", (uint8_t)data[i]);
        if((i+1)%BYTES_PER_LINE == 0) {
            printf("\n");
        }
    }
    printf("\n}\n");
}

// int crypto_pk_obsolete_public_hybrid_encrypt(crypto_pk_t *env, char *to,
//                                        size_t tolen,
//                                        const char *from, size_t fromlen,
//                                        int padding, int force);
//
// int crypto_pk_obsolete_private_hybrid_decrypt(crypto_pk_t *env, char *to,
//                                         size_t tolen,
//                                         const char *from, size_t fromlen,
//                                         int padding, int warnOnFailure);


// crypto_pk_private_decrypt(crypto_pk_t *env, char *to,
//                           size_t tolen,
//                           const char *from, size_t fromlen,
//                           int padding, int warnOnFailure)


int main(int argc, char **argv)
{
    crypto_pk_t *pk = NULL;
    char plain[1024], cipher[1024];
    int n = 140;

    // Generate key and save to file
    pk = crypto_pk_new();
    crypto_pk_generate_key(pk);
    crypto_pk_write_private_key_to_filename(pk, "hybrid_private_key");

    // Generate some random plain.
    crypto_rand(plain, 1024);

    // Do the encryption
    int len = crypto_pk_obsolete_public_hybrid_encrypt(
        pk,
        cipher, sizeof(cipher),
        plain, n,
        PK_PKCS1_OAEP_PADDING, 0
    );

    // Output test vector
    print_bytes("plain", plain, n);
    print_bytes("cipher", cipher, len);

    // Decrypt
    char test[1024];
    len = crypto_pk_private_decrypt(pk, test, sizeof(test), cipher, 128, PK_PKCS1_OAEP_PADDING, 1);

    print_bytes("decrypted", test, len);
}
