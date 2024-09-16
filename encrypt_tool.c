#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void file_encrypt_decrypt(const char *input_filename, const char *output_filename, unsigned char *key, unsigned char *iv, int encrypt_mode) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");

    if (!input_file || !output_file) {
        perror("File opening failed");
        return;
    }

    unsigned char buffer[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, inlen;

    while ((inlen = fread(buffer, 1, 1024, input_file)) > 0) {
        if (encrypt_mode) {
            outlen = encrypt(buffer, inlen, key, iv, outbuf);
        } else {
            outlen = decrypt(buffer, inlen, key, iv, outbuf);
        }
        fwrite(outbuf, 1, outlen, output_file);
    }

    fclose(input_file);
    fclose(output_file);
}

void generate_random_key(unsigned char *key, int length) {
    if (RAND_bytes(key, length) != 1) {
        fprintf(stderr, "Error generating random bytes.\n");
        exit(1);
    }
}

void save_key_to_file(const char *filename, unsigned char *key, int length) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("File opening failed");
        exit(1);
    }

    fprintf(file, "\"");
    for (int i = 0; i < length; i++) {
        fprintf(file, "%02x", key[i]);
    }
    fprintf(file, "\"\n");

    fclose(file);
}

void load_key_from_file(const char *filename, unsigned char *key, int length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Key file opening failed");
        exit(1);
    }

    char hex_key[2 * length + 1];
    fscanf(file, "\"%64s\"", hex_key);
    fclose(file);

    for (int i = 0; i < length; i++) {
        sscanf(&hex_key[2 * i], "%2hhx", &key[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <input file> <output file>\n", argv[0]);
        return 1;
    }

    unsigned char key[32];
    unsigned char iv[16] = {0}; // Initialization vector (IV) should be random in real applications

    if (strcmp(argv[1], "encrypt") == 0) {
        generate_random_key(key, sizeof(key));
        file_encrypt_decrypt(argv[2], argv[3], key, iv, 1);
        save_key_to_file("decrypt_code.txt", key, sizeof(key));
    } else if (strcmp(argv[1], "decrypt") == 0) {
        load_key_from_file("decrypt_code.txt", key, sizeof(key));
        file_encrypt_decrypt(argv[2], argv[3], key, iv, 0);
    } else {
        fprintf(stderr, "Invalid mode. Use 'encrypt' or 'decrypt'.\n");
        return 1;
    }

    return 0;
}
