#ifndef CRYPT_UTILS_H_INCLUDED
#define CRYPT_UTILS_H_INCLUDED

int calcute_dek(const unsigned char *prekey,
                int prekey_len,
                const char *label,
                unsigned char *dek);

void decrypt_key(const char *enc_key, const char *key_file, const char *label,
                 unsigned char *dek);

void generate_key(const char *cert_file,
                  const char *label,
                  char *enc_key,
                  int key_len,
                  unsigned char *dek);

int AES_encrypt(void *dst, int dstlen, const void *src, int src_len,
                unsigned char *key, int use_base64);

int AES_decrypt(void *dst, int dstlen, const void *src, int srclen,
                unsigned char *key, int use_base64);

int RSA_encrypt(unsigned char *dst, int dstlen, const unsigned char *src, int srclen,
        const char *cert_file, int use_base64);

int RSA_decrypt(unsigned char *dst, int dstlen, const unsigned char *src, int srclen,
        const char *key_file, int use_base64);

#endif // CRYPT_UTILS_H_INCLUDED
