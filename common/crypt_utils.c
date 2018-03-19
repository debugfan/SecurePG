#include "crypt_utils.h"

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "string_utils.h"
#include "base64.h"
#include <conio.h>

void to_hex_string(char *dst, int dst_len, const unsigned char *src, int src_len)
{
    int i;
    char tmp[8];
    for(i = 0; i < src_len; i++)
    {
        if(i*2+1 < dst_len)
        {
            _snprintf(tmp, sizeof(tmp), "%02X", src[i]);
            dst[i*2] = tmp[0];
            dst[i*2+1] = tmp[1];
        }
    }
}

int calcute_dek(const unsigned char *prekey,
                int prekey_len,
                const char *label,
                unsigned char *dek)
{
    HMAC_CTX ctx;
    unsigned int len;

    HMAC_CTX_init(&ctx);
    if (!HMAC_Init_ex(&ctx, prekey, prekey_len, EVP_sha256(), NULL))
    {
        fprintf(stderr, "Failed to initialize HMAC\n");
    }
    if (!HMAC_Update(&ctx, (unsigned char *)label, strlen(label)))
    {
        fprintf(stderr, "Error updating HMAC with data\n");
    }
    if (!HMAC_Final(&ctx, dek, &len))
    {
        fprintf(stderr, "Error finalizing data\n");
    }
    HMAC_CTX_cleanup(&ctx);
    return len;
}

RSA *load_rsa_public_key(const char *key_file)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    key = BIO_new_file(key_file, "r");
    pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
    BIO_free(key);

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    return rsa;
}

int get_pass(char *buf, int len)
{
    int i;
    char c;

    i = 0;
    while(i + 1 < len) {
        c = getch();
        if(c == '\r' || c == '\n') {
            putchar('\n');
            break;
        }
        putchar('*');
        buf[i++] = c;
        if(i + 1 >= len) {
            break;
        }
    }
    if(i < len) {
        buf[i] = '\0';
        return i;
    }
    else {
        return 0;
    }
}

int pem_password_callback(char *buf, int max_len, int flag, void *ctx)
{
    fprintf(stdout, "Input password for %s: ", ctx == NULL ? "key" : (char *)ctx);
    return get_pass(buf, max_len);
}

RSA *load_rsa_private_key(const char *key_file)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    char err_buf[1024];

    bio = BIO_new_file(key_file, "r");
    if(bio != NULL) {
        pkey = PEM_read_bio_PrivateKey(bio, &pkey, pem_password_callback, (char *)key_file);
        if(pkey != NULL) {
            rsa = EVP_PKEY_get1_RSA(pkey);
            EVP_PKEY_free(pkey);
        }
        else {
            fprintf(stderr,
                    "PEM_read_bio_PrivateKey failed: %s\n",
                    ERR_error_string(ERR_get_error(), err_buf));
        }
        BIO_free(bio);
    }
    else {
        fprintf(stderr,
                "BIO_new_file failed: %s\n",
                ERR_error_string(ERR_get_error(), err_buf));
    }

    return rsa;
}

int AES_encrypt(void *dst, int dstlen, const void *src, int src_len, unsigned char *key, int use_base64)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[32];
    unsigned char cipher[8096];
    int len;
    int cipher_off;

    ctx = EVP_CIPHER_CTX_new();
    memset(iv, 0, sizeof(iv));
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher, &len, (unsigned char *)src, src_len);
    cipher_off = len;
    EVP_EncryptFinal_ex(ctx, cipher + cipher_off, &len);
    cipher_off += len;

    if(use_base64 != 0)
    {
        return base64_encode(dst, dstlen, cipher, cipher_off);
    }
    else
    {
        if(cipher_off <= dstlen)
        {
            memcpy(dst, cipher, cipher_off);
            return cipher_off;
        }
        else
        {
            return 0;
        }
    }
}

int AES_decrypt(void *dst, int dstlen, const void *src, int srclen, unsigned char *key, int use_base64)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[32];
    unsigned char b64_out[8096];
    int b64_outlen;
    unsigned char plain[8096];
    int off;
    int len;

    if(use_base64 != 0)
    {
        b64_outlen = base64_decode(b64_out, sizeof(b64_out), (char *)src, srclen);
    }

    ctx = EVP_CIPHER_CTX_new();
    memset(iv, 0, sizeof(iv));
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plain, &len,
                      use_base64 != 0 ? b64_out : src,
                      use_base64 != 0 ? b64_outlen : srclen);
    off = len;
    EVP_DecryptFinal_ex(ctx, plain + off, &len);
    off += len;
    if(off <= dstlen)
    {
        memcpy(dst, plain, off);
        return off;
    }
    else
    {
        return 0;
    }
}

int RSA_encrypt(unsigned char *dst, int dstlen, const unsigned char *src, int srclen,
                const char *cert_file, int use_base64)
{
    RSA *rsa = NULL;
    unsigned char *rsa_out;
    int rsa_outlen;
    int keysize;
    int result = 0;

    rsa = load_rsa_public_key(cert_file);
    if(rsa != NULL) {
        keysize = RSA_size(rsa);
        rsa_out = malloc(keysize * 2);
        if(rsa_out != NULL) {
            rsa_outlen = RSA_public_encrypt(srclen, src, rsa_out, rsa, RSA_PKCS1_PADDING);

            if(use_base64 != 0)
            {
                result = base64_encode((char *)dst, dstlen, rsa_out, rsa_outlen);
            }
            else
            {
                if(rsa_outlen <= dstlen)
                {
                    memcpy(dst, rsa, rsa_outlen);
                    result = rsa_outlen;
                }
                else
                {
                    result = 0;
                }
            }

            free(rsa_out);
        }
    }
    else {
        fprintf(stderr, "load_rsa_public_key failed.\n");
    }

    return result;
}

int RSA_decrypt(unsigned char *dst, int dstlen, const unsigned char *src, int srclen,
                const char *key_file, int use_base64)
{
    RSA *rsa;
    int keysize;
    unsigned char *rsa_out;
    int rsa_outlen;
    unsigned char b64_out[4096];
    int b64_outlen;
    int result = 0;

    rsa = load_rsa_private_key(key_file);
    if(rsa != NULL) {

        keysize = RSA_size(rsa);
        rsa_out = malloc(keysize * 2);
        if(rsa_out != NULL) {

            memset(rsa_out, 0, keysize * 2);

            if(use_base64 != 0)
            {
                b64_outlen = base64_decode(b64_out, sizeof(b64_out), (char *)src, srclen);
            }

            rsa_outlen = RSA_private_decrypt(use_base64 != 0 ? b64_outlen : srclen,
                                             use_base64 != 0 ? b64_out : src,
                                             rsa_out, rsa, RSA_PKCS1_PADDING);

            if(rsa_outlen <= dstlen)
            {
                memcpy(dst, rsa_out, rsa_outlen);
                result = rsa_outlen;
            }
            else
            {
                result = 0;
            }

            free(rsa_out);
        }
        else {
            fprintf(stderr, "malloc failed.\n");
        }
    }
    else {
        fprintf(stderr, "load_rsa_private_key failed.\n");
    }

    return result;
}

void decrypt_key(const char *enc_key, const char *key_file, const char *label, unsigned char *dek)
{
    unsigned char pre_key[1024];
    int len;
    len = RSA_decrypt(pre_key, sizeof(pre_key), (unsigned char *)enc_key, strlen(enc_key), key_file, 1);
    calcute_dek(pre_key, len, label, dek);
}

void generate_key(const char *cert_file,
                  const char *label,
                  char *enc_key,
                  int key_len,
                  unsigned char *dek)
{
    unsigned char rand[32];
    unsigned char prekey[64];
    int len;

    memset(rand, 0, sizeof(rand));
    RAND_bytes(rand, sizeof(rand));
    to_hex_string((char *)prekey, sizeof(prekey), rand, sizeof(rand));

    memset(dek, 0, 32);
    calcute_dek(prekey, sizeof(prekey), label, dek);

    len = RSA_encrypt((unsigned char *)enc_key, key_len - 1, prekey, sizeof(prekey), cert_file, 1);

    if(len > 0)
    {
        enc_key[len] = '\0';
    }
}
