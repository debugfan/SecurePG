#include "crypt_utils.h"

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "string_utils.h"

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

int base64_encode(char *dst, int dstlen, const unsigned char* src, int srclen)
{
	BIO *bio, *b64;
	int len;
	BUF_MEM *bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, src, srclen);
	BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    len = bptr->length;
    memcpy(dst, bptr->data, len);
    dst[len] = '\0';

	BIO_free_all(bio);

	return len;
}

int base64_decode(unsigned char *dst, size_t dstlen, const char *src, size_t srclen)
{
	int len = 0;
	BIO *b64,*bsrc;
	b64 = BIO_new(BIO_f_base64());
	bsrc = BIO_new_mem_buf(src, srclen);
	bsrc = BIO_push(b64, bsrc);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	len = BIO_read(bsrc, dst, srclen);
	dst[len] = 0;
	BIO_free_all(bsrc);
	return len;
}

int calcute_dek(const unsigned char *prekey,
                int prekey_len,
                const char *comment,
                unsigned char *dek)
{
    HMAC_CTX ctx;
    unsigned int len;

    HMAC_CTX_init(&ctx);
    if (!HMAC_Init_ex(&ctx, prekey, prekey_len, EVP_sha256(), NULL))
    {
        printf("Failed to initialise HMAC\n");
    }
    if (!HMAC_Update(&ctx, (unsigned char *)comment, strlen(comment)))
    {
        printf("Error updating HMAC with data\n");
    }
    if (!HMAC_Final(&ctx, dek, &len))
    {
        printf("Error finalising data\n");
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

int pem_password_callback(char *buf, int max_len, int flag, void *ctx)
{
    const char* PASSWD = "123456";
    int len = strlen(PASSWD);

    if(len > max_len)
        return 0;

    memcpy(buf, PASSWD, len);
    return len;
}

RSA *load_rsa_private_key(const char *key_file)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    char err_buf[1024];

    key = BIO_new_file(key_file, "r");
    pkey = PEM_read_bio_PrivateKey(key, &pkey, NULL, NULL);
    if(pkey == NULL)
    {
        fprintf(stderr,
                "error: %s\n",
                ERR_error_string(ERR_get_error(), err_buf));
    }
    BIO_free(key);

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    return rsa;
}

void encrypt_file(const char *input_file,
                  const char *key_file,
                  const char *comment,
                  const char *output_file)
{
    RSA *rsa = NULL;
    unsigned char rand[32];
    unsigned char prekey[64];
    unsigned char dek[32];
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[32];
    unsigned char *rsa_out = NULL;
    int rsa_outlen;
    FILE *in, *out;
    char plain[128*3];
    int plain_len;
    unsigned char cipher[1024];
    int cipher_len;
    int keysize;
    unsigned char b64_in[1024];
    char b64_out[1024*4];
    int b64_off;
    int b64_len;

    memset(rand, 0, sizeof(rand));
    RAND_bytes(rand, sizeof(rand));
    to_hex_string((char *)prekey, sizeof(prekey), rand, sizeof(rand));

    rsa = load_rsa_public_key(key_file);
    keysize = RSA_size(rsa);
    rsa_out = malloc(keysize * 2);
    rsa_outlen = RSA_public_encrypt(sizeof(prekey), prekey, rsa_out, rsa, RSA_PKCS1_PADDING);

    memset(dek, 0, sizeof(dek));
    calcute_dek(prekey, sizeof(prekey), comment, dek);

    in = fopen(input_file, "rb");

    if(in == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
        exit(1);
    }

    out = fopen(output_file, "wb");

    if(out == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
        exit(1);
    }

    memset(b64_out, 0, sizeof(b64_out));
    base64_encode(b64_out, sizeof(b64_out), rsa_out, rsa_outlen);
    free(rsa_out);

    fprintf(out, "Key: %s\n", b64_out);
    fprintf(out, "Comment: %s\n\n", comment);

    ctx = EVP_CIPHER_CTX_new();

    memset(iv, 0, sizeof(iv));
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dek, iv);

    b64_off = 0;

    while((plain_len = fread(plain, 1, sizeof(plain), in)) > 0)
    {
        int max_b64 = 0;
        int cipher_off = 0;

        EVP_EncryptUpdate(ctx, cipher, &cipher_len, (unsigned char *)plain, plain_len);

        while(cipher_off < cipher_len)
        {
            int rest = cipher_len - cipher_off;

            if(b64_off + rest >= sizeof(b64_in))
            {
                max_b64 = sizeof(b64_len);
            }
            else
            {
                max_b64 = b64_off + rest;
            }

            while(max_b64%3 != 0)
            {
                max_b64--;
            }

            if(max_b64 > 0)
            {
                int copied = max_b64-b64_off;
                memcpy(b64_in+b64_off, cipher + cipher_off, copied);
                b64_off += copied;
                cipher_off += copied;
                b64_len = base64_encode(b64_out, sizeof(b64_out), b64_in, b64_off);
                fwrite(b64_out, 1, b64_len, out);
                b64_off = 0;
            }
            else
            {
                memcpy(b64_in + b64_off, cipher + cipher_off, rest);
                b64_off += rest;
                cipher_off += rest;
            }
        }
    }

    EVP_EncryptFinal_ex(ctx, cipher, &cipher_len);

    memcpy(b64_in+b64_off, cipher, cipher_len);
    b64_off += cipher_len;
    b64_len = base64_encode(b64_out, sizeof(b64_out), b64_in, b64_off);
    fwrite(b64_out, 1, b64_len, out);
    fwrite("\n", 1, 1, out);

    fclose(in);
    fclose(out);

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_key(const char *pre_key, const char *key_file, const char *comment, unsigned char *dek)
{
    RSA *rsa = NULL;
    int keysize;
    unsigned char *rsa_out;
    int rsa_outlen;
    unsigned char b64_out[1024];
    int b64_outlen;

    rsa = load_rsa_private_key(key_file);

    keysize = RSA_size(rsa);

    rsa_out = malloc(keysize * 2);

    memset(rsa_out, 0, keysize * 2);

    b64_outlen = base64_decode(b64_out, sizeof(b64_out), pre_key, strlen(pre_key));

    rsa_outlen = RSA_private_decrypt(b64_outlen, b64_out, rsa_out, rsa, RSA_PKCS1_PADDING);

    calcute_dek(rsa_out, rsa_outlen, comment, dek);

    free(rsa_out);
}

void decrypt_file(const char *input_file,
                  const char *key_file,
                  const char *output_file)
{
    char line[4096+1];
    char comment[1024];
    char enc_key[1024];
    unsigned char dek[32];
    unsigned char iv[32];
    FILE *in, *out;
    EVP_CIPHER_CTX *ctx;
    unsigned char cipher[1024];
    int cipher_off;
    int max_cipher;
    unsigned char b64_out[1024];
    int b64_outlen;
    int b64_off;
    unsigned char plain[1024];
    int plain_len;

    in = fopen(input_file, "r");
    if(in == NULL)
    {
        return;
    }

    out = fopen(output_file, "wb");
    if(out == NULL)
    {
        return;
    }

    for(;;)
    {
        if (fgets(line, sizeof(line), in) == NULL)
        {
            break;
        }

        if(0 == strncmp(line, "\r", 1) || 0 == strncmp(line, "\n", 1))
        {
            break;
        }
        else if(0 == strncmp(line, "Key: ", 5))
        {
            strcpy(enc_key, line + 5);
        }
        else if(0 == strncmp(line, "Comment: ", 9))
        {
            strcpy(comment, line + 9);
            trim_right(comment, "\r\n");
        }
    }

    decrypt_key(enc_key, key_file, comment, dek);

    ctx = EVP_CIPHER_CTX_new();

    memset(iv, 0, sizeof(iv));
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dek, iv);

    cipher_off = 0;
    memset(cipher, 0, sizeof(cipher));

    for(;;)
    {
        if (fgets(line, sizeof(line), in) == NULL)
        {
            break;
        }

        b64_outlen = base64_decode(b64_out, sizeof(b64_out), line, strlen(line));
        for(b64_off = 0; b64_off < b64_outlen;)
        {
            int rest = b64_outlen - b64_off;

            if(cipher_off + rest >= sizeof(cipher))
            {
                max_cipher = sizeof(cipher);
            }
            else
            {
                max_cipher = cipher_off + rest;
            }

            while(max_cipher%16 != 0)
            {
                max_cipher--;
            }

            if(max_cipher > 0)
            {
                int copied = max_cipher-cipher_off;
                memcpy(cipher + cipher_off, b64_out + b64_off, copied);
                cipher_off += copied;
                b64_off += copied;
                EVP_DecryptUpdate(ctx, plain, &plain_len, cipher, cipher_off);
                fwrite(plain, 1, plain_len, out);
                cipher_off = 0;
            }
            else
            {
                memcpy(cipher + cipher_off, b64_out + b64_off, rest);
                cipher_off += rest;
                b64_off += rest;
            }
        }
    }

    if(cipher_off > 0)
    {
        EVP_DecryptUpdate(ctx, plain, &plain_len, cipher, cipher_off);
        fwrite(plain, 1, plain_len, out);
    }

    EVP_DecryptFinal_ex(ctx, plain, &plain_len);

    if(plain_len > 0)
    {
        fwrite(plain, 1, plain_len, out);
    }

    fclose(in);
    fclose(out);
}
