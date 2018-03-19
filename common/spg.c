#include "spg.h"
#include <winsock2.h>
#include <windows.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "string_utils.h"
#include "base64.h"
#include "secure_socket.h"
#include "crypt_utils.h"

void encrypt_with_dek(FILE *in,
                      const unsigned char *dek,
                      FILE *out)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[32];
    char plain[128*3];
    int plain_len;
    unsigned char cipher[1024];
    int cipher_len;
    unsigned char b64_in[1024];
    char b64_out[1024*4];
    int b64_off;
    int b64_len;

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

    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_file(const char *input_file,
                  const char *cert_file,
                  const char *label,
                  const char *output_file)
{
    unsigned char dek[32];
    FILE *in, *out;
    char b64_out[1024*4];
    time_t now;
    struct tm tm;

    in = fopen(input_file, "rb");

    if(in == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
        exit(1);
    }

    if(output_file != NULL)
    {
        out = fopen(output_file, "wb");
    }
    else
    {
        out = stdout;
    }

    if(out == NULL)
    {
        fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
        exit(1);
    }

    generate_key(cert_file, label, b64_out, sizeof(b64_out), dek);

    fprintf(out, "key: %s\n", b64_out);
    fprintf(out, "label: %s\n", label);
    time(&now);
    tm = *localtime(&now);
    fprintf(out, "date: %04d-%02d-%02d %02d:%02d:%02d\n",
            tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    fprintf(out, "\n");

    encrypt_with_dek(in, dek, out);

    fclose(in);
    if(output_file != NULL) {
        fclose(out);
    }
}

void decrypt_key_by_agent(const char *ip,
                          int port,
                          const char *cert,
                          const char *enc_key,
                          const char *label,
                          unsigned char *dek)
{
    int sockfd = 0;
    char buf[1024];
    struct sockaddr_in serv_addr;
    char b64_in[64];
    int len;
    secure_socket_t ss;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Create socket failed\n");
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.S_un.S_addr = inet_addr(ip);

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       fprintf(stderr, "Connect server failed: %s:%d\n", ip, port);
    }

    sprintf(buf, "{ \"key\": \"%s\", \"label\": \"%s\"}", enc_key, label);

    init_secure_socket(&ss, sockfd, cert, NULL);

    secure_send(&ss, buf, strlen(buf));

    memset(dek, 0, 32);
    len = secure_recv(&ss, (char *)b64_in, sizeof(b64_in));

    base64_decode(dek, 32, b64_in, len);

    closesocket(sockfd);
}

#define BASE64_ROUND(x, off) ((x) >= off ? (((x)-off) / 4) * 4 + off : 0)

void decrypt_with_dek(FILE *in, const unsigned char *dek, FILE *out)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[32];
    char line[1024];
    unsigned char b64_out[2048];
    int b64_outlen;
    int b64_off;
    unsigned char cipher[1024];
    int cipher_off;
    int max_cipher;
    unsigned char plain[1024];
    int plain_len;
    int len;

    ctx = EVP_CIPHER_CTX_new();

    memset(iv, 0, sizeof(iv));
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dek, iv);

    cipher_off = 0;
    memset(cipher, 0, sizeof(cipher));

    for(;;)
    {
        len = BASE64_ROUND(sizeof(line), 1);
        if (fgets(line, len, in) == NULL)
        {
            break;
        }

        b64_outlen = base64_decode(b64_out,
                                   sizeof(b64_out),
                                   line,
                                   strlen(line));

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

            while(max_cipher%32 != 0)
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
}

void internal_decrypt_file(const char *input_file,
                  const char *key_file,
                  const char *addr,
                  int port,
                  const char *cert_file,
                  const char *output_file)
{
    char line[2048];
    char label[1024];
    char enc_key[1024];
    unsigned char dek[32];
    FILE *in, *out;

    in = fopen(input_file, "r");
    if(in == NULL)
    {
        fprintf(stderr, "open input file failed: %s", input_file);
        return;
    }

    if(output_file != NULL)
    {
        out = fopen(output_file, "wb");
        if(out == NULL)
        {
            fprintf(stderr, "open output file failed: %s", output_file);
            return;
        }
    }
    else
    {
        out = stdout;
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
        else if(0 == strncasecmp(line, "key: ", strlen("key: ")))
        {
            strcpy(enc_key, line + strlen("key: "));
            rtrim(enc_key, "\r\n");
        }
        else if(0 == strncasecmp(line, "label: ", strlen("label: ")))
        {
            strcpy(label, line + strlen("label: "));
            rtrim(label, "\r\n");
        }
    }

    if(key_file != NULL)
    {
        decrypt_key(enc_key, key_file, label, dek);
    }
    else
    {
        decrypt_key_by_agent(addr, port, cert_file, enc_key, label, dek);
    }

    decrypt_with_dek(in, dek, out);

    fclose(in);

    if(output_file != NULL)
    {
        fclose(out);
    }
}

void decrypt_file_by_agent(const char *input_file,
                  const char *addr,
                  int port,
                  const char *cert_file,
                  const char *output_file)
{
    internal_decrypt_file(input_file, NULL, addr, port, cert_file, output_file);
}

void decrypt_file_by_private_key(const char *input_file,
                  const char *key_file,
                  const char *output_file)
{
    internal_decrypt_file(input_file, key_file, NULL, 0, NULL, output_file);
}
