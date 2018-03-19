#include "secure_socket.h"
#include <string.h>
#include "crypt_utils.h"
#include "string_utils.h"
#include <stdio.h>
#include "json_utils.h"

void init_secure_socket(secure_socket_t *ss, SOCKET s, const char *cert_file, const char *key_file)
{
    ss->s = s;
    ss->cert = cert_file;
    ss->key = key_file;
    ss->secure = 0;
}

void secure_send(secure_socket_t *ss, const char *buf, int len)
{
    if(ss->secure == 0)
    {
        char enc_key[8192];
        char cipher[8192];
        char json_text[8192*2];
        const char *label = "SECUREPG-SSL";

        generate_key(ss->cert, label, enc_key, sizeof(enc_key), ss->dek);
        AES_encrypt(cipher, sizeof(cipher), buf, len, ss->dek, 1);

        sprintf(json_text, "{\"key\": \"%s\", \"label\": \"%s\", \"data\": \"%s\"}",
                enc_key, label, cipher);
        send(ss->s, json_text, strlen(json_text), 0);
        ss->secure = 1;
    }
    else
    {
        unsigned char cipher[8192];
        int cipher_len;
        cipher_len = AES_encrypt(cipher, sizeof(cipher), buf, len, ss->dek, 1);
        send(ss->s, (char *)cipher, cipher_len, 0);
    }
}

void secure_parse(const char *buf, int len, char *pre_key, char *label, char *data)
{
    const char *p;
    json_item_t item;

    p = parse_json_item(buf, len, &item);
    while(p != NULL)
    {
        if(0 == strncasecmp("key", item.key, item.key_len))
        {
            memcpy(pre_key, item.value, item.value_len);
            pre_key[item.value_len] = '\0';
        }
        else if(0 == strncasecmp("label", item.key, item.key_len))
        {
            memcpy(label, item.value, item.value_len);
            label[item.value_len] = '\0';
        }
        else if(0 == strncasecmp("data", item.key, item.key_len))
        {
            memcpy(data, item.value, item.value_len);
            data[item.value_len] = '\0';
        }
        p = parse_json_item(p, buf + len - p, &item);
    }
}

int secure_recv(secure_socket_t *ss, char *buf, int len)
{
    char cipher[4096];
    int cipher_len;
    char plain[4096];
    int plain_len;
    char prekey[4096];
    char label[4096];

    if(ss->secure == 0)
    {
        char tmp[8196];
        int tmp_len;
        tmp_len = recv(ss->s, tmp, sizeof(tmp), 0);
        secure_parse(tmp, tmp_len, prekey, label, cipher);
        decrypt_key(prekey, ss->key, label, ss->dek);
        cipher_len = strlen(cipher);
        ss->secure = 1;
    }
    else
    {
        cipher_len = recv(ss->s, cipher, sizeof(cipher), 0);
    }

    plain_len = AES_decrypt(plain, sizeof(plain), cipher, cipher_len, ss->dek, 1);
    memcpy(buf, plain, plain_len);

    return plain_len;
}
