#ifndef SECURE_SOCKET_H_INCLUDED
#define SECURE_SOCKET_H_INCLUDED

#include <Winsock2.h>
#include <windows.h>

typedef struct {
    SOCKET s;
    unsigned char dek[64];
    const char *cert;
    const char *key;
    int secure;
} secure_socket_t;

void init_secure_socket(secure_socket_t *ss, SOCKET s, const char *cert_file, const char *key_file);
void secure_send(secure_socket_t *ss, const char *buf, int len);
int secure_recv(secure_socket_t *ss, char *buf, int len);

#endif // SECURE_SOCKET_H_INCLUDED
