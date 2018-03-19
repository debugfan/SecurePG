#ifndef BASE64_H_INCLUDED
#define BASE64_H_INCLUDED

#include <string.h>

int base64_encode(char *dst, int dstlen, const unsigned char* src, int srclen);
int base64_decode(unsigned char *dst, size_t dstlen, const char *src, size_t srclen);

#endif // BASE64_H_INCLUDED
