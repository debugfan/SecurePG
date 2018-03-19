#include "base64.h"
#include <openssl/bio.h>
#include <openssl/engine.h>

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
