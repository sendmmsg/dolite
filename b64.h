#ifndef B64_H_
#define B64_H_
#include <stdlib.h>
#include <string.h>
#if !defined(SQLITEINT_H)
#include "sqlite3ext.h"
#endif
size_t b64_encoded_size(size_t inlen);
size_t b64_decoded_size(const char *in);
char *b64_encode(const unsigned char *in, size_t len, void *(*memalloc)(int));
int b64_decode(const char *in, unsigned char *out, size_t outlen);
#endif // B64_H_
