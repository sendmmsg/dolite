#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1
#include <stdio.h>
#include <zlib.h>

static void encode(sqlite3_context *context, int argc, sqlite3_value **argv) {
  const unsigned char *pIn;
  unsigned char *pOut, *enc;
  unsigned int nIn;
  unsigned long int nOut;
  /* unsigned char x[8]; */
  pIn = sqlite3_value_blob(argv[0]);
  nIn = sqlite3_value_bytes(argv[0]);
  // printf("pIn %p nIn %d\n", pIn, nIn);
  char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  size_t extra_chars = ((nIn % 3) ? nIn % 3 + 1 : 0);
  size_t pad_chars = (extra_chars) ? 4 - extra_chars : 0;
  nOut = 4 * (nIn / 3) + extra_chars + pad_chars;
  pOut = sqlite3_malloc(nOut);
  enc = pOut;

  // printf("pOut %p nOut %ld\n", pOut, nOut);
  /* int i, j; */
  /* for (i = 4; i >= 0; i--) { */
  /*   x[i] = (nIn >> (7 * (4 - i))) & 0x7f; */
  /* } */
  /* for (i = 0; i < 4 && x[i] == 0; i++) { */
  /* } */
  /* for (j = 0; i <= 4; i++, j++) */
  /*   pOut[j] = x[i]; */
  /* pOut[j - 1] |= 0x80; */
  const unsigned char *needle = pIn, *ceiling = pIn + nIn;
  while (needle < ceiling) {
    *enc++ = alphabet[(*needle) >> 2];
    if (needle + 1 < ceiling) {
      *enc++ = alphabet[((*needle << 4) & 0x30) | (*(needle + 1) >> 4)];
      if (needle + 2 < ceiling) {
        *enc++ = alphabet[((*(needle + 1) << 2) & 0x3c) | (*(needle + 2) >> 6)];
        *enc++ = alphabet[*(needle + 2) & 0x3f];
      } else
        *enc++ = alphabet[(*(needle + 1) << 2) & 0x3c];
    } else
      *enc++ = alphabet[(*needle << 4) & 0x30];
    needle += 3;
  }
  while (enc < pOut + nOut)
    *enc++ = '=';

  sqlite3_result_blob(context, pOut, nOut, sqlite3_free);
}

/*
** Implementation of the "uncompress(X)" SQL function.  The argument X
** is a blob which was obtained from compress(Y).  The output will be
** the value Y.
*/
/* static void uncompressFunc(sqlite3_context *context, int argc, */
/*                            sqlite3_value **argv) { */
/*   const unsigned char *pIn; */
/*   unsigned char *pOut; */
/*   unsigned int nIn; */
/*   unsigned long int nOut; */
/*   int rc; */
/*   int i; */

/*   pIn = sqlite3_value_blob(argv[0]); */
/*   nIn = sqlite3_value_bytes(argv[0]); */
/*   nOut = 0; */
/*   for (i = 0; i < nIn && i < 5; i++) { */
/*     nOut = (nOut << 7) | (pIn[i] & 0x7f); */
/*     if ((pIn[i] & 0x80) != 0) { */
/*       i++; */
/*       break; */
/*     } */
/*   } */
/*   pOut = sqlite3_malloc(nOut + 1); */
/*   rc = uncompress(pOut, &nOut, &pIn[i], nIn - i); */
/*   if (rc == Z_OK) { */
/*     sqlite3_result_blob(context, pOut, nOut, sqlite3_free); */
/*   } else { */
/*     sqlite3_free(pOut); */
/*   } */
/* } */

#ifdef _WIN32
__declspec(dllexport)
#endif

    int sqlite3_enc_init(sqlite3 *db, char **pzErrMsg,
                         const sqlite3_api_routines *pApi) {
  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
  (void)pzErrMsg; /* Unused parameter */
  rc = sqlite3_create_function(db, "encode", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS,
                               0, encode, 0, 0);
  /* if (rc == SQLITE_OK) { */
  /*   rc = sqlite3_create_function(db, "uncompress", 1, */
  /*                                SQLITE_UTF8 | SQLITE_INNOCUOUS | */
  /*                                    SQLITE_DETERMINISTIC, */
  /*                                0, uncompressFunc, 0, 0); */
  //}
  return rc;
}
