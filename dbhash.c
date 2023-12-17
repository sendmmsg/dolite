/*
** 2016-06-07
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This is a utility program that computes an SHA1 hash on the content
** of an SQLite database.
**
** The hash is computed over just the content of the database.  Free
** space inside of the database file, and alternative on-disk representations
** of the same content (ex: UTF8 vs UTF16) do not affect the hash.  So,
** for example, the database file page size, encoding, and auto_vacuum setting
** can all be changed without changing the hash.
*/
#include "sqlite3.h"
#include <assert.h>
#include <ctype.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

crypto_generichash_state hash_state;

/*
** Print an error message for an error that occurs at runtime, then
** abort the program.
*/
static void runtimeError(const char *zFormat, ...) {
  va_list ap;
  va_start(ap, zFormat);
  vfprintf(stderr, zFormat, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  exit(1);
}

/*
** Prepare a new SQL statement.  Print an error and abort if anything
** goes wrong.
*/
static sqlite3_stmt *db_vprepare(sqlite3 *db, const char *zFormat, va_list ap) {
  char *zSql;
  int rc;
  sqlite3_stmt *pStmt;

  zSql = sqlite3_vmprintf(zFormat, ap);
  if (zSql == 0)
    runtimeError("out of memory");
  rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, 0);
  if (rc) {
    runtimeError("SQL statement error: %s\n\"%s\"", sqlite3_errmsg(db), zSql);
  }
  sqlite3_free(zSql);
  return pStmt;
}
static sqlite3_stmt *db_prepare(sqlite3 *db, const char *zFormat, ...) {
  va_list ap;
  sqlite3_stmt *pStmt;
  va_start(ap, zFormat);
  pStmt = db_vprepare(db, zFormat, ap);
  va_end(ap);
  return pStmt;
}

static int hash_update(const unsigned char *data, int data_len) {
  // printf("hash_update called\n");
  int rc = crypto_generichash_update(&hash_state, data, data_len);
  return rc;
}
/*
** Compute the hash for all rows of the query formed from the printf-style
** zFormat and its argument.
*/
static int hash_one_query(sqlite3 *db, const char *zFormat, ...) {
  va_list ap;
  sqlite3_stmt *pStmt; /* The query defined by zFormat and "..." */
  int nCol;            /* Number of columns in the result set */
  int i;               /* Loop counter */
  int rc;

  /* Prepare the query defined by zFormat and "..." */
  va_start(ap, zFormat);
  pStmt = db_vprepare(db, zFormat, ap);
  va_end(ap);
  nCol = sqlite3_column_count(pStmt);

  /* Compute a hash over the result of the query */
  while (SQLITE_ROW == sqlite3_step(pStmt)) {
    for (i = 0; i < nCol; i++) {
      switch (sqlite3_column_type(pStmt, i)) {
      case SQLITE_NULL: {
        rc += hash_update((const unsigned char *)"0", 1);
        break;
      }
      case SQLITE_INTEGER: {
        sqlite3_uint64 u;
        int j;
        unsigned char x[8];
        sqlite3_int64 v = sqlite3_column_int64(pStmt, i);
        memcpy(&u, &v, 8);
        for (j = 7; j >= 0; j--) {
          x[j] = u & 0xff;
          u >>= 8;
        }
        rc += hash_update((const unsigned char *)"1", 1);
        rc += hash_update(x, 8);
        break;
      }
      case SQLITE_FLOAT: {
        sqlite3_uint64 u;
        int j;
        unsigned char x[8];
        double r = sqlite3_column_double(pStmt, i);
        memcpy(&u, &r, 8);
        for (j = 7; j >= 0; j--) {
          x[j] = u & 0xff;
          u >>= 8;
        }
        rc += hash_update((const unsigned char *)"2", 1);
        rc += hash_update(x, 8);
        break;
      }
      case SQLITE_TEXT: {
        int n = sqlite3_column_bytes(pStmt, i);
        const unsigned char *z = sqlite3_column_text(pStmt, i);
        rc += hash_update((const unsigned char *)"3", 1);
        rc += hash_update(z, n);
        break;
      }
      case SQLITE_BLOB: {
        int n = sqlite3_column_bytes(pStmt, i);
        const unsigned char *z = sqlite3_column_blob(pStmt, i);
        rc += hash_update((const unsigned char *)"4", 1);
        rc += hash_update(z, n);
        break;
      }
      }
    }
  }
  sqlite3_finalize(pStmt);
  return rc;
}

int dolite_hash_db(sqlite3 *db, unsigned char *digest,
                   unsigned char digest_len) {

  sqlite3_stmt *pStmt;
  memset(digest, 0, digest_len);
  /* Start the hash */
  int rc = crypto_generichash_init(&hash_state, NULL, 0, digest_len);
  if (rc != 0)
    goto err;
  /* Hash table content */
  pStmt =
      db_prepare(db, "SELECT name FROM sqlite_schema\n"
                     " WHERE type='table' AND sql NOT LIKE 'CREATE VIRTUAL%%'\n"
                     "   AND name NOT LIKE 'sqlite_%%'\n"
                     "   AND name NOT LIKE 'dolite_%%'\n"
                     " ORDER BY name COLLATE nocase;\n");

  while (SQLITE_ROW == sqlite3_step(pStmt)) {
    /* We want rows of the table to be hashed in PRIMARY KEY order.
    ** Technically, an ORDER BY clause is required to guarantee that
    ** order.  However, though not guaranteed by the documentation, every
    ** historical version of SQLite has always output rows in PRIMARY KEY
    ** order when there is no WHERE or GROUP BY clause, so the ORDER BY
    ** can be safely omitted. */
    printf("    hashing table %s\n", sqlite3_column_text(pStmt, 0));
    rc = hash_one_query(db, "SELECT * FROM \"%w\"",
                        sqlite3_column_text(pStmt, 0));
    if (rc != 0)
      goto err;
  }

  /* Hash the database schema */
  rc =
      hash_one_query(db, "SELECT type, name, tbl_name, sql FROM sqlite_schema\n"
                         " WHERE tbl_name NOT LIKE 'dolite_%%'\n"
                         " ORDER BY name COLLATE nocase;\n");
  if (rc != 0)
    goto err;

  /* Finish and output the hash and close the database connection. */
  rc = crypto_generichash_final(&hash_state, digest, digest_len);
  if (rc != 0)
    goto err;
  /* for (int i = 0; i < 32; i++) { */
  /*   printf("%x", digest[i]); */
  /* } */
  /* printf("\n"); */

err:
  sqlite3_finalize(pStmt);
  if (rc == 0)
    return SQLITE_OK;
  return SQLITE_ERROR;
}
