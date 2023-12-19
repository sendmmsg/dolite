#define SQLITE_ENABLE_SNAPSHOT 1
#define SQLITE_ENABLE_SESSION 1
#include "sqlite3.h"
//#include "sqlite3ext.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define DIGEST_BYTES 32
unsigned char digest[DIGEST_BYTES];
void DumpHex(const void *data, size_t size);
int session_table_filter(void *pctx, const char *table);
int64_t clock_usecs(void);
void print_stmt_value(sqlite3_stmt *stmt, int col);
void hash_print(unsigned char *data, size_t length, int pad, char pad_char);
int dolite_hash_db(sqlite3 *db, unsigned char *digest,
                   unsigned char digest_len);
char *hash_tostring(unsigned char *data, size_t length, int pad, char pad_char);

static const char *const error_names[] = {
    [SQLITE_OK] = "SQLITE_OK: Successful result ",
    [SQLITE_ERROR] = "SQLITE_ERROR: Generic error ",
    [SQLITE_INTERNAL] = "SQLITE_INTERNAL: Internal logic error in SQLite ",
    [SQLITE_PERM] = "SQLITE_PERM: Access permission denied ",
    [SQLITE_ABORT] = "SQLITE_ABORT: Callback routine requested an abort ",
    [SQLITE_BUSY] = "SQLITE_BUSY: The database file is locked ",
    [SQLITE_LOCKED] = "SQLITE_LOCKED: A table in the database is locked ",
    [SQLITE_NOMEM] = "SQLITE_NOMEM: A malloc() failed ",
    [SQLITE_READONLY] =
        "SQLITE_READONLY: Attempt to write a readonly database ",
    [SQLITE_INTERRUPT] =
        "SQLITE_INTERRUPT: Operation terminated by sqlite3_interrupt()",
    [SQLITE_IOERR] = "SQLITE_IOERR: Some kind of disk I/O error occurred ",
    [SQLITE_CORRUPT] = "SQLITE_CORRUPT: The database disk image is malformed ",
    [SQLITE_NOTFOUND] =
        "SQLITE_NOTFOUND: Unknown opcode in sqlite3_file_control() ",
    [SQLITE_FULL] = "SQLITE_FULL: Insertion failed because database is full ",
    [SQLITE_CANTOPEN] = "SQLITE_CANTOPEN: Unable to open the database file ",
    [SQLITE_PROTOCOL] = "SQLITE_PROTOCOL: Database lock protocol error ",
    [SQLITE_EMPTY] = "SQLITE_EMPTY: Internal use only ",
    [SQLITE_SCHEMA] = "SQLITE_SCHEMA: The database schema changed ",
    [SQLITE_TOOBIG] = "SQLITE_TOOBIG: String or BLOB exceeds size limit ",
    [SQLITE_CONSTRAINT] =
        "SQLITE_CONSTRAINT: Abort due to constraint violation ",
    [SQLITE_MISMATCH] = "SQLITE_MISMATCH: Data type mismatch ",
    [SQLITE_MISUSE] = "SQLITE_MISUSE: Library used incorrectly ",
    [SQLITE_NOLFS] = "SQLITE_NOLFS: Uses OS features not supported on host ",
    [SQLITE_AUTH] = "SQLITE_AUTH: Authorization denied ",
    [SQLITE_FORMAT] = "SQLITE_FORMAT: Not used ",
    [SQLITE_RANGE] =
        "SQLITE_RANGE: 2nd parameter to sqlite3_bind out of range ",
    [SQLITE_NOTADB] = "SQLITE_NOTADB: File opened that is not a database file ",
    [SQLITE_NOTICE] = "SQLITE_NOTICE: Notifications from sqlite3_log() ",
    [SQLITE_WARNING] = "SQLITE_WARNING: Warnings from sqlite3_log() ",
    [SQLITE_ROW] = "SQLITE_ROW: sqlite3_step() has another row ready ",
    [SQLITE_DONE] = "SQLITE_DONE: sqlite3_step() has finished executing ",
};

static int xConflict(void *pCtx, int eConflict, sqlite3_changeset_iter *pIter) {
  int ret = (int)pCtx;
  return ret;
}

void exit_with_error(sqlite3 *db, const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
  sqlite3_close(db);
  exit(1);
}

int do_select_query(sqlite3 *db) {
  sqlite3_stmt *stmt;

  // create prepared statement
  int rc = sqlite3_prepare_v2(db, "SELECT *  FROM Cars;", -1, &stmt, 0);
  if (rc != SQLITE_OK)
    exit_with_error(db, "failure fetching data: ");

  // run the SQL
  rc = sqlite3_step(stmt);
  int ncols = sqlite3_column_count(stmt);
  // run the SQL
  while (rc == SQLITE_ROW) {
    for (int i = 0; i < ncols; i++) {
      print_stmt_value(stmt, i);
    }

    printf("\n");
    rc = sqlite3_step(stmt);
  }

  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
  return SQLITE_OK;
}

int session_table_filter(void *pctx, const char *table) {
  printf("session_table_filter called for table: %s\n", table);

  if (strlen(table) != strlen("dolite_hist"))
    return 1;

  if (strncmp(table, "dolite_hist", strlen("dolite_hist")) == 0)
    return 0;

  return 1;
}

int64_t clock_usecs(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)((int64_t)ts.tv_sec * 1000000 + (int64_t)ts.tv_nsec / 1000);
}

sqlite3_session *create_session(sqlite3 *db) {
  printf("Creating Session\n");
  sqlite3_session *session = 0;
  int rc = sqlite3session_create(db, "main", &session);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not create session: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  printf("Enabling Session\n");
  rc = sqlite3session_enable(session, 1);
  if (rc != 1) {
    fprintf(stderr, "Could not enable session: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  int val = 1;
  rc = sqlite3session_object_config(session, SQLITE_SESSION_OBJCONFIG_ROWID,
                                    &val);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error configuring Session for non-rowid tables: %s\n",
            sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  rc = sqlite3session_attach(session, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not attach 'ALL' to session: %s\n",
            sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }
  sqlite3session_table_filter(session, session_table_filter, NULL);

  return session;
}

sqlite3_session *dolite_init(sqlite3 *db) {
  char *err_msg = 0;
  char *sql =
      "CREATE TABLE IF NOT EXISTS dolite_hist(id INTEGER PRIMARY KEY, ts "
      "DATETIME, User TEXT, Changehash TEXT, Message TEXT, Dbhash TEXT, Diff "
      "BLOB );";

  printf("Creating dolite history table\n");
  int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating dolite_hist table: %s\n", err_msg);
    sqlite3_free(err_msg);
    return NULL;
  }
  return create_session(db);
}

int create_and_insert(sqlite3 *db) {

  char *sql =
      "DROP TABLE IF EXISTS Cars;"
      "CREATE TABLE Cars(id INTEGER PRIMARY KEY, Name TEXT, Price INTEGER);"
      "INSERT INTO Cars VALUES(NULL,'Audi', 52642);"
      "INSERT INTO Cars VALUES(NULL,'Mercedes', 57127);"
      "INSERT INTO Cars VALUES(NULL,'Skoda', 9000);"
      "INSERT INTO Cars VALUES(NULL,'Volvo', 29000);"
      "INSERT INTO Cars VALUES(NULL,'Bentley', 350000);"
      "INSERT INTO Cars VALUES(NULL,'Citroen', 21000);"
      "INSERT INTO Cars VALUES(NULL,'Hummer', 41400);"
      "INSERT INTO Cars VALUES(NULL,'Volkswagen', 21600);";

  char *err_msg = 0;
  int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}
int insert_new_car(sqlite3 *db, char *name, int price) {
  sqlite3_stmt *stmt;

  char *sql = "INSERT INTO Cars (Name, Price) VALUES (?, ?);";

  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to prepare statement(%s): %s\n", sql,
            sqlite3_errmsg(db));
    sqlite3_close(db);
    exit(1);
  }

  /* int idx = sqlite3_bind_parameter_index(res, "@Name"); */
  /* printf("idx: %d\n", idx); */
  rc = sqlite3_bind_text(stmt, 1, name, strlen(name), NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind text: %s\n", sqlite3_errmsg(db));
    exit(0);
  }
  /* idx = sqlite3_bind_parameter_index(res, "@Price"); */
  /* printf("idx: %d\n", idx); */
  sqlite3_bind_int(stmt, 2, price);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind integer: %s\n", sqlite3_errmsg(db));
    exit(0);
  }

  rc = sqlite3_step(stmt);
  if (SQLITE_DONE != rc) {
    fprintf(stderr, "insert statement didn't return DONE (%i): %s\n", rc,
            sqlite3_errmsg(db));
  } else {
    printf("INSERT completed\n\n");
  }
  sqlite3_finalize(stmt);
  return SQLITE_OK;
}

void dolite_revert_last_commit(sqlite3 *db) {

  sqlite3_stmt *stmt;
  char *sql = "SELECT Diff FROM dolite_hist ORDER BY id DESC LIMIT 1;";

  const void *data = NULL;
  int dlen = 0;

  void *invdata = NULL;
  int invdlen = 0;

  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    exit_with_error(db, "failure fetching data: ");
    goto done;
  }

  rc = sqlite3_step(stmt);
  int ncols = sqlite3_column_count(stmt);
  // run the SQL
  while (rc == SQLITE_ROW) {
    for (int i = 0; i < ncols; i++) {
      data = sqlite3_column_blob(stmt, i);
      dlen = sqlite3_column_bytes(stmt, i);
      printf("Found changeset:\n");
      // DumpHex(data, dlen);
      printf("oring len: %d orig data %p\n", dlen, data);
      rc = sqlite3changeset_invert(dlen, data, &invdlen, &invdata);

      printf("invert len: %d invert data %p\n", invdlen, invdata);
      if (rc != SQLITE_OK) {
        exit_with_error(db, "failure inverting changeset: ");
        goto done;
      }

      rc = sqlite3changeset_apply(db, invdlen, invdata, session_table_filter,
                                  xConflict, NULL);

      if (rc != SQLITE_OK) {
        exit_with_error(db, "failure applying inverted changeset: ");
        goto done;
      }
      // destroy the object to avoid resource leaks
      sqlite3_free(invdata);
    }

    fprintf(stderr, "\n");
    rc = sqlite3_step(stmt);
  }

done:
  sqlite3_finalize(stmt);
}

int dolite_revert_commit(sqlite3 *db, int commitId) {
  sqlite3_stmt *stmt;
  char *sql = "SELECT Diff FROM dolite_hist WHERE id = ?;";

  const void *data = NULL;
  int dlen = 0;

  void *invdata = NULL;
  int invdlen = 0;

  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
  if (rc != SQLITE_OK)
    exit_with_error(db, "failure fetching data: ");

  rc = sqlite3_step(stmt);
  int ncols = sqlite3_column_count(stmt);
  // run the SQL
  while (rc == SQLITE_ROW) {
    for (int i = 0; i < ncols; i++) {
      data = sqlite3_column_blob(stmt, i);
      dlen = sqlite3_column_bytes(stmt, i);
      printf("Found changeset:\n");
      // DumpHex(data, dlen);
      printf("oring len: %d orig data %p\n", dlen, data);
      rc = sqlite3changeset_invert(dlen, data, &invdlen, &invdata);

      printf("invert len: %d invert data %p\n", invdlen, invdata);
      if (rc != SQLITE_OK) {
        exit_with_error(db, "failure inverting changeset: ");
      }

      rc = sqlite3changeset_apply(db, invdlen, invdata, session_table_filter,
                                  xConflict, NULL);

      if (rc != SQLITE_OK)
        exit_with_error(db, "failure applying inverted changeset: ");
      // destroy the object to avoid resource leaks
      sqlite3_free(invdata);
    }

    fprintf(stderr, "\n");
    rc = sqlite3_step(stmt);
  }

  sqlite3_finalize(stmt);
}

void print_stmt_value(sqlite3_stmt *stmt, int col) {
  int value_type = sqlite3_column_type(stmt, col);
  /* printf("Col %d: ", i); */
  switch (value_type) {
  case SQLITE_INTEGER:
    printf("i: %lld, ", sqlite3_column_int64(stmt, col));
    break;
  case SQLITE_FLOAT:
    printf("f: %f, ", sqlite3_column_double(stmt, col));
    break;
  case SQLITE_BLOB:
    printf("b: (%d), ", sqlite3_column_bytes(stmt, col));
    break;
  case SQLITE_NULL:
    printf("NULL, ");
    break;
  case SQLITE_TEXT:
    printf("s: '%.*s', ", sqlite3_column_bytes(stmt, col),
           sqlite3_column_text(stmt, col));
    break;
  default:
    printf("Unknown type, %d ", value_type);
    break;
  }
}

void print_change_value(sqlite3_value *pValue) {
  if (pValue == NULL) {
    return;
  }
  int value_type = sqlite3_value_type(pValue);
  /* printf("Col %d: ", i); */
  switch (value_type) {
  case SQLITE_INTEGER:
    printf("i: %lld, ", sqlite3_value_int64(pValue));
    break;
  case SQLITE_FLOAT:
    printf("f: %f, ", sqlite3_value_double(pValue));
    break;
  case SQLITE_BLOB:
    printf("b: (%d), ", sqlite3_value_bytes(pValue));
    break;
  case SQLITE_NULL:
    printf("NULL, ");
    break;
  case SQLITE_TEXT:
    printf("s: '%.*s', ", sqlite3_value_bytes(pValue),
           sqlite3_value_text(pValue));
    break;
  default:
    printf("Unknown type, %d ", value_type);
    break;
  }
}
int inspect_changeset(int nChangeset, void *pChangeset) {
  if (nChangeset > 0) {
    // DumpHex(pChangeset, nChangeset);
  }
  sqlite3_changeset_iter *iter;
  int rc = sqlite3changeset_start(&iter, nChangeset, pChangeset);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error obtaining changeset iterator\n");
    return SQLITE_ERROR;
  }
  const char *pzTab;
  int pnCol;
  int pOp;
  int pbIndirect;
  /*   sqlite3_changeset_iter *pIter,  /\* Iterator object *\/ */
  /*   const char **pzTab,             /\* OUT: Pointer to table name *\/ */
  /*   int *pnCol,                     /\* OUT: Number of columns in table *\/
   */
  /*   int *pOp,                       /\* OUT: SQLITE_INSERT, DELETE or
   * UPDATE
   * *\/ */
  /*   int *pbIndirect                 /\* OUT: True for an 'indirect' change
   * *\/ */
  /* ); */
  while (sqlite3changeset_next(iter) == SQLITE_ROW) {
    rc = sqlite3changeset_op(iter, &pzTab, &pnCol, &pOp, &pbIndirect);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error in sqlite3changeset_op()\n");
      return SQLITE_ERROR;
    }

    sqlite3_value *pValue;
    switch (pOp) {
    case SQLITE_INSERT:
      printf("  CS INSERT INTO %s (indirect: %d):: ", pzTab, pbIndirect);
      for (int i = 0; i < pnCol; i++) {
        rc = sqlite3changeset_new(iter, i, &pValue);
        if (rc != SQLITE_OK) {
          fprintf(stderr, "Error in sqlite3changeset_new()\n");
          return SQLITE_ERROR;
        }
        print_change_value(pValue);
      }
      printf("\n");
      break;
    case SQLITE_DELETE:
      printf("  CS DELETE FROM %s, (indirect: %d):: ", pzTab, pbIndirect);
      for (int i = 0; i < pnCol; i++) {
        rc = sqlite3changeset_old(iter, i, &pValue);
        if (rc != SQLITE_OK) {
          fprintf(stderr, "Error in sqlite3changeset_new()\n");
          return SQLITE_ERROR;
        }
        print_change_value(pValue);
      }
      printf("\n");
      break;
    case SQLITE_UPDATE:
      printf("  CS UPDATE %s  (indirect: %d):: ", pzTab, pbIndirect);
      for (int i = 0; i < pnCol; i++) {
        rc = sqlite3changeset_old(iter, i, &pValue);
        if (rc != SQLITE_OK) {
          fprintf(stderr, "Error in sqlite3changeset_new()\n");
          return SQLITE_ERROR;
        }
        print_change_value(pValue);
      }
      printf(" => ");
      for (int i = 0; i < pnCol; i++) {
        rc = sqlite3changeset_new(iter, i, &pValue);
        if (rc != SQLITE_OK) {
          fprintf(stderr, "Error in sqlite3changeset_new()\n");
          return SQLITE_ERROR;
        }
        print_change_value(pValue);
      }
      printf("\n");
      break;
    default:
      fprintf(stderr, "Error in sqlite3changeset_op(), unknown opcode\n");
    }
  }
  sqlite3changeset_finalize(iter);
}

sqlite3_session *dolite_commit(sqlite3 *db, sqlite3_session *session,
                               char *username, char *commit_message) {

  printf("Commit message: %s\n", commit_message);

  int nChangeset;
  void *pChangeset;
  int rc = sqlite3session_changeset(session, &nChangeset, &pChangeset);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not obtain changeset: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }
  printf("Got changeset, size: %d, data:  %p\n", nChangeset, pChangeset);
  inspect_changeset(nChangeset, pChangeset);

  sqlite3_stmt *stmt;
  // dolite_hist(User TEXT, Hash TEXT, Message  TEXT, Diff BLOB)
  int64_t ts_start = clock_usecs();
  rc = sqlite3_prepare_v2(
      db, "INSERT INTO dolite_hist VALUES (NULL, DATETIME('now'), ?,?,?,?,?);",
      -1, &stmt, 0);

  if (rc != SQLITE_OK)
    exit_with_error(db, "failure fetching data: ");

  rc = sqlite3_bind_text(stmt, 1, username, strlen(username), NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind username: %s\n", sqlite3_errmsg(db));
    exit(0);
  }

  char *hash_message = "hashish";
  rc = sqlite3_bind_text(stmt, 2, hash_message, strlen(hash_message), NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind hash: %s\n", sqlite3_errmsg(db));
    exit(0);
  }

  rc = sqlite3_bind_text(stmt, 3, commit_message, strlen(commit_message), NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind commit message: %s\n", sqlite3_errmsg(db));
    exit(0);
  }

  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  char *dbhash = hash_tostring(digest, DIGEST_BYTES, 0, 'i');
  printf("\n\n base64-encoded hash: %s\n\n", dbhash);
  rc = sqlite3_bind_text(stmt, 4, dbhash, strlen(dbhash), NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db));
    exit(0);
  }
  rc = sqlite3_bind_blob(stmt, 5, pChangeset, nChangeset, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db));
    exit(0);
  }

  int64_t ts_stop = clock_usecs();
  printf("dolite_commit: compiling SQL and binding took %lu microsecs\n",
         ts_stop - ts_start);
  rc = sqlite3_step(stmt);
  int ncols = sqlite3_column_count(stmt);
  // run the SQL
  while (rc == SQLITE_ROW) {
    for (int i = 0; i < ncols; i++) {
      printf(" --  '%s' ", sqlite3_column_text(stmt, i));
    }

    printf("\n");
    rc = sqlite3_step(stmt);
  }
  free(dbhash);

  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
  sqlite3_free(pChangeset);
  sqlite3session_delete(session);

  return create_session(db);
}

char *hash_tostring(unsigned char *data, size_t length, int pad,
                    char pad_char) {
  char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  size_t extra_chars = ((length % 3) ? length % 3 + 1 : 0);
  size_t pad_chars = (pad && extra_chars) ? 4 - extra_chars : 0;
  size_t str_chars = 4 * (length / 3) + extra_chars + pad_chars;
  char *str = (char *)malloc(str_chars + 1);
  if (!str)
    return NULL;

  char *enc = str;
  const unsigned char *needle = data, *ceiling = data + length;
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
  while (pad && enc < str + str_chars)
    *enc++ = pad_char;
  *enc = 0;
  return str;
}

void hash_print(unsigned char *data, size_t length, int pad, char pad_char) {
  char *string = hash_tostring(data, length, pad, pad_char);
  printf("Hash: %s\n", string);
  free(string);
}

int main() {
  sqlite3 *db;

  char *err_msg = 0;

  int rc = sqlite3_open("test.db", &db);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }

  printf("first DB hash, empty: \t ");
  int64_t ts_start = clock_usecs();
  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  hash_print(digest, DIGEST_BYTES, 0, ';');
  int64_t ts_stop = clock_usecs();
  printf("dolite_hash_db: %lu microsecs\n", ts_stop - ts_start);
  sqlite3_session *pSession = 0;
  // Start the Session here!
  pSession = dolite_init(db);
  if (pSession == NULL) {
    fprintf(stderr, "Could not create session: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return SQLITE_ERROR;
  }

  // Do stuff
  rc = create_and_insert(db);
  if (rc != SQLITE_OK) {

    fprintf(stderr, "Cannot create table: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);

    return 1;
  }

  printf("added baseline \n");
  ts_start = clock_usecs();
  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  hash_print(digest, DIGEST_BYTES, 0, ';');
  ts_stop = clock_usecs();
  printf("dolite_hash_db: %lu microsecs\n", ts_stop - ts_start);
  pSession = dolite_commit(db, pSession, "ponsko", "initial commit");
  do_select_query(db);
  rc = insert_new_car(db, "Koeningsegg", 19999);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot insert new car: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }
  ts_start = clock_usecs();
  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  hash_print(digest, DIGEST_BYTES, 0, ';');
  ts_stop = clock_usecs();
  printf("dolite_hash_db: %lu microsecs\n", ts_stop - ts_start);
  rc = insert_new_car(db, "Volvo", 19999);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot insert new car: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }
  ts_start = clock_usecs();
  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  hash_print(digest, DIGEST_BYTES, 0, ';');
  ts_stop = clock_usecs();
  printf("dolite_hash_db: %lu microsecs\n", ts_stop - ts_start);
  rc = insert_new_car(db, "Saab", 19999);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot insert new car: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }
  printf("added Saab \n");
  pSession = dolite_commit(db, pSession, "ponsko", "added some cars");
  char *errmsg;
  rc = sqlite3_exec(db, "UPDATE Cars SET price = 99999 WHERE Name = 'Volvo';",
                    NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not update Volvo in Cars: %s\n", errmsg);
    sqlite3_close(db);
    return 1;
  }
  rc = sqlite3_exec(db, "DELETE FROM Cars WHERE Name = 'Hummer';", NULL, NULL,
                    &errmsg);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not delete Hummers from Cars: %s\n", errmsg);
    sqlite3_close(db);
    return 1;
  }

  pSession = dolite_commit(db, pSession, "ponsko", "removed hummers");
  /* do_select_query(db); */
  /* printf("Reverting last commit\n"); */
  /* dolite_revert_last_commit(db); */

  do_select_query(db);
  pSession = dolite_commit(db, pSession, "ponsko", "returned hummers");

  ts_start = clock_usecs();
  dolite_hash_db(db, &digest[0], DIGEST_BYTES);
  hash_print(digest, DIGEST_BYTES, 0, ';');
  ts_stop = clock_usecs();
  printf("dolite_hash_db: %lu microsecs\n", ts_stop - ts_start);

  printf("Closing session\n");
  sqlite3session_delete(pSession);
  printf("Closing database\n");
  rc = sqlite3_close(db);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not close database, returned: %s\n",
            error_names[rc]);
    return 1;
  }
  return 0;
}

void DumpHex(const void *data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}
