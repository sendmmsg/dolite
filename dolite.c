#define SQLITE_DQS 0
#define SQLITE_ENABLE_DBPAGE_VTAB
#define SQLITE_ENABLE_DBSTAT_VTA
#define SQLITE_ENABLE_EXPLAIN_COMMENTS
#define SQLITE_ENABLE_FTS4
#define SQLITE_ENABLE_FTS5
#define SQLITE_ENABLE_GEOPOLY
#define SQLITE_ENABLE_MATH_FUNCTIONS
#define SQLITE_ENABLE_PREUPDATE_HOOK
#define SQLITE_ENABLE_RTREE
#define SQLITE_ENABLE_SESSION
#define SQLITE_ENABLE_SESSION
#define SQLITE_ENABLE_SNAPSHOT
#define SQLITE_ENABLE_STMTVTAB
#define SQLITE_HAVE_ZLIB
#if !defined(SQLITEINT_H)
#include "sqlite3ext.h"
#endif
SQLITE_EXTENSION_INIT1
#include "dolite.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct changeset {
  int len;
  void *data;
} changeset;
/* dolite_vtab is a subclass of sqlite3_vtab which is
** underlying representation of the virtual table
*/
typedef struct dolite_vtab dolite_vtab;
struct dolite_vtab {
  sqlite3_vtab base; /* Base class - must be first */
  /* Add new fields here, as necessary */
  sqlite3_session *session;
  sqlite3 *db;
  char *dbname;
};

/* dolite_cursor is a subclass of sqlite3_vtab_cursor which will
** serve as the underlying representation of a cursor that scans
** over rows of the result
*/
typedef struct dolite_cursor dolite_cursor;
struct dolite_cursor {
  sqlite3_vtab_cursor base; /* Base class - must be first */
  /* Insert new fields here.  For this dolite we only keep track
  ** of the rowid */
  sqlite3_int64 iRowid; /* The rowid */
  changeset diff;
  sqlite3_changeset_iter *diffiter;
  char eof;
};

int sprint_change_value(sqlite3_value *pValue, char *buf) {
  if (pValue == NULL) {
    return 0;
  }
  int value_type = sqlite3_value_type(pValue);
  /* printf("Col %d: ", i); */
  switch (value_type) {
  case SQLITE_INTEGER:
    return sprintf(buf, "%lld, ", sqlite3_value_int64(pValue));
    break;
  case SQLITE_FLOAT:
    return sprintf(buf, "%f, ", sqlite3_value_double(pValue));
    break;
  case SQLITE_BLOB:
    return sprintf(buf, "[%d], ", sqlite3_value_bytes(pValue));
    break;
  case SQLITE_NULL:
    return sprintf(buf, "NULL, ");
    break;
  case SQLITE_TEXT:
    return sprintf(buf, "'%.*s', ", sqlite3_value_bytes(pValue), sqlite3_value_text(pValue));
    break;
  default:
    return sprintf(buf, "Unknown type, %d ", value_type);
    break;
  }
}
static changeset changeset_duplicate(int size, const void *changes) {
  changeset tmp;
  tmp.len = size;
  tmp.data = sqlite3_malloc(size);
  memcpy(tmp.data, changes, size);

  return tmp;
}
static int dolite_merge_staged(sqlite3 *db, char *dbname, changeset *mergeset) {
  char *err_msg = NULL;
  char *select_sql = sqlite3_mprintf("SELECT id, diff FROM dolite_%w_staged;", dbname);

  sqlite3_stmt *stmt;
  changeset in_A = {.len = 0, .data = NULL};
  changeset in_B = {.len = 0, .data = NULL};
  changeset result = {.len = 0, .data = NULL};

  int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "failure preparing statement: %s", select_sql);
    goto err;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    /* printf("Nothing in the dolite_diff table\n"); */
    goto done;
  }
  in_A = changeset_duplicate(sqlite3_column_bytes(stmt, 1), sqlite3_column_blob(stmt, 1));

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    /* printf("Only one changeset the dolite_diff table, nothing to concaternate\n"); */
    result = in_A;
    in_A.data = NULL;

    *mergeset = result;
    goto done;
  }
  in_B = changeset_duplicate(sqlite3_column_bytes(stmt, 1), sqlite3_column_blob(stmt, 1));

  rc = sqlite3changeset_concat(in_A.len, in_A.data, in_B.len, in_B.data, &result.len, &result.data);

  sqlite3_free(in_A.data);
  sqlite3_free(in_B.data);
  in_A = result;
  *mergeset = result;

  rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    in_B = changeset_duplicate(sqlite3_column_bytes(stmt, 1), sqlite3_column_blob(stmt, 1));

    rc = sqlite3changeset_concat(in_A.len, in_A.data, in_B.len, in_B.data, &result.len, &result.data);
    // Get more rows to concatenate
    sqlite3_free(in_A.data);
    sqlite3_free(in_B.data);
    in_A = result;
    *mergeset = result;
    rc = sqlite3_step(stmt);
  }

done:
  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
  sqlite3_free(select_sql);
  return SQLITE_OK;
err:
  if (err_msg)
    sqlite3_free(err_msg);
  sqlite3_close(db);
  return rc;
}
static int gen_diffstr(char *buffer, int buflen, sqlite3_changeset_iter *iter, int pOp, int pnCol) {
  sqlite3_value *pValue;
  int rc;
  int wrote = 0;
  switch (pOp) {
  case SQLITE_INSERT:
    for (int i = 0; i < pnCol; i++) {
      rc = sqlite3changeset_new(iter, i, &pValue);
      if (rc != SQLITE_OK) {
        fprintf(stderr, "Error in sqlite3changeset_new()\n");
        return SQLITE_ERROR;
      }
      wrote = sprint_change_value(pValue, buffer);
      buffer += wrote;
    }
    break;
  case SQLITE_DELETE:
    for (int i = 0; i < pnCol; i++) {
      rc = sqlite3changeset_old(iter, i, &pValue);
      if (rc != SQLITE_OK) {
        fprintf(stderr, "Error in sqlite3changeset_new()\n");
        return SQLITE_ERROR;
      }
      wrote = sprint_change_value(pValue, buffer);
      buffer += wrote;
    }
    break;
  case SQLITE_UPDATE:
    for (int i = 0; i < pnCol; i++) {
      rc = sqlite3changeset_old(iter, i, &pValue);
      if (rc != SQLITE_OK) {
        fprintf(stderr, "Error in sqlite3changeset_new()\n");
        return SQLITE_ERROR;
      }
      wrote = sprint_change_value(pValue, buffer);
      buffer += wrote;
    }
    sprintf(buffer, " => ");
    for (int i = 0; i < pnCol; i++) {
      rc = sqlite3changeset_new(iter, i, &pValue);
      if (rc != SQLITE_OK) {
        fprintf(stderr, "Error in sqlite3changeset_new()\n");
        return SQLITE_ERROR;
      }
      wrote = sprint_change_value(pValue, buffer);
      buffer += wrote;
    }
  }
}
static int session_table_filter(void *pctx, const char *table) {
  printf("session_table_filter called for table: %s\n", table);

  if (strncmp(table, "dolite_", strlen("dolite_")) == 0)
    return 0;

  return 1;
}

static sqlite3_session *create_session(sqlite3 *db) {
  printf("Creating Session\n");
  sqlite3_session *session = 0;
  // TODO: "main" should be created from argv[1] or something similar
  int rc = sqlite3session_create(db, "main", &session);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not create session: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }
  printf("object config\n");
  int val = 1;
  rc = sqlite3session_object_config(session, SQLITE_SESSION_OBJCONFIG_ROWID, &val);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error configuring Session for non-rowid tables: rc: %d,  %s (dolite.so linked correctly?)\n", rc,
            sqlite3_errmsg(db));

    /* sqlite3_close(db); */
    /* return NULL; */
  }
  assert(rc == SQLITE_OK);
  printf("attach\n");
  rc = sqlite3session_attach(session, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not attach 'ALL' to session: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }
  /* printf("setting filter\n"); */
  /* sqlite3session_table_filter(session, session_table_filter, NULL); */

  printf("Checking session status\n");
  rc = sqlite3session_enable(session, -1);
  if (rc == 1) {
    fprintf(stderr, "  Session enabled\n");
  } else if (rc == 0) {
    fprintf(stderr, "  Session disabled\n");
  }

  return session;
}
/*
** The doliteConnect() method is invoked to create a new
** template virtual table.
**
** Think of this routine as the constructor for dolite_vtab objects.
**
** All this routine needs to do is:
**
**    (1) Allocate the dolite_vtab object and initialize all fields.
**
**    (2) Tell SQLite (via the sqlite3_declare_vtab() interface) what the
**        result set of queries against the virtual table will look like.
*/
static int doliteConnect(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                         char **pzErr) {
  dolite_vtab *pNew;
  int rc;

  fprintf(stderr, "doliteConnect\n");
  rc = sqlite3_declare_vtab(db, "CREATE TABLE x(a,b)");
  /* For convenience, define symbolic names for the index to each column. */
#define DOLITE_A 0
#define DOLITE_B 1
  if (rc == SQLITE_OK) {
    pNew = sqlite3_malloc(sizeof(*pNew));
    *ppVtab = (sqlite3_vtab *)pNew;
    if (pNew == 0)
      return SQLITE_NOMEM;
    memset(pNew, 0, sizeof(*pNew));
    pNew->session = create_session(db);
    fprintf(stderr, "session created at %p\n", pNew->session);
  }
  return rc;
}

// TODO: make this take a variable number of arguments?
static void dolite_commit(sqlite3_context *context, int argc, sqlite3_value **argv) {
  changeset toinsert = {.data = NULL, .len = 0};
  dolite_vtab *pTab = (dolite_vtab *)sqlite3_user_data(context);
  const unsigned char *username = sqlite3_value_text(argv[0]);
  const unsigned char *message = sqlite3_value_text(argv[1]);

  dolite_merge_staged(pTab->db, pTab->dbname, &toinsert);
  if (toinsert.len < 1) {
    char *pOut = sqlite3_mprintf("dolite_commit: nothing to commit, changeset size: %d", toinsert.len);
    sqlite3_result_text(context, pOut, strlen(pOut), sqlite3_free);
    return;
  }

  sqlite3_stmt *stmt;
  char *insert_sql = sqlite3_mprintf("INSERT INTO dolite_%w_diff VALUES (NULL, DATETIME('now'), ?);", pTab->dbname);
  int rc = sqlite3_prepare_v2(pTab->db, insert_sql, -1, &stmt, 0);
  sqlite3_free(insert_sql);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error preparing dolite_%s_diff statement: %s \n", pTab->dbname, insert_sql);
    char *pOut = sqlite3_mprintf("dolite_commit: error preparing insert statement: %s", insert_sql);
    sqlite3_result_text(context, pOut, strlen(pOut), sqlite3_free);
    return;
  }

#define DIGEST_BYTES 1024
  unsigned char digest[DIGEST_BYTES];
  dolite_hash_blob(&digest[0], DIGEST_BYTES, toinsert.data, toinsert.len);
  char *changeset_hash = hash_tostring(digest, DIGEST_BYTES, 0, 'i');
  printf("\n\n base64-encoded hash: %s\n\n", changeset_hash);

  /* rc = sqlite3_bind_text(stmt, 2, changeset_hash, strlen(changeset_hash), NULL); */
  /* if (rc != SQLITE_OK) { */
  /*   fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db)); */
  /*   exit(0); */
  /* } */
  rc = sqlite3_bind_blob(stmt, 1, pCur->diff.data, pCur->diff.len, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(p->db));
    return SQLITE_ERROR;
  }

  /* int64_t ts_stop = clock_usecs(); */
  /* printf("dolite_commit: compiling SQL and binding took %lu microsecs\n", */
  /*        ts_stop - ts_start); */
  rc = sqlite3_step(stmt);
  /* int ncols = sqlite3_column_count(stmt); */
  // run the SQL
  while (rc == SQLITE_ROW) {
    /* for (int i = 0; i < ncols; i++) { */
    /*   printf(" --  '%s' ", sqlite3_column_text(stmt, i)); */
    /* } */

    /* printf("\n"); */
    rc = sqlite3_step(stmt);
  }
  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
  sqlite3_free(pCur->diff.data);
  sqlite3session_delete(p->session);
  p->session = create_session(p->db);
}

static int doliteCreate(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                        char **pzErr) {
  dolite_vtab *pNew;
  int rc;
  char *err_msg = 0;
  fprintf(stderr, "doliteCreate\n");

  char *vtab_log_cmd = sqlite3_mprintf("CREATE TABLE dolite_%w_changes (id INTEGER PRIMARY KEY, operation TEXT, "
                                       "indirect INTEGER, mtab TEXT, diff TEXT);",
                                       argv[2]);

  char *staged_cmd =
      sqlite3_mprintf("CREATE TABLE dolite_%w_staged (id INTEGER PRIMARY KEY, ts DATETIME, diff BLOB);", argv[2]);
  rc = sqlite3_exec(db, staged_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table dolite_%s_hist table: %s\n", argv[2], err_msg);
    sqlite3_free(err_msg);
  }
  char *diff_cmd = sqlite3_mprintf(
      "CREATE TABLE dolite_%w_diffs (id INTEGER PRIMARY KEY, ts DATETIME, user TEXT, message TEXT, diff BLOB);",
      argv[2]);

  rc = sqlite3_exec(db, diff_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table dolite_%s_hist table: %s\n", argv[2], err_msg);
    sqlite3_free(err_msg);
  }
  rc = sqlite3_declare_vtab(db, vtab_log_cmd);

  /*   /\* For convenience, define symbolic names for the index to each column. *\/ */
  /* #define DOLITE_A 0 */
  /* #define DOLITE_B 1 */
  if (rc == SQLITE_OK) {
    pNew = sqlite3_malloc(sizeof(*pNew));
    *ppVtab = (sqlite3_vtab *)pNew;
    if (pNew == 0) // TODO: handle all resources correctly
      return SQLITE_NOMEM;

    memset(pNew, 0, sizeof(*pNew));
    pNew->session = create_session(db);
    pNew->db = db;
    pNew->dbname = sqlite3_mprintf("%w", argv[2]);
    fprintf(stderr, "session created at %p\n", pNew->session);
  }
  // TODO: handle all resources correctly
  sqlite3_free(vtab_log_cmd);
  sqlite3_free(staged_cmd);
  sqlite3_free(diff_cmd);

  rc = sqlite3_create_function(db, "dolite_commit", 2, SQLITE_UTF8 | SQLITE_INNOCUOUS, pNew, dolite_commit, 0, 0);

  return rc;
}

/*
** This method is the destructor for dolite_vtab objects.
*/
static int doliteDisconnect(sqlite3_vtab *pVtab) {
  fprintf(stderr, "doliteDisconnect\n");
  dolite_vtab *p = (dolite_vtab *)pVtab;
  sqlite3_free(p);
  return SQLITE_OK;
}

static int doliteDestroy(sqlite3_vtab *pVtab) {
  fprintf(stderr, "doliteDestroy\n");
  dolite_vtab *p = (dolite_vtab *)pVtab;
  sqlite3_free(p);
  return SQLITE_OK;
}
/*
** Constructor for a new dolite_cursor object.
*/
static int doliteOpen(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor) {
  fprintf(stderr, "doliteOpen\n");
  dolite_cursor *pCur;
  dolite_vtab *p = (dolite_vtab *)pVtab;

  // SQLITE_API int sqlite3session_isempty(sqlite3_session * pSession);
  pCur = sqlite3_malloc(sizeof(*pCur));
  if (pCur == 0)
    return SQLITE_NOMEM;
  memset(pCur, 0, sizeof(*pCur));
  *ppCursor = &pCur->base;

  int rc = sqlite3session_changeset(p->session, &(pCur->diff.len), &(pCur->diff.data));
  if (rc != SQLITE_OK) {
    fprintf(stderr, "failure fetching changeset: session %p rc: %d. %s\n", p->session, rc, error_names[rc]);
  }
  fprintf(stderr, "nchange %d pchange %p\n", pCur->diff.len, pCur->diff.data);

  // Add diff to temp table
  if (pCur->diff.len > 0) {

    sqlite3_stmt *stmt;
    /* int64_t ts_start = clock_usecs(); */
    char *insert_sql = sqlite3_mprintf("INSERT INTO dolite_%w_staged VALUES (NULL, DATETIME('now'), ?);", p->dbname);
    rc = sqlite3_prepare_v2(p->db, insert_sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error preparing dolite_%s_staged statement: %s \n", p->dbname, insert_sql);
      return SQLITE_ERROR;
    }
    sqlite3_free(insert_sql);

    /* dolite_hash_blob(&digest[0], DIGEST_BYTES, pChangeset, nChangeset); */
    /* char *changeset_hash = hash_tostring(digest, DIGEST_BYTES, 0, 'i'); */
    /* printf("\n\n base64-encoded hash: %s\n\n", changeset_hash); */

    /* rc = sqlite3_bind_text(stmt, 2, changeset_hash, strlen(changeset_hash), NULL); */
    /* if (rc != SQLITE_OK) { */
    /*   fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db)); */
    /*   exit(0); */
    /* } */
    rc = sqlite3_bind_blob(stmt, 1, pCur->diff.data, pCur->diff.len, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(p->db));
      return SQLITE_ERROR;
    }

    /* int64_t ts_stop = clock_usecs(); */
    /* printf("dolite_commit: compiling SQL and binding took %lu microsecs\n", */
    /*        ts_stop - ts_start); */
    rc = sqlite3_step(stmt);
    /* int ncols = sqlite3_column_count(stmt); */
    // run the SQL
    while (rc == SQLITE_ROW) {
      /* for (int i = 0; i < ncols; i++) { */
      /*   printf(" --  '%s' ", sqlite3_column_text(stmt, i)); */
      /* } */

      /* printf("\n"); */
      rc = sqlite3_step(stmt);
    }
    // destroy the object to avoid resource leaks
    sqlite3_finalize(stmt);
    sqlite3_free(pCur->diff.data);
    sqlite3session_delete(p->session);
    p->session = create_session(p->db);
  }

  dolite_merge_staged(p->db, p->dbname, &(pCur->diff));
  // TODO:
  rc = sqlite3changeset_start(&(pCur->diffiter), pCur->diff.len, pCur->diff.data);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error obtaining changeset iterator\n");
  }
  return SQLITE_OK;
}

/*
** Destructor for a dolite_cursor.
*/
static int doliteClose(sqlite3_vtab_cursor *cur) {
  fprintf(stderr, "doliteClose\n");
  dolite_cursor *pCur = (dolite_cursor *)cur;
  sqlite3changeset_finalize(pCur->diffiter);
  sqlite3_free(pCur->diff.data);
  sqlite3_free(pCur);
  fprintf(stderr, "doliteClose, done\n");
  return SQLITE_OK;
}

/*
** Advance a dolite_cursor to its next row of output.
*/
static int doliteNext(sqlite3_vtab_cursor *cur) {
  dolite_cursor *pCur = (dolite_cursor *)cur;
  /* if (sqlite3changeset_next(pCur->diffiter) == SQLITE_ROW) { */
  /*   // We have another row, great, EOF not set */
  /*   pCur->eof = 0; */
  /*   pCur->iRowid++; */
  /*   fprintf(stderr, "doliteNext EOF = 0\n"); */
  /* } else { */
  /*   // No more rows, set EOF */
  /*   // xEof() will use it */
  /*   pCur->eof = 1; */
  /*   fprintf(stderr, "doliteNext EOF = 1\n"); */
  /* } */
  return SQLITE_OK;
}

/*
** Return values of columns for the row at which the dolite_cursor
** is currently pointing.
*/
static int doliteColumn(sqlite3_vtab_cursor *cur, /* The cursor */
                        sqlite3_context *ctx,     /* First argument to sqlite3_result_...() */
                        int i                     /* Which column to return */
) {

  /* fprintf(stderr, "doliteColumn, %d\n", i); */
  dolite_cursor *pCur = (dolite_cursor *)cur;
  if (pCur->eof)
    return SQLITE_ERROR;
  char buffer[1024];
  const char *pzTab;
  int pnCol;
  int pOp;
  int pbIndirect;
  int rc = sqlite3changeset_op(pCur->diffiter, &pzTab, &pnCol, &pOp, &pbIndirect);
  char *operation;
  switch (pOp) {
  case SQLITE_INSERT:
    operation = "INSERT";
    break;
  case SQLITE_UPDATE:
    operation = "UPDATE";
    break;
  case SQLITE_DELETE:
    operation = "DELETE";
    break;
  default:
    fprintf(stderr, "doliteColumn: pOp invalid!\n");
    return SQLITE_ERROR;
  }
  switch (i) {
  case 0:
    sqlite3_result_int(ctx, pCur->iRowid);
    break;
  case 1:
    sqlite3_result_text(ctx, operation, 6, NULL);
    break;
  case 2:
    sqlite3_result_int(ctx, pbIndirect);
    break;
  case 3:
    sqlite3_result_text(ctx, pzTab, strlen(pzTab), NULL);
    break;
  case 4:
    gen_diffstr(buffer, 1024, pCur->diffiter, pOp, pnCol);
    char *outstr = sqlite3_mprintf("%w", buffer);
    sqlite3_result_text(ctx, outstr, strlen(outstr), NULL);
    break;
  default:
    assert(i < 4);
    break;
  }
  return SQLITE_OK;
}

/*
** Return the rowid for the current row.  In this implementation, the
** rowid is the same as the output value.
*/
static int doliteRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  fprintf(stderr, "doliteRowid\n");
  dolite_cursor *pCur = (dolite_cursor *)cur;
  *pRowid = pCur->iRowid;
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int doliteEof(sqlite3_vtab_cursor *cur) {
  dolite_cursor *pCur = (dolite_cursor *)cur;
  pCur->iRowid++;
  if (sqlite3changeset_next(pCur->diffiter) == SQLITE_ROW) {
    // We have another row, great, EOF not set
    pCur->eof = 0;
    /* fprintf(stderr, "doliteEof EOF = 0\n"); */
  } else {
    // No more rows, set EOF
    // xEof() will use it
    pCur->eof = 1;
    /* fprintf(stderr, "doliteEof EOF = 1\n"); */
  }
  /* fprintf(stderr, "doliteEof -> returning %d\n", pCur->eof); */
  return pCur->eof;
}

/*
** This method is called to "rewind" the dolite_cursor object back
** to the first row of output.  This method is always called at least
** once prior to any call to doliteColumn() or doliteRowid() or
** doliteEof().
*/
static int doliteFilter(sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStr, int argc,
                        sqlite3_value **argv) {
  fprintf(stderr, "doliteFilter\n");
  dolite_cursor *pCur = (dolite_cursor *)pVtabCursor;
  pCur->iRowid = 0;
  if (pCur->diff.len == 0)
    pCur->eof = 1;

  if (sqlite3changeset_next(pCur->diffiter) == SQLITE_ROW) {
    // We have another row, great, EOF not set
    pCur->eof = 0;
    pCur->iRowid++;
    fprintf(stderr, "doliteFilter EOF = 0\n");
  } else {
    // No more rows, set EOF
    // xEof() will use it
    pCur->eof = 1;
    fprintf(stderr, "doliteFilter EOF = 1\n");
  }

  return SQLITE_OK;
}

/*
** SQLite will invoke this method one or more times while planning a query
** that uses the virtual table.  This routine needs to create
** a query plan for each invocation and compute an estimated cost for that
** plan.
*/
static int doliteBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) { return SQLITE_OK; }

/*
** This following structure defines all the methods for the
** virtual table.
*/
static sqlite3_module doliteModule = {/* iVersion    */ .iVersion = 0,
                                      /* xCreate     */ doliteCreate,
                                      /* xConnect    */ doliteConnect,
                                      /* xBestIndex  */ doliteBestIndex,
                                      /* xDisconnect */ doliteDisconnect,
                                      /* xDestroy    */ doliteDestroy,
                                      /* xOpen       */ doliteOpen,
                                      /* xClose      */ doliteClose,
                                      /* xFilter     */ doliteFilter,
                                      /* xEof        */ doliteEof,
                                      /* xNext       */ doliteNext,
                                      /* xColumn     */ doliteColumn,
                                      /* xRowid      */ doliteRowid,
                                      /* xUpdate     */ 0,
                                      /* xBegin      */ 0,
                                      /* xSync       */ 0,
                                      /* xCommit     */ 0,
                                      /* xRollback   */ 0,
                                      /* xFindMethod */ 0,
                                      /* xRename     */ 0,
                                      /* xSavepoint  */ 0,
                                      /* xRelease    */ 0,
                                      /* xRollbackTo */ 0,
                                      /* xShadowName */ 0,
                                      /* xIntegrity  */ 0};

#ifdef _WIN32
__declspec(dllexport)
#endif

    int sqlite3_dolite_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
  fprintf(stderr, "sqlite3_dolite_init called\n");

  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
  rc = sqlite3_create_module(db, "dolite", &doliteModule, 0);
  fprintf(stderr, "sqlite3_create_module, returned %d \n", rc);

  return rc;
}

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t b64_encoded_size(size_t inlen) {
  size_t ret;

  ret = inlen;
  if (inlen % 3 != 0)
    ret += 3 - (inlen % 3);
  ret /= 3;
  ret *= 4;

  return ret;
}
static size_t b64_decoded_size(const char *in) {
  size_t len;
  size_t ret;
  size_t i;

  if (in == NULL)
    return 0;

  len = strlen(in);
  ret = len / 4 * 3;

  for (i = len; i-- > 0;) {
    if (in[i] == '=') {
      ret--;
    } else {
      break;
    }
  }
  return ret;
}
static char *b64_encode(const unsigned char *in, size_t len) {
  char *out;
  size_t elen;
  size_t i;
  size_t j;
  size_t v;

  if (in == NULL || len == 0)
    return NULL;

  elen = b64_encoded_size(len);
  out = sqlite3_malloc(elen + 1);
  out[elen] = '\0';

  for (i = 0, j = 0; i < len; i += 3, j += 4) {
    v = in[i];
    v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
    v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

    out[j] = b64chars[(v >> 18) & 0x3F];
    out[j + 1] = b64chars[(v >> 12) & 0x3F];
    if (i + 1 < len) {
      out[j + 2] = b64chars[(v >> 6) & 0x3F];
    } else {
      out[j + 2] = '=';
    }
    if (i + 2 < len) {
      out[j + 3] = b64chars[v & 0x3F];
    } else {
      out[j + 3] = '=';
    }
  }

  return out;
}
static int b64invs[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1,
                        -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17,
                        18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31,
                        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};
int b64_isvalidchar(char c) {
  if (c >= '0' && c <= '9')
    return 1;
  if (c >= 'A' && c <= 'Z')
    return 1;
  if (c >= 'a' && c <= 'z')
    return 1;
  if (c == '+' || c == '/' || c == '=')
    return 1;
  return 0;
}
static int b64_decode(const char *in, unsigned char *out, size_t outlen) {
  size_t len;
  size_t i;
  size_t j;
  int v;

  if (in == NULL || out == NULL)
    return 0;

  len = strlen(in);
  if (outlen < b64_decoded_size(in) || len % 4 != 0)
    return 0;

  for (i = 0; i < len; i++) {
    if (!b64_isvalidchar(in[i])) {
      return 0;
    }
  }

  for (i = 0, j = 0; i < len; i += 4, j += 3) {
    v = b64invs[in[i] - 43];
    v = (v << 6) | b64invs[in[i + 1] - 43];
    v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
    v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

    out[j] = (v >> 16) & 0xFF;
    if (in[i + 2] != '=')
      out[j + 1] = (v >> 8) & 0xFF;
    if (in[i + 3] != '=')
      out[j + 2] = v & 0xFF;
  }

  return 1;
}
