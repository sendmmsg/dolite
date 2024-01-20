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
#include "b64.h"
#include "dbhash.c"
#include "dolite.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define DIGEST_BYTES 32

const char *create_dolite_config_sql = "CREATE TABLE dolite_config ("
                                       "id INTEGER PRIMARY KEY,"
                                       "key TEXT,"
                                       "value TEXT);";
const char *create_v_changes_sql = "CREATE TABLE %w_changes ("
                                   "id INTEGER PRIMARY KEY,"
                                   "operation TEXT,"
                                   "indirect INTEGER,"
                                   "tab TEXT,"
                                   "diff TEXT);";
const char *create_staged_sql = "CREATE TABLE %w_staged ("
                                "id INTEGER PRIMARY KEY,"
                                "ts DATETIME,"
                                "diff BLOB);";
const char *create_ignore_sql = "CREATE TABLE %w_ignore ("
                                "id INTEGER PRIMARY KEY,"
                                "mtab TEXT);";
const char *create_commits_sql = "CREATE TABLE %w_commits ("
                                 "id INTEGER PRIMARY KEY,"
                                 "ts DATETIME,"
                                 "user TEXT,"
                                 "message TEXT,"
                                 "hash TEXT,"
                                 "parent TEXT,"
                                 "diff BLOB);";
const char *create_branches_sql = "CREATE TABLE %w_branches ("
                                  "branch TEXT PRIMARY KEY,"
                                  "hash TEXT);";
const char *create_v_logs_sql = "CREATE TABLE %w_logs ("
                                "id INTEGER PRIMARY KEY,"
                                "ts DATETIME,"
                                "user TEXT,"
                                "message TEXT,"
                                "hash TEXT);";
const char *cte_commits_sql = "WITH RECURSIVE cte_commits (id, hash, parent) AS ("
                              "SELECT e.id, e.hash, e.parent "
                              "FROM %w_commits e "
                              "WHERE e.hash = '%w' "
                              "UNION ALL "
                              "SELECT e.id, e.hash, e.parent "
                              "FROM %w_commits e "
                              "JOIN cte_commits c ON c.parent = e.hash "
                              ") "
                              "SELECT * FROM cte_commits;";

typedef struct changeset {
  int len;
  void *data;
} changeset;
typedef struct dolite_vtab dolite_vtab;
struct dolite_vtab {
  sqlite3_vtab base;
  sqlite3_session *session;
  sqlite3 *db;
  char *dbname;
};

typedef struct dolite_cursor dolite_cursor;
struct dolite_cursor {
  sqlite3_vtab_cursor base;
  sqlite3_int64 iRowid;
  changeset diff;
  sqlite3_changeset_iter *diffiter;
  char eof;
};

int sprint_change_value(sqlite3_value *pValue, char *buf) {
  if (pValue == NULL) {
    return 0;
  }
  int value_type = sqlite3_value_type(pValue);
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
  char *select_sql = sqlite3_mprintf("SELECT id, diff FROM %w_staged;", dbname);

  sqlite3_stmt *stmt;
  changeset in_A = {.len = 0, .data = NULL};
  changeset in_B = {.len = 0, .data = NULL};
  changeset result = {.len = 0, .data = NULL};

  int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);
  sqlite3_free(select_sql);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "failure preparing statement: %s", select_sql);
    goto done;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    goto done;
  }
  in_A = changeset_duplicate(sqlite3_column_bytes(stmt, 1), sqlite3_column_blob(stmt, 1));

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
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

  rc = SQLITE_OK;
done:
  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
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
  return SQLITE_ERROR;
}

// Caller must free return if != NULL
static char *dolite_config_get(sqlite3 *db, char *key) {
  sqlite3_stmt *stmt;
  char *get_key_sql = sqlite3_mprintf("SELECT value FROM dolite_config WHERE key = '%w';", key);
  fprintf(stderr, "dolite_config_get: get_key_sql %s\n", get_key_sql);
  char *key_value = 0;
  int rc = sqlite3_prepare_v2(db, get_key_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "dolite_config_get: failed to prepare %s\n", sqlite3_errmsg(db));
  }
  assert(rc == SQLITE_OK);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "dolite_config_get: no_rows!\n");
    goto done;
  }
  char *res = (char *)sqlite3_column_text(stmt, 0);
  fprintf(stderr, "dolite_config_get: key_value => %s\n", res);
  if (res != NULL)
    key_value = sqlite3_mprintf("%w", res);

done:
  sqlite3_finalize(stmt);
  sqlite3_free(get_key_sql);

  return key_value;
}
static int session_table_filter(void *pctx, const char *table) {
  sqlite3 *db = (sqlite3 *)pctx;
  int is_in_ignore = 0;
  char *dbname = dolite_config_get(db, "DBNAME");
  fprintf(stderr, "dolite_config_get('DBNAME') returned -> %s\n", dbname);
  if (dbname == NULL)
    goto clean_dbname;

  char *is_in_ignore_sql = sqlite3_mprintf("SELECT count(*) FROM %w_ignore WHERE mtab = '%w';", dbname, table);
  fprintf(stderr, "dolite_config_get: SQL %s", is_in_ignore_sql);
  if (is_in_ignore_sql == NULL)
    goto clean_sql;

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, is_in_ignore_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "session_table_filter: failed to prepare %s\n", sqlite3_errmsg(db));
    goto clean_stmt;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "session_table_filter: failed to obtain value %s\n", sqlite3_errmsg(db));
  }

  is_in_ignore = sqlite3_column_int64(stmt, 0);
  fprintf(stderr, "dolite_config_get: is_in_igonore %d", is_in_ignore);

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(is_in_ignore_sql);
clean_dbname:
  sqlite3_free(dbname);

  fprintf(stderr, "session_table_filter: tracking changes to: %s, retval: %d \n", table, is_in_ignore);
  if (is_in_ignore)
    return 0;

  return 1;
}

static sqlite3_session *create_session(sqlite3 *db) {
  sqlite3_session *session = 0;
  int rc = sqlite3session_create(db, "main", &session);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not create session: %s\n", sqlite3_errmsg(db));
  }
  assert(rc == SQLITE_OK);
  int val = 1;
  rc = sqlite3session_object_config(session, SQLITE_SESSION_OBJCONFIG_ROWID, &val);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error configuring Session for non-rowid tables: rc: %d,  %s (dolite.so linked correctly?)\n", rc,
            sqlite3_errmsg(db));
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3session_attach(session, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Could not attach 'ALL' to session: %s\n", sqlite3_errmsg(db));
  }
  assert(rc == SQLITE_OK);
  sqlite3session_table_filter(session, session_table_filter, db);

  rc = sqlite3session_enable(session, -1);
  assert(rc == 1);

  return session;
}

static void dolite_clean_staged(sqlite3 *db, char *dbname) {
  sqlite3_stmt *stmt;
  char *delete_from_sql = sqlite3_mprintf("DELETE FROM %w_staged;", dbname);
  int rc = sqlite3_prepare_v2(db, delete_from_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "dolite_clean_staged: failed to prepare %s\n", sqlite3_errmsg(db));
  }
  sqlite3_free(delete_from_sql);

  rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    rc = sqlite3_step(stmt);
  }

  sqlite3_finalize(stmt);
}

static char *dolite_checkout(sqlite3 *db, sqlite3_session **session, char *dbname, char *hash) {
  return sqlite3_mprintf(
      "TODO: Revert and remove commits to go back in history. Option for just changing data but keeping diffs?");
}
static void dolite_checkout_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_vtab *pTab = (dolite_vtab *)sqlite3_user_data(context);
  const char *hash = (const char *)sqlite3_value_text(argv[0]);
  char *result = dolite_checkout(pTab->db, &(pTab->session), pTab->dbname, hash);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}
static char *dolite_revert(sqlite3 *db, sqlite3_session **session, char *dbname, char *hash) {
  return sqlite3_mprintf(
      "TODO: check if anything in session (dirty), iff fail.  invert and apply diff with hash. commit staged.");
}
static void dolite_revert_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_vtab *pTab = (dolite_vtab *)sqlite3_user_data(context);
  const char *hash = (const char *)sqlite3_value_text(argv[0]);
  char *result = dolite_revert(pTab->db, &(pTab->session), pTab->dbname, hash);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}
static char *dolite_reset(sqlite3 *db, sqlite3_session **session, char *dbname) {
  return sqlite3_mprintf("TODO: Undo changes in **session, and all in _staged. Clear _staged. No session kept");
}
static void dolite_reset_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_vtab *pTab = (dolite_vtab *)sqlite3_user_data(context);
  char *result = dolite_reset(pTab->db, &(pTab->session), pTab->dbname);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}

static char *dolite_commit(sqlite3 *db, sqlite3_session **session, char *dbname, const char *username,
                           const char *message);

// TODO: make this take a variable number of arguments?
static void dolite_commit_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_vtab *pTab = (dolite_vtab *)sqlite3_user_data(context);
  const char *username = (const char *)sqlite3_value_text(argv[0]);
  const char *message = (const char *)sqlite3_value_text(argv[1]);
  char *result = dolite_commit(pTab->db, &(pTab->session), pTab->dbname, username, message);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}

// TODO: Wrap in BEGIN/COMMIT
static char *dolite_commit(sqlite3 *db, sqlite3_session **session, char *dbname, const char *username,
                           const char *message) {
  changeset toinsert = {.data = NULL, .len = 0};
  unsigned char digest[DIGEST_BYTES];
  sqlite3_stmt *stmt = NULL;

  // Get everything from _staged
  dolite_merge_staged(db, dbname, &toinsert);
  if (toinsert.len < 1) {
    char *pOut = sqlite3_mprintf("dolite_commit: nothing to commit, changeset size: %d", toinsert.len);
    return pOut;
  }

  // Insert in _diffs
  char *insert_sql = sqlite3_mprintf("INSERT INTO %w_commits VALUES (NULL, DATETIME('now'), ?, ?, ?, ?, ?);", dbname);
  int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    const char *err_msg = sqlite3_errmsg(db);
    sqlite3_free(insert_sql);
    char *pOut = sqlite3_mprintf("dolite_commit: error preparing insert statement: %s", insert_sql);
    return pOut;
  }
  sqlite3_free(insert_sql);
  dolite_hash_blob(&digest[0], DIGEST_BYTES, toinsert.data, toinsert.len);
  char *diff_hash = b64_encode(digest, DIGEST_BYTES, sqlite3_malloc);

  rc = sqlite3_bind_text(stmt, 1, username, strlen(username), NULL);
  if (rc != SQLITE_OK) {
    char *pOut = sqlite3_mprintf("dolite_commit: failed to bind text: %s", sqlite3_errmsg(db));
    return pOut;
  }
  rc = sqlite3_bind_text(stmt, 2, message, strlen(message), NULL);
  if (rc != SQLITE_OK) {
    char *pOut = sqlite3_mprintf("dolite_commit: failed to bind text: %s", sqlite3_errmsg(db));
    return pOut;
  }
  rc = sqlite3_bind_text(stmt, 3, diff_hash, strlen(diff_hash), NULL);
  if (rc != SQLITE_OK) {
    char *pOut = sqlite3_mprintf("dolite_commit: failed to bind text: %s", sqlite3_errmsg(db));
    return pOut;
  }
  rc = sqlite3_bind_blob(stmt, 4, toinsert.data, toinsert.len, NULL);
  if (rc != SQLITE_OK) {
    char *pOut = sqlite3_mprintf("dolite_commit: failed to bind blob: %s", sqlite3_errmsg(db));
    return pOut;
  }

  rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    rc = sqlite3_step(stmt);
  }

  sqlite3_finalize(stmt);
  sqlite3_free(toinsert.data);

  sqlite3session_delete(*session);
  *session = create_session(db);

  dolite_clean_staged(db, dbname);

  char *pOut = sqlite3_mprintf("dolite_commit: new commit %s", diff_hash);
  return pOut;
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
static int dolite_changes_Connect(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                                  char **pzErr) {
  dolite_vtab *pNew;
  int rc;

  fprintf(stderr, "dolite_changes_Connect\n");
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
static int create_all_tables(sqlite3 *db, const char *dbname) {
  char *err_msg = 0;
  char *staged_cmd = sqlite3_mprintf(create_staged_sql, dbname);
  char *commits_cmd = sqlite3_mprintf(create_commits_sql, dbname);
  char *branch_cmd = sqlite3_mprintf(create_branches_sql, dbname);
  char *ignore_cmd = sqlite3_mprintf(create_ignore_sql, dbname);
  char *config_cmd = sqlite3_mprintf(create_dolite_config_sql, dbname);

  int rc = sqlite3_exec(db, config_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table dolite_config table on %s: %s\n", dbname, err_msg);
    goto done;
  }
  rc = sqlite3_exec(db, staged_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table %s_staged table: %s\n", dbname, err_msg);
    goto done;
  }

  rc = sqlite3_exec(db, commits_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table %s_commits table: %s\n", dbname, err_msg);
    goto done;
  }

  rc = sqlite3_exec(db, branch_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table %s_branch table: %s\n", dbname, err_msg);
    goto done;
  }
  rc = sqlite3_exec(db, ignore_cmd, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating table %s_ignore table: %s\n", dbname, err_msg);
    goto done;
  }
  char *tables[] = {sqlite3_mprintf("%w_staged", dbname),   sqlite3_mprintf("%w_ignore", dbname),
                    sqlite3_mprintf("%w_branches", dbname), sqlite3_mprintf("%w_commits", dbname),
                    sqlite3_mprintf("dolite_config"),       NULL};

  int i = 0;
  char *table = tables[i];
  while (table != NULL) {
    char *cmd = sqlite3_mprintf("INSERT INTO %w_ignore VALUES (NULL, '%w');", dbname, table);
    rc = sqlite3_exec(db, cmd, 0, 0, &err_msg);
    sqlite3_free(cmd);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error adding table to %s_ignore table: %s\n", dbname, err_msg);
      goto done;
    }
    sqlite3_free(table);
    table = tables[++i];
  }

  char *cmd = sqlite3_mprintf("INSERT INTO dolite_config VALUES (NULL, 'DBNAME', '%w');", dbname);
  rc = sqlite3_exec(db, cmd, 0, 0, &err_msg);
  sqlite3_free(cmd);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error setting 'DBNAME' configuration in dolite_config: %s\n", dbname, err_msg);
    goto done;
  }

done:
  sqlite3_free(staged_cmd);
  sqlite3_free(commits_cmd);
  sqlite3_free(branch_cmd);
  sqlite3_free(ignore_cmd);
  return rc;
}
static int dolite_changes_Create(sqlite3 *db, void *pAux, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                                 char **pzErr) {
  dolite_vtab *pNew;
  int rc;
  char *err_msg = 0;
  /* fprintf(stderr, "doliteCreate\n"); */
  create_all_tables(db, argv[2]);
  char *vtab_changes_cmd = sqlite3_mprintf(create_v_changes_sql, argv[2]);
  rc = sqlite3_declare_vtab(db, vtab_changes_cmd);

  /*   /\* For convenience, define symbolic names for the index to each column. *\/ */
  if (rc == SQLITE_OK) {
    pNew = sqlite3_malloc(sizeof(*pNew));
    *ppVtab = (sqlite3_vtab *)pNew;
    if (pNew == 0) // TODO: handle all resources correctly
      return SQLITE_NOMEM;

    memset(pNew, 0, sizeof(*pNew));
    pNew->session = create_session(db);
    pNew->db = db;
    pNew->dbname = sqlite3_mprintf("%w", argv[2]);
    rc = sqlite3_create_function(db, "dolite_commit", 2, SQLITE_UTF8 | SQLITE_INNOCUOUS, pNew, dolite_commit_cmd, 0, 0);
    rc = sqlite3_create_function(db, "dolite_reset", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS, pNew, dolite_reset_cmd, 0, 0);
    rc = sqlite3_create_function(db, "dolite_revert", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS, pNew, dolite_reset_cmd, 0, 0);
    rc = sqlite3_create_function(db, "dolite_checkout", 1, SQLITE_UTF8 | SQLITE_INNOCUOUS, pNew, dolite_checkout_cmd, 0,
                                 0);
  }
  // TODO: handle all resources correctly
  sqlite3_free(vtab_changes_cmd);

  return rc;
}

/*
** This method is the destructor for dolite_vtab objects.
*/
static int dolite_changes_Disconnect(sqlite3_vtab *pVtab) {
  fprintf(stderr, "dolite_changes_Disconnect\n");
  dolite_vtab *p = (dolite_vtab *)pVtab;
  sqlite3_free(p);
  return SQLITE_OK;
}

static int dolite_changes_Destroy(sqlite3_vtab *pVtab) {
  fprintf(stderr, "dolite_changes_Destroy\n");
  dolite_vtab *p = (dolite_vtab *)pVtab;
  sqlite3_free(p);
  return SQLITE_OK;
}
/*
** Constructor for a new dolite_cursor object.
*/
static int dolite_changes_Open(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor) {
  fprintf(stderr, "dolite_changes_Open\n");
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
    char *insert_sql = sqlite3_mprintf("INSERT INTO %w_staged VALUES (NULL, DATETIME('now'), ?);", p->dbname);
    rc = sqlite3_prepare_v2(p->db, insert_sql, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error preparing %s_staged statement: %s \n", p->dbname, insert_sql);
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
static int dolite_changes_Close(sqlite3_vtab_cursor *cur) {
  fprintf(stderr, "dolite_changes_Close\n");
  dolite_cursor *pCur = (dolite_cursor *)cur;
  sqlite3changeset_finalize(pCur->diffiter);
  sqlite3_free(pCur->diff.data);
  sqlite3_free(pCur);
  fprintf(stderr, "dolite_changes_Close, done\n");
  return SQLITE_OK;
}

/*
** Advance a dolite_cursor to its next row of output.
*/
static int dolite_changes_Next(sqlite3_vtab_cursor *cur) {
  /* dolite_cursor *pCur = (dolite_cursor *)cur; */
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
static int dolite_changes_Column(sqlite3_vtab_cursor *cur, /* The cursor */
                                 sqlite3_context *ctx,     /* First argument to sqlite3_result_...() */
                                 int i                     /* Which column to return */
) {

  /* fprintf(stderr, "dolite_changes_Column, %d\n", i); */
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
    fprintf(stderr, "dolite_changes_Column: pOp invalid!\n");
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
static int dolite_changes_Rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  fprintf(stderr, "dolite_changes_Rowid\n");
  dolite_cursor *pCur = (dolite_cursor *)cur;
  *pRowid = pCur->iRowid;
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int dolite_changes_Eof(sqlite3_vtab_cursor *cur) {
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
  fprintf(stderr, "dolite_changes_Eof -> returning %d\n", pCur->eof);
  return pCur->eof;
}

/*
** This method is called to "rewind" the dolite_cursor object back
** to the first row of output.  This method is always called at least
** once prior to any call to doliteColumn() or doliteRowid() or
** doliteEof().
*/
static int dolite_changes_Filter(sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStr, int argc,
                                 sqlite3_value **argv) {
  fprintf(stderr, "dolite_changes_Filter\n");
  dolite_cursor *pCur = (dolite_cursor *)pVtabCursor;
  pCur->iRowid = 0;
  if (pCur->diff.len == 0)
    pCur->eof = 1;

  if (sqlite3changeset_next(pCur->diffiter) == SQLITE_ROW) {
    // We have another row, great, EOF not set
    pCur->eof = 0;
    pCur->iRowid++;
    /* fprintf(stderr, "doliteFilter EOF = 0\n"); */
  } else {
    // No more rows, set EOF
    // xEof() will use it
    pCur->eof = 1;
    /* fprintf(stderr, "doliteFilter EOF = 1\n"); */
  }

  return SQLITE_OK;
}

/*
** SQLite will invoke this method one or more times while planning a query
** that uses the virtual table.  This routine needs to create
** a query plan for each invocation and compute an estimated cost for that
** plan.
*/
static int dolite_changes_BestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) { return SQLITE_OK; }

/*
** This following structure defines all the methods for the
** virtual table.
*/
static sqlite3_module dolite_changes_Module = {/* iVersion    */ .iVersion = 0,
                                               /* xCreate     */ dolite_changes_Create,
                                               /* xConnect    */ dolite_changes_Connect,
                                               /* xBestIndex  */ dolite_changes_BestIndex,
                                               /* xDisconnect */ dolite_changes_Disconnect,
                                               /* xDestroy    */ dolite_changes_Destroy,
                                               /* xOpen       */ dolite_changes_Open,
                                               /* xClose      */ dolite_changes_Close,
                                               /* xFilter     */ dolite_changes_Filter,
                                               /* xEof        */ dolite_changes_Eof,
                                               /* xNext       */ dolite_changes_Next,
                                               /* xColumn     */ dolite_changes_Column,
                                               /* xRowid      */ dolite_changes_Rowid,
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
  rc = sqlite3_create_module(db, "dolite", &dolite_changes_Module, 0);
  fprintf(stderr, "sqlite3_create_module, returned %d \n", rc);

  return rc;
}
