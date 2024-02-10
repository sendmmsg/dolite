#define SQLITE_ENABLE_SESSION 1
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
// Match the 160-byte SHA1 in git, but with blake2 instead.
#define DIGEST_BYTES 20
/* #define DEBUG 1 */
static char *get_branch_hash(sqlite3 *db, char *dbname, char *branch);

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
                                  "hash TEXT,"
                                  "active INTEGER);";
const char *create_v_logs_sql = "CREATE TABLE %w_logs ("
                                "id INTEGER PRIMARY KEY,"
                                "ts DATETIME,"
                                "user TEXT,"
                                "message TEXT,"
                                "hash TEXT);";
const char *cte_commits_sql = "WITH RECURSIVE cte_commits (id, ts, user, message, hash, parent, diff) AS ("
                              "SELECT e.id, e.ts, e.user, e.message, e.hash, e.parent, e.diff "
                              "FROM %w_commits e "
                              "WHERE e.hash = '%w' "
                              "UNION ALL "
                              "SELECT e.id, e.ts, e.user, e.message, e.hash, e.parent, e.diff "
                              "FROM %w_commits e "
                              "JOIN cte_commits c ON c.parent = e.hash "
                              ") "
                              "SELECT * FROM cte_commits;";
// the hidden column in the virtual table for log
#define DOLITE_LOG_INPUT_COL 7

typedef struct changeset {
  int len;
  void *data;
} changeset;
typedef struct _dolite_changes_vtab dolite_changes_vtab;
struct _dolite_changes_vtab {
  sqlite3_vtab base;
  sqlite3_session *session;
  sqlite3 *db;
  char *dbname;
};

static changeset get_staged(sqlite3 *db, char *dbname);
static int stage_session(sqlite3 *db, char *dbname, sqlite3_session **session);
typedef struct _dolite_changes_cursor dolite_changes_cursor;
struct _dolite_changes_cursor {
  sqlite3_vtab_cursor base;
  sqlite3_int64 iRowid;
  changeset diff;
  sqlite3_changeset_iter *diffiter;
  char eof;
};

char *hex_encode(const unsigned char *in, size_t len, void *(*memalloc)(int)) {
  assert(in != NULL);
  unsigned char *pin = in;
  const char *hex = "0123456789abcdef";

  int outsize = 2 * len + 1;
  char *str = memalloc(outsize);
  char *pout = str;
  int i = 0;
  int j = 0;
  for (; i < len; ++i, j += 2) {
    int hval = (*pin >> 4) & 0xF;
    pout[j] = hex[hval];
    hval = (*pin++) & 0xF;
    pout[j + 1] = hex[hval];
  }
  pout[j] = 0;
  return str;
}

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

// Allocates new changeset, up to caller to free properly
static changeset changeset_merge(changeset old, changeset new) {
  changeset tmp;

  int rc = sqlite3changeset_concat(old.len, old.data, new.len, new.data, &tmp.len, &tmp.data);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "changeset_merge: failed to merge %p(%d) with %p(%d)\n", old.data, old.len, new.data, new.len);
  }

  return tmp;
}

static int merge_staged_changes_from_input(sqlite3 *db, char *dbname, changeset *input, changeset *mergeset) {
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

  // Nothing in sqlite_staged
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    *mergeset = *input;
    goto done;
  }

  in_B = changeset_duplicate(sqlite3_column_bytes(stmt, 1), sqlite3_column_blob(stmt, 1));
  rc = sqlite3changeset_concat(input->len, input->data, in_B.len, in_B.data, &result.len, &result.data);

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
static int merge_staged_changes_from_table(sqlite3 *db, char *dbname, changeset *mergeset) {
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
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get: get_key_sql %s\n", get_key_sql);
#endif
  char *key_value = 0;
  int rc = sqlite3_prepare_v2(db, get_key_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "dolite_config_get: failed to prepare %s\n", sqlite3_errmsg(db));
    goto done;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "dolite_config_get: no_rows!\n");
    goto done;
  }
  char *res = (char *)sqlite3_column_text(stmt, 0);
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get: key_value => %s\n", res);
#endif
  if (res != NULL)
    key_value = sqlite3_mprintf("%w", res);

done:
  sqlite3_finalize(stmt);
  sqlite3_free(get_key_sql);

  return key_value;
}

static int get_table_size(sqlite3 *db, char *table) {
  int table_count = 0;
  char *dbname = dolite_config_get(db, "DBNAME");
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get('DBNAME') returned -> %s\n", dbname);
#endif
  if (dbname == NULL)
    goto clean_dbname;

  char *table_size_sql = sqlite3_mprintf("SELECT count(*) FROM %w_staged;", dbname);
  fprintf(stderr, "get_table_size: SQL %s\n", table_size_sql);
  if (table_size_sql == NULL)
    goto clean_sql;

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, table_size_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "get_table_size: failed to prepare %s\n", sqlite3_errmsg(db));
    goto clean_stmt;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "get_table_size: failed to obtain value %s\n", sqlite3_errmsg(db));
  }

  table_count = sqlite3_column_int64(stmt, 0);
  fprintf(stderr, "get_table_size: size %d\n", table_count);

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(table_size_sql);
clean_dbname:
  sqlite3_free(dbname);

  return table_count;
}
static int session_table_filter(void *pctx, const char *table) {
  sqlite3 *db = (sqlite3 *)pctx;
  int is_in_ignore = 0;
  char *dbname = dolite_config_get(db, "DBNAME");
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get('DBNAME') returned -> %s\n", dbname);
#endif
  if (dbname == NULL)
    goto clean_dbname;

  char *is_in_ignore_sql = sqlite3_mprintf("SELECT count(*) FROM %w_ignore WHERE mtab = '%w';", dbname, table);
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get: SQL %s\n", is_in_ignore_sql);
#endif
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
#ifdef DEBUG
  fprintf(stderr, "dolite_config_get: is_in_igonore %d\n", is_in_ignore);
#endif

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(is_in_ignore_sql);
clean_dbname:
  sqlite3_free(dbname);

#ifdef DEBUG
  fprintf(stderr, "session_table_filter: tracking changes to: %s -> %s \n", table, is_in_ignore ? "NO" : "YES");
#endif
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

int get_commit_like(sqlite3 *db, char *dbname, char *hash, char **destination) {

  sqlite3_stmt *stmt = NULL;
  char *select_like_commits_sql =
      sqlite3_mprintf("SELECT count(hash), hash FROM %w_commits WHERE hash LIKE '%w%%';", dbname, hash);

  int rc = sqlite3_prepare_v2(db, select_like_commits_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "get_branch_hash: failed to prepare %s\n", sqlite3_errmsg(db));
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "get_branch_hash: failed to obtain value %s\n", sqlite3_errmsg(db));
    goto clean_stmt;
  }

  int count = sqlite3_column_int(stmt, 0);
  if (count == 0 || count < 0) {
    rc = 0;
    *destination = NULL;
    fprintf(stderr, "get_commit_like: No matching commits found\n");
    goto clean_stmt;
  }
  if (count > 1) {
    rc = count;
    *destination = NULL;
    fprintf(stderr, "get_commit_like: Multiple (%d) matching commits found, aborting\n", count);
    goto clean_stmt;
  }

  char *cand = sqlite3_column_text(stmt, 1);
  if (cand == NULL) {
    rc = 0;
    goto clean_stmt;
  }

  rc = 1;
  int len = strlen(cand);
  *destination = sqlite3_malloc(len + 1);
  memcpy(*destination, cand, len + 1);

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(select_like_commits_sql);

done:
  return rc;
}

static int check_staged(sqlite3 *db, char *dbname) {
  sqlite3_stmt *stmt = NULL;
  char *res = NULL;
  char *check_staged_sql = sqlite3_mprintf("SELECT count(*) FROM %w_staged;", dbname);

  int rc = sqlite3_prepare_v2(db, check_staged_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    rc = -1;
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "%s: failed to obtain value %s\n", __func__, sqlite3_errmsg(db));
    rc = -1;
    goto clean_stmt;
  }

  rc = sqlite3_column_int(stmt, 0);

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(check_staged_sql);

  return rc;
}
static int deactivate_all_branches(sqlite3 *db, char *dbname) {
  sqlite3_stmt *stmt = NULL;
  char *deactivate_branches_sql = sqlite3_mprintf("UPDATE %w_branches SET active = 0;", dbname);

  int rc = sqlite3_prepare_v2(db, deactivate_branches_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "%s: failed to execute statement %s\n", __func__, sqlite3_errmsg(db));
    goto clean_stmt;
  }
  rc = SQLITE_OK;

clean_sql:
  sqlite3_free(deactivate_branches_sql);
clean_stmt:
  sqlite3_finalize(stmt);

  return rc;
}

// if named == true we should also update the named branch with matching hash
static int change_head_branch(sqlite3 *db, char *dbname, char *hash, int named) {
  sqlite3_stmt *stmt = NULL;
  deactivate_all_branches(db, dbname);

  char *head_update_sql = NULL;
  if (named) {
    fprintf(stderr, "Named branch = TRUE\n");
    head_update_sql = sqlite3_mprintf(
        "UPDATE %w_branches SET active = 1, hash = '%w' WHERE branch = 'HEAD' or hash = '%w';", dbname, hash, hash);
  } else {
    fprintf(stderr, "Named branch = FALSE\n");
    head_update_sql =
        sqlite3_mprintf("UPDATE %w_branches SET active = 1, hash = '%w' WHERE branch = 'HEAD';", dbname, hash);
  }

  int rc = sqlite3_prepare_v2(db, head_update_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "%s: failed to execute statement %s\n", __func__, sqlite3_errmsg(db));
    goto clean_stmt;
  }
  rc = SQLITE_OK;

clean_sql:
  sqlite3_free(head_update_sql);
clean_stmt:
  sqlite3_finalize(stmt);

  return rc;
}

// Abort on any conflicts, should not happen!
static int conflict_handler(void *pCtx, int eConflict, sqlite3_changeset_iter *p) {
  char buffer[1024];
  const char *pzTab;
  int pnCol;
  int pOp;
  int pbIndirect;
  int rc = sqlite3changeset_op(p, &pzTab, &pnCol, &pOp, &pbIndirect);
  fprintf(stderr, "%s: called, eConflict : %s this should not happen if everything works correctly\n", __func__,
          changeset_conflict[eConflict]);

  gen_diffstr(buffer, 1024, p, pOp, pnCol);

  fprintf(stderr, "%s:   conflict %s\n", __func__, buffer);
  return SQLITE_CHANGESET_ABORT;
}

#define COMMIT_REVERT 2
#define COMMIT_APPLY 3

static int execute_changeset(sqlite3 *db, char *dbname, char *commit_hash, int op) {
  changeset cs = {.data = NULL, .len = 0};
  sqlite3_stmt *commit_cs_stmt;
  char *commit_cs_sql = sqlite3_mprintf("SELECT diff FROM %w_commits WHERE hash = '%w';", dbname, commit_hash);
  int rc = sqlite3_prepare_v2(db, commit_cs_sql, -1, &commit_cs_stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: prepare_v2 returned %d (%s) error: %s\n", __func__, rc, error_names[rc], sqlite3_errmsg(db));
    goto clean_sql;
  }
  rc = sqlite3_step(commit_cs_stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "%s: step() returned %d (%s) error: %s\n", __func__, rc, error_names[rc], sqlite3_errmsg(db));
    goto clean_stmt;
  }

  if (op == COMMIT_REVERT) {
    // Create inverted version of the changeset
    rc = sqlite3changeset_invert(sqlite3_column_bytes(commit_cs_stmt, 0), sqlite3_column_blob(commit_cs_stmt, 0),
                                 &cs.len, &cs.data);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "%s: changeset_invert() returned %d (%s) error: %s\n", __func__, rc, error_names[rc],
              sqlite3_errmsg(db));
      goto clean_cs;
    }
    rc = sqlite3changeset_apply(db, cs.len, cs.data, NULL, conflict_handler, NULL);
  }

  if (op == COMMIT_APPLY) {
    rc = sqlite3changeset_apply(db, sqlite3_column_bytes(commit_cs_stmt, 0),
                                (void *)sqlite3_column_blob(commit_cs_stmt, 0), NULL, conflict_handler, NULL);
  }

  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: changeset_apply() returned %d (%s) error: %s\n", __func__, rc, error_names[rc],
            sqlite3_errmsg(db));
  }
clean_cs:
  if (cs.data != NULL)
    sqlite3_free(cs.data);

clean_stmt:
  sqlite3_finalize(commit_cs_stmt);
clean_sql:
  sqlite3_free(commit_cs_sql);

  return rc;
}

static int obtain_revert_apply(sqlite3 *db, char *dbname, char *head_hash, char *target_hash) {
  sqlite3_stmt *revert_list_stmt = NULL;
  sqlite3_stmt *apply_list_stmt = NULL;
  char *revert_list_sql = sqlite3_mprintf("SELECT hash, id FROM dolite_log where start = '%w' "
                                          "EXCEPT "
                                          "SELECT hash, id FROM dolite_log WHERE start = '%w' "
                                          "ORDER BY id DESC;",
                                          head_hash, target_hash);
  char *apply_list_sql = sqlite3_mprintf("SELECT hash, id FROM dolite_log where start = '%w' "
                                         "EXCEPT "
                                         "SELECT hash, id FROM dolite_log WHERE start = '%w' "
                                         "ORDER BY id ASC;",
                                         target_hash, head_hash);
  int rc = sqlite3_prepare_v2(db, revert_list_sql, -1, &revert_list_stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    goto clean_sql;
  }
  rc = sqlite3_prepare_v2(db, apply_list_sql, -1, &apply_list_stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    goto clean_stmt;
  }

  while ((rc = sqlite3_step(revert_list_stmt)) == SQLITE_ROW) {
    const char *commit_hash = (const char *)sqlite3_column_text(revert_list_stmt, 0);
    fprintf(stderr, "%s: Should REVERT commit with hash %s\n", __func__, commit_hash);
    rc = execute_changeset(db, dbname, (char *)commit_hash, COMMIT_REVERT);
  }
  // nothing found, expected
  if (rc == SQLITE_DONE) {
    fprintf(stderr, "%s: no more commits to revert\n", __func__);
  } else {
    fprintf(stderr, "%s: Error looking for revert commits, step retufned %d\n", __func__, rc);
    goto clean_stmt;
  }

  while ((rc = sqlite3_step(apply_list_stmt)) == SQLITE_ROW) {
    const char *commit_hash = (const char *)sqlite3_column_text(apply_list_stmt, 0);
    fprintf(stderr, "%s: Should APPLY commit with hash %s\n", __func__, commit_hash);
    rc = execute_changeset(db, dbname, (char *)commit_hash, COMMIT_APPLY);
  }
  // nothing found, expected
  if (rc == SQLITE_DONE) {
    fprintf(stderr, "%s: no more commits to aply\n", __func__);
  } else {
    fprintf(stderr, "%s: Error looking for apply commits, step retufned %d\n", __func__, rc);
    goto clean_stmt;
  }

clean_stmt:
  sqlite3_finalize(revert_list_stmt);
  sqlite3_finalize(apply_list_stmt);
clean_sql:
  sqlite3_free(revert_list_sql);
  sqlite3_free(apply_list_sql);

  return rc;
}

static char *dolite_checkout(sqlite3 *db, sqlite3_session **session, char *dbname, char *hash) {

  int rc = 0;
  int named_hash = 0;
  // 1. check if hash is a branch
  char *target_commit_hash = get_branch_hash(db, dbname, hash);
  if (target_commit_hash == NULL) {
    fprintf(stderr, "No branch named %s found\n", hash);
    // 2. check if hash is LIKE _ONE_ hash in the commits
    //   -> if not, fail
    rc = get_commit_like(db, dbname, hash, &target_commit_hash);
    if (rc == 0)
      return sqlite3_mprintf("No matching commits (%d) found\n", rc);
  }
  if (rc > 1)
    return sqlite3_mprintf("Multiple (%d) commits found, be more specific", rc);
  else {
    named_hash = 1;
  }

  // 3. trigger session -> staged
  rc = stage_session(db, dbname, session);
  fprintf(stderr, "staged session: rc -> %d\n", rc);
  // 4. check if there is anything in staged
  //   -> if yes, fail -> dolite_reset()
  int in_staged = check_staged(db, dbname);
  if (in_staged != 0)
    return sqlite3_mprintf("Error, uncommited changes in staged. Commit changes or reset before checkout\n");

  // 5. get list of commits between current HEAD and destination
  char *head_commit_hash = get_branch_hash(db, dbname, "HEAD");
  fprintf(stderr, "HEAD: %s\n", head_commit_hash);
  fprintf(stderr, "Commit is: %s\n", target_commit_hash);
  // 6. obtain, invert, apply all diffs to reach destination
  // TODO
  rc = sqlite3session_enable(*session, 0);
  rc = obtain_revert_apply(db, dbname, head_commit_hash, target_commit_hash);
  // 7. update branches
  rc = change_head_branch(db, dbname, target_commit_hash, named_hash);
  rc = sqlite3session_enable(*session, 1);

  return sqlite3_mprintf("TODO: Checkout");
}
static void dolite_checkout_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_changes_vtab *pTab = (dolite_changes_vtab *)sqlite3_user_data(context);
  const char *hash = (const char *)sqlite3_value_text(argv[0]);
  char *result = dolite_checkout(pTab->db, &(pTab->session), pTab->dbname, hash);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}

static char *dolite_revert(sqlite3 *db, sqlite3_session **session, char *dbname, char *hash) {
  return sqlite3_mprintf(
      "TODO: check if anything in session (dirty), iff fail.  invert and apply diff with hash. commit staged.");
}
static void dolite_revert_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_changes_vtab *pTab = (dolite_changes_vtab *)sqlite3_user_data(context);
  const char *hash = (const char *)sqlite3_value_text(argv[0]);
  char *result = dolite_revert(pTab->db, &(pTab->session), pTab->dbname, hash);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}
static char *dolite_reset(sqlite3 *db, sqlite3_session **session, char *dbname) {
  return sqlite3_mprintf("TODO: Undo changes in **session, and all in _staged. Clear _staged. No session kept");
}
static void dolite_reset_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_changes_vtab *pTab = (dolite_changes_vtab *)sqlite3_user_data(context);
  char *result = dolite_reset(pTab->db, &(pTab->session), pTab->dbname);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}

static char *get_branch_hash(sqlite3 *db, char *dbname, char *branch) {
  sqlite3_stmt *stmt = NULL;
  char *res = NULL;
  char *select_staged_sql = sqlite3_mprintf("SELECT hash FROM %w_branches WHERE branch = '%w';", dbname, branch);

  int rc = sqlite3_prepare_v2(db, select_staged_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "%s: failed to prepare %s\n", __func__, sqlite3_errmsg(db));
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);

  // nothing found, expected
  if (rc == SQLITE_DONE) {
    goto clean_stmt;
  }

  // else somethin or error?
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "%s: rc = %d, failed to obtain value %s\n", __func__, rc, sqlite3_errmsg(db));
    // TODO: print error?
    goto clean_stmt;
  }

  const unsigned char *hash = sqlite3_column_text(stmt, 0);
  if (hash != NULL) {
    int len = strlen((char *)hash);
    res = sqlite3_malloc(len + 1);
    memcpy(res, hash, len + 1);
  }
  fprintf(stderr, "%s: %s, ret -> %s\n", __func__, hash, res);

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(select_staged_sql);

  return res;
}

static char *dolite_commit(sqlite3 *db, sqlite3_session **session, char *dbname, const char *username,
                           const char *message);

// TODO: make this take a variable number of arguments?
static void dolite_commit_cmd(sqlite3_context *context, int argc, sqlite3_value **argv) {
  dolite_changes_vtab *pTab = (dolite_changes_vtab *)sqlite3_user_data(context);
  const char *username = (const char *)sqlite3_value_text(argv[0]);
  const char *message = (const char *)sqlite3_value_text(argv[1]);
  /* printf("dolite_commit_cmd: %s %s\n", username, message); */
  char *result = dolite_commit(pTab->db, &(pTab->session), pTab->dbname, username, message);
  sqlite3_result_text(context, result, strlen(result), sqlite3_free);
}

static int update_branches(sqlite3 *db, char *dbname, char *parent, char *diff_hash) {
  char *update_sql = NULL;
  sqlite3_stmt *stmt = NULL;
  fprintf(stderr, "update_branches(%s, %s, %s)\n", dbname, parent, diff_hash);

  if (parent == NULL) {
    update_sql =
        sqlite3_mprintf("UPDATE %w_branches SET hash = '%w' WHERE hash IS NULL and active = 1;", dbname, diff_hash);
  } else {
    update_sql = sqlite3_mprintf("UPDATE %w_branches SET hash = '%w' WHERE hash = '%w' and active = 1;", dbname,
                                 diff_hash, parent);
  }
  int rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK)
    goto clean_stmt;

  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "update_branches: failed to update: %s\n", sqlite3_errmsg(db));
    goto clean_stmt;
  }

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(update_sql);

  return rc;
}
// TODO: Wrap in BEGIN/COMMIT
static char *dolite_commit(sqlite3 *db, sqlite3_session **session, char *dbname, const char *username,
                           const char *message) {
  changeset toinsert = {.data = NULL, .len = 0};
  unsigned char digest[DIGEST_BYTES];
  sqlite3_stmt *stmt = NULL;

  int rc = stage_session(db, dbname, session);
  // TODO: error handling
  toinsert = get_staged(db, dbname);

  // Get everything from _staged
  /* merge_staged_changes_from_table(db, dbname, &toinsert); */
  /* if (toinsert.len < 1) { */
  /*   char *pOut = sqlite3_mprintf("dolite_commit: nothing to commit, changeset size: %d", toinsert.len); */
  /*   return pOut; */
  /* } */

  // Insert in _diffs
  char *insert_sql = sqlite3_mprintf("INSERT INTO %w_commits VALUES (NULL, DATETIME('now'), ?, ?, ?, ?, ?);", dbname);
  rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    const char *err_msg = sqlite3_errmsg(db);
    sqlite3_free(insert_sql);
    char *pOut = sqlite3_mprintf("dolite_commit: error preparing insert statement: %s", insert_sql);
    return pOut;
  }
  sqlite3_free(insert_sql);

  char *parent = get_branch_hash(db, dbname, "HEAD");
  if (parent == NULL)
    dolite_hash_blob(&digest[0], DIGEST_BYTES, toinsert.data, toinsert.len);
  else
    dolite_hash_blob_keyed(&digest[0], DIGEST_BYTES, toinsert.data, toinsert.len, parent, strlen(parent));

  char *diff_hash = hex_encode(digest, DIGEST_BYTES, sqlite3_malloc);
  fprintf(stderr, "dolite_commit: parent: %s\n", parent);

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
  if (parent != NULL)
    rc = sqlite3_bind_text(stmt, 4, parent, strlen(parent), NULL);

  if (rc != SQLITE_OK) {
    char *pOut = sqlite3_mprintf("dolite_commit: failed to bind text: %s", sqlite3_errmsg(db));
    return pOut;
  }
  rc = sqlite3_bind_blob(stmt, 5, toinsert.data, toinsert.len, NULL);
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

  update_branches(db, dbname, parent, diff_hash);
  dolite_clean_staged(db, dbname);

  char *pOut = sqlite3_mprintf("%s", diff_hash);
  if (parent != NULL)
    sqlite3_free(parent);
  sqlite3_free(diff_hash);

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
  dolite_changes_vtab *pNew;
  int rc;

#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Connect\n");
#endif
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
  sqlite3_free(config_cmd);
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
    fprintf(stderr, "Error setting 'DBNAME' configuration (%s) in dolite_config: %s\n", dbname, err_msg);
    goto done;
  }
  cmd = sqlite3_mprintf("INSERT INTO %w_branches VALUES ('master', NULL, 1), ('HEAD', NULL, 1);", dbname);
  rc = sqlite3_exec(db, cmd, 0, 0, &err_msg);
  sqlite3_free(cmd);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error creating master branch and HEAD configuration (%s) in create_all_tables(): %s\n", dbname,
            err_msg);
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
  dolite_changes_vtab *pNew;
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
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Disconnect\n");
#endif
  dolite_changes_vtab *p = (dolite_changes_vtab *)pVtab;

  stage_session(p->db, p->dbname, &(p->session));
  sqlite3session_delete(p->session);
  sqlite3_free(p->dbname);

  sqlite3_free(p);
  return SQLITE_OK;
}

static int dolite_changes_Destroy(sqlite3_vtab *pVtab) {
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Destroy\n");
#endif
  dolite_changes_vtab *p = (dolite_changes_vtab *)pVtab;
  sqlite3_free(p);
  return SQLITE_OK;
}

// Get the staged changes from %w_staged if possible
static changeset get_staged(sqlite3 *db, char *dbname) {
  changeset result = {.data = NULL, .len = 0};
  changeset tmp = {.data = NULL, .len = 0};
  sqlite3_stmt *stmt = 0;

  char *select_staged_sql = sqlite3_mprintf("SELECT diff FROM %w_staged;", dbname);

  int rc = sqlite3_prepare_v2(db, select_staged_sql, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "get_staged: failed to prepare %s\n", sqlite3_errmsg(db));
    goto clean_sql;
  }
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    fprintf(stderr, "get_staged: failed to obtain value %s\n", sqlite3_errmsg(db));
    goto clean_stmt;
  }

  tmp.data = (void *)sqlite3_column_blob(stmt, 0);
  tmp.len = sqlite3_column_bytes(stmt, 0);

  if (tmp.len > 0) {
    result = changeset_duplicate(tmp.len, tmp.data);
  }

clean_stmt:
  sqlite3_finalize(stmt);
clean_sql:
  sqlite3_free(select_staged_sql);

  return result;
}

static int stage_session(sqlite3 *db, char *dbname, sqlite3_session **session) {
  changeset diffs;
  changeset result = {.len = 0, .data = NULL};
  int rc = sqlite3session_changeset(*session, &diffs.len, &diffs.data);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "stage_session: failure fetching changeset, session %p rc: %d. %s\n", *session, rc,
            error_names[rc]);
  }
#ifdef DEBUG
  fprintf(stderr, "stage_session: nchange %d pchange %p\n", diffs.len, diffs.data);
#endif

  // if nothing has changed, nothing to do.
  if (diffs.len < 1) {
    fprintf(stderr, "stage_session: changeset len -> 0\n");
    goto done;
  }

  // we have something to do, check if theres anything in the table

  changeset in_table = get_staged(db, dbname);
#ifdef DEBUG
  fprintf(stderr, "stage_session: %s_staged already holds %d bytes\n", dbname, in_table.len);
#endif

  // if there's something in the table, we should merge with diff first
  if (in_table.len < 1) {
    result = diffs;
  } else {
    result = changeset_merge(in_table, diffs);
    sqlite3_free(in_table.data);
    sqlite3_free(diffs.data);
  }

  // Add diff to temp table only if there's something there to add
  sqlite3_stmt *stmt;

  char *insert_sql = sqlite3_mprintf("INSERT INTO %w_staged VALUES (NULL, DATETIME('now'), ?);", dbname);
  rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error preparing %s_staged statement: %s \n", dbname, insert_sql);
    goto cleanup_insert_sql;
  }

  char *err_msg = 0;
  char *delete_old_sql = sqlite3_mprintf("DELETE FROM %w_staged;", dbname);
  rc = sqlite3_exec(db, delete_old_sql, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error clearing table %s_staged: %s\n", dbname, err_msg);
  }

  rc = sqlite3_bind_blob(stmt, 1, result.data, result.len, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db));
    return SQLITE_ERROR;
  }
  rc = sqlite3_step(stmt);
  // run the SQL
  while (rc == SQLITE_ROW) {
    rc = sqlite3_step(stmt);
  }

  // destroy the object to avoid resource leaks
  sqlite3_finalize(stmt);
  sqlite3session_delete(*session);
  *session = create_session(db);

  sqlite3_free(diffs.data);
  sqlite3_free(delete_old_sql);
cleanup_insert_sql:
  sqlite3_free(insert_sql);
done:
  return 0;
}

/*
** Constructor for a new dolite_cursor object.
*/
static int dolite_changes_Open(sqlite3_vtab *pVtab, sqlite3_vtab_cursor **ppCursor) {

#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Open\n");
#endif

  dolite_changes_cursor *pCur;
  dolite_changes_vtab *p = (dolite_changes_vtab *)pVtab;
  sqlite3 *db = p->db;
  char *dbname = p->dbname;

  // SQLITE_API int sqlite3session_isempty(sqlite3_session * pSession);
  pCur = sqlite3_malloc(sizeof(*pCur));
  if (pCur == 0)
    return SQLITE_NOMEM;
  memset(pCur, 0, sizeof(*pCur));
  *ppCursor = &pCur->base;

  stage_session(db, dbname, &(p->session));
  pCur->diff = get_staged(db, dbname);
  int rc = sqlite3changeset_start(&(pCur->diffiter), pCur->diff.len, pCur->diff.data);

  /* int rc = sqlite3session_changeset(p->session, &(pCur->diff.len), &(pCur->diff.data)); */
  /* if (rc != SQLITE_OK) { */
  /*   fprintf(stderr, "failure fetching changeset: session %p rc: %d. %s\n", p->session, rc, error_names[rc]); */
  /* } */
  /* fprintf(stderr, "nchange %d pchange %p\n", pCur->diff.len, pCur->diff.data); */

  /* char *table_name = sqlite3_mprintf("%w_staged"); */
  /* int table_size = get_table_size(db, table_name); */
  /* fprintf(stderr, "dolite_changes_Open:  %d rows in table %s\n", table_size, table_name); */

  /* // Add diff to temp table only if there's something there to add */
  /* if (pCur->diff.len > 0) { */
  /*   sqlite3_stmt *stmt; */

  /*   char *insert_sql = sqlite3_mprintf("INSERT INTO %w_staged VALUES (NULL, DATETIME('now'), ?);", dbname); */
  /*   rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0); */

  /*   if (rc != SQLITE_OK) { */
  /*     fprintf(stderr, "Error preparing %s_staged statement: %s \n", dbname, insert_sql); */
  /*     return SQLITE_ERROR; */
  /*   } */
  /*   sqlite3_free(insert_sql); */

  /*   /\* dolite_hash_blob(&digest[0], DIGEST_BYTES, pChangeset, nChangeset); *\/ */
  /*   /\* char *changeset_hash = hash_tostring(digest, DIGEST_BYTES, 0, 'i'); *\/ */
  /*   /\* printf("\n\n base64-encoded hash: %s\n\n", changeset_hash); *\/ */

  /*   /\* rc = sqlite3_bind_text(stmt, 2, changeset_hash, strlen(changeset_hash), NULL); *\/ */
  /*   /\* if (rc != SQLITE_OK) { *\/ */
  /*   /\*   fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(db)); *\/ */
  /*   /\*   exit(0); *\/ */
  /*   /\* } *\/ */

  /*   // if there's already things in the table, we should merge them */
  /*   if (table_size > 0) { */
  /*     // merged should have the concatenated set of changes after this */
  /*     changeset merged; */
  /*     merge_staged_changes_from_input(p->db, p->dbname, &(pCur->diff), &merged); */
  /*     sqlite3_free(pCur->diff.data); */
  /*     pCur->diff = merged; */

  /*     char *err_msg = 0; */
  /*     char *cleanup_sql = sqlite3_mprintf("DELETE FROM %w_staged;", dbname); */
  /*     int rc = sqlite3_exec(db, cleanup_sql, 0, 0, &err_msg); */
  /*     if (rc != SQLITE_OK) { */
  /*       fprintf(stderr, "Error clearing table %s_staged: %s\n", dbname, err_msg); */
  /*     } */
  /*   } */

  /*   rc = sqlite3_bind_blob(stmt, 1, pCur->diff.data, pCur->diff.len, NULL); */
  /*   if (rc != SQLITE_OK) { */
  /*     fprintf(stderr, "Failed to bind blob: %s\n", sqlite3_errmsg(p->db)); */
  /*     return SQLITE_ERROR; */
  /*   } */
  /*   rc = sqlite3_step(stmt); */
  /*   // run the SQL */
  /*   while (rc == SQLITE_ROW) { */
  /*     rc = sqlite3_step(stmt); */
  /*   } */

  /*   // destroy the object to avoid resource leaks */
  /*   sqlite3_finalize(stmt); */
  /*   sqlite3session_delete(p->session); */
  /*   p->session = create_session(p->db); */
  /* } */

  /* sqlite3_free(table_name); */
  // rc = sqlite3changeset_start(&(pCur->diffiter), pCur->diff.len, pCur->diff.data);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Error obtaining changeset iterator\n");
  }
  return SQLITE_OK;
}

/*
** Destructor for a dolite_cursor.
*/
static int dolite_changes_Close(sqlite3_vtab_cursor *cur) {
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Close\n");
#endif
  dolite_changes_cursor *pCur = (dolite_changes_cursor *)cur;
  sqlite3changeset_finalize(pCur->diffiter);
  sqlite3_free(pCur->diff.data);
  sqlite3_free(pCur);
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Close, done\n");
#endif
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
  dolite_changes_cursor *pCur = (dolite_changes_cursor *)cur;
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
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Rowid\n");
#endif
  dolite_changes_cursor *pCur = (dolite_changes_cursor *)cur;
  *pRowid = pCur->iRowid;
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int dolite_changes_Eof(sqlite3_vtab_cursor *cur) {
  dolite_changes_cursor *pCur = (dolite_changes_cursor *)cur;
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
#ifdef DEBUG
  fprintf(stderr, "dolite_changes_Eof -> returning %d\n", pCur->eof);
#endif
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
  dolite_changes_cursor *pCur = (dolite_changes_cursor *)pVtabCursor;
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

    /*     int sqlite3_dolite_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) { */
    /* #ifdef DEBUG */
    /*   fprintf(stderr, "sqlite3_dolite_init called\n"); */
    /* #endif */

    /*   int rc = SQLITE_OK; */
    /*   SQLITE_EXTENSION_INIT2(pApi); */
    /*   rc = sqlite3_create_module(db, "dolite", &dolite_changes_Module, 0); */
    /* #ifdef DEBUG */
    /*   fprint(stderr, "sqlite3_create_module, returned %d \n", rc); */
    /* #endif */

    /*   return rc; */
    /* } */

    typedef struct _dolite_log_vtab dolite_log_vtab;

struct _dolite_log_vtab {
  sqlite3_vtab base;
  sqlite3 *db;
  char *dbname;
};

typedef struct _dolite_log_cursor dolite_log_cursor;

struct _dolite_log_cursor {
  sqlite3_vtab_cursor base; /* Base class - must be first */
  sqlite3 *db;
  sqlite3_stmt *stmt;
  // sql string used to prepare stmt
  char *zSql;
  int rc;
};
static int dolite_log_Connect(sqlite3 *db, void *pUnused, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                              char **pzErrUnused) {
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Connect\n");
#endif
  dolite_log_vtab *pNew;
  int rc;

/* Column numbers */
#define LOG_COLUMN_TS 0
#define LOG_COLUMN_USER 1
#define LOG_COLUMN_MESSAGE 2
#define LOG_COLUMN_HASH 3
#define LOG_COLUMN_PARENT 4
#define LOG_COLUMN_DIFF 5

  (void)pUnused;
  (void)pzErrUnused;
  rc = sqlite3_declare_vtab(db, "CREATE TABLE            y(id, ts, user, message, hash, parent, diff, start HIDDEN)");
  if (rc == SQLITE_OK) {
    *ppVtab = sqlite3_malloc(sizeof(*pNew));
    pNew = (dolite_log_vtab *)*ppVtab;

    if (pNew == 0)
      return SQLITE_NOMEM;
    memset(pNew, 0, sizeof(*pNew));
    sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
  }

  pNew->db = db;
  pNew->dbname = sqlite3_mprintf("%w", argv[2]);
  return rc;
}

/*
** This method is the destructor for series_cursor objects.
*/
static int dolite_log_Disconnect(sqlite3_vtab *pVtab) {
  fprintf(stderr, "dolite_log_Disconnect\n");
  dolite_log_vtab *p = (dolite_log_vtab *)pVtab;
  sqlite3_free(p->dbname);
  sqlite3_free(p);
  return SQLITE_OK;
}

/*
** Constructor for a new series_cursor object.
*/
static int dolite_log_Open(sqlite3_vtab *p, sqlite3_vtab_cursor **ppCursor) {
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Open\n");
#endif
  dolite_log_cursor *pCur;
  dolite_log_vtab *pTab = (dolite_log_vtab *)p;

  pCur = sqlite3_malloc(sizeof(*pCur));
  if (pCur == 0)
    return SQLITE_NOMEM;
  memset(pCur, 0, sizeof(*pCur));
  *ppCursor = &pCur->base;
  pCur->db = pTab->db;
  return SQLITE_OK;
}

/*
** Destructor for a series_cursor.
*/
static int dolite_log_Close(sqlite3_vtab_cursor *cur) {
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Close\n");
#endif
  dolite_log_cursor *p = (dolite_log_cursor *)cur;
  sqlite3_free(p->zSql);
  sqlite3_finalize(p->stmt);
  sqlite3_free(cur);
  return SQLITE_OK;
}

/*
** Advance a series_cursor to its next row of output.
*/
static int dolite_log_Next(sqlite3_vtab_cursor *cur) {
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Next\n");
#endif
  dolite_log_cursor *pCur = (dolite_log_cursor *)cur;
  pCur->rc = sqlite3_step(pCur->stmt);
#ifdef DEBUG
  fprintf(stderr, "sqlite_log_next: rc %d\n", pCur->rc);
#endif
  return SQLITE_OK;
}

/*
** Return values of columns for the row at which the series_cursor
** is currently pointing.
*/
static int dolite_log_Column(sqlite3_vtab_cursor *cur, /* The cursor */
                             sqlite3_context *ctx,     /* First argument to sqlite3_result_...() */
                             int i                     /* Which column to return */
) {
  dolite_log_cursor *pCur = (dolite_log_cursor *)cur;
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Column cur: %p, ctx: %p, i: %d\npCur->rc: %d\n", cur, ctx, i, pCur->rc);
#endif
  if (pCur->rc != SQLITE_ROW) {
    return SQLITE_ERROR;
  }
  if (i == DOLITE_LOG_INPUT_COL) {
    sqlite3_result_text(ctx, pCur->zSql, -1, SQLITE_TRANSIENT);
  } else {
    sqlite3_result_value(ctx, sqlite3_column_value(pCur->stmt, i));
  }

  return SQLITE_OK;
}

#ifndef LARGEST_UINT64
#define LARGEST_UINT64 (0xffffffff | (((sqlite3_uint64)0xffffffff) << 32))
#endif

/*
** Return the rowid for the current row, logically equivalent to n+1 where
** "n" is the ascending integer in the aforesaid production definition.
*/
static int dolite_log_Rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  fprintf(stderr, "dolite_log_Rowid\n");
  dolite_log_cursor *pCur = (dolite_log_cursor *)cur;
  /* sqlite3_uint64 n = pCur->ss.uSeqIndexNow; */
  /* *pRowid = (sqlite3_int64)((n < LARGEST_UINT64) ? n + 1 : 0); */
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int dolite_log_Eof(sqlite3_vtab_cursor *cur) {
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Eof\n");
#endif
  dolite_log_cursor *pCur = (dolite_log_cursor *)cur;
  if (pCur->rc != SQLITE_ROW)
    return 1;
  // return !pCur->ss.isNotEOF;
  return 0;
}

/* True to cause run-time checking of the start=, stop=, and/or step=
** parameters.  The only reason to do this is for testing the
** constraint checking logic for virtual tables in the SQLite core.
*/
#ifndef SQLITE_SERIES_CONSTRAINT_VERIFY
#define SQLITE_SERIES_CONSTRAINT_VERIFY 0
#endif

static int dolite_log_Filter(sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStrUnused, int argc,
                             sqlite3_value **argv) {

  dolite_log_cursor *pCur = (dolite_log_cursor *)pVtabCursor;
  int rc;
  char *hash_str = 0;
  int hash_len = -1;
  char free_hash = 0;
  char *dbname = dolite_config_get(pCur->db, "DBNAME");
  if (dbname == NULL) {
    fprintf(stderr, "dolite_log_Filter: dbname not found\n");
    return SQLITE_ERROR;
  }

#ifdef DEBUG
  fprintf(stderr, "dolite_log_Filter(%p, %d, %s, %d, %p)\n", pVtabCursor, idxNum, idxStrUnused, argc, argv);
#endif

  if (argc == 0 || sqlite3_value_type(argv[0]) != SQLITE_TEXT) {
    hash_str = get_branch_hash(pCur->db, dbname, "HEAD");
    hash_len = strlen(hash_str);
    free_hash = 1;
  } else {
    hash_str = sqlite3_value_text(argv[0]);
    hash_len = sqlite3_value_bytes(argv[0]);
  }
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Filter: Should get history for commit: %s (%d)\n", hash_str, hash_len);
#endif
  sqlite3_free(pCur->zSql);
  pCur->zSql = sqlite3_mprintf("%s", hash_str);

  if (free_hash)
    sqlite3_free(hash_str);

  if (pCur->zSql == 0) {
    rc = SQLITE_NOMEM;
    goto error;
  }
  char *cte_sql = sqlite3_mprintf(cte_commits_sql, dbname, pCur->zSql, dbname);
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Filter: SQL command to evaluate '%s'\n", cte_sql);
#endif

  rc = sqlite3_prepare_v2(pCur->db, cte_sql, -1, &(pCur->stmt), 0);
  sqlite3_free(cte_sql);
#ifdef DEBUG
  fprintf(stderr, "dolite_log_Filter: prepare_v2 returned %d (%s) error: %s\n", rc, error_names[rc],
          sqlite3_errmsg(pCur->db));
#endif
  if (rc != SQLITE_OK) {
    goto error;
  }

#ifdef DEBUG
  fprintf(stderr, "dolite_log_Filter: Successfully prepared, stepping\n");
#endif
  pCur->rc = sqlite3_step(pCur->stmt);
  rc = (pCur->rc == SQLITE_DONE || pCur->rc == SQLITE_ROW) ? SQLITE_OK : pCur->rc;
  if (rc == SQLITE_OK) {
#ifdef DEBUG
    fprintf(stderr, "Step ok\n");
#endif
    goto done;
  }

error:
#ifdef DEBUG
  fprintf(stderr, "cleaning after error\n");
#endif
  sqlite3_finalize(pCur->stmt);
  pCur->stmt = 0;
  sqlite3_free(pCur->zSql);
  pCur->zSql = 0;
  // sqlite3_free(cte_sql);
  pCur->rc = SQLITE_DONE;

#ifdef DEBUG
  fprintf(stderr, "log_filter: pcur->rc %d \n", pCur->rc);
#endif
  return SQLITE_ERROR;
done:
#ifdef DEBUG
  fprintf(stderr, "log_filter: pcur->rc %d \n", pCur->rc);
#endif
  return SQLITE_OK;
}

/*
** SQLite will invoke this method one or more times while planning a query
** that uses the generate_series virtual table.  This routine needs to create
** a query plan for each invocation and compute an estimated cost for that
** plan.
**
** In this implementation idxNum is used to represent the
** query plan.  idxStr is unused.
**
** The query plan is represented by bits in idxNum:
**
**  (1)  start = $value  -- constraint exists
**  (2)  stop = $value   -- constraint exists
**  (4)  step = $value   -- constraint exists
**  (8)  output in descending order
*/
static int dolite_log_BestIndex(sqlite3_vtab *pVTab, sqlite3_index_info *pIdxInfo) {

#ifdef DEBUG
  fprintf(stderr, "dolite_log_BestIndex\n");
  fprintf(stderr, "nConstraint %d\n", pIdxInfo->nConstraint);
#endif
  int found = 0;

  for (int i = 0; i < pIdxInfo->nConstraint; i++) {
#ifdef DEBUG
    fprintf(stderr, "  iColumn %d\n", pIdxInfo->aConstraint[i].iColumn);
    fprintf(stderr, "  op %d\n", pIdxInfo->aConstraint[i].op);
    fprintf(stderr, "  usable %d\n", pIdxInfo->aConstraint[i].usable);
#endif
    if (pIdxInfo->aConstraint[i].usable) {
      pIdxInfo->aConstraintUsage[i].argvIndex = i + 1;
      found = 1;
    }
  }

  /*
  if (!found) {
    sqlite3_free(pVTab->zErrMsg);
    pVTab->zErrMsg = sqlite3_mprintf("first argument to \"dolite_log()\" missing or unusable");
    return SQLITE_ERROR;
  }
  */
  return SQLITE_OK;
}

static sqlite3_module dolite_log_Module = {
    0,                     /* iVersion */
    0,                     /* xCreate */
    dolite_log_Connect,    /* xConnect */
    dolite_log_BestIndex,  /* xBestIndex */
    dolite_log_Disconnect, /* xDisconnect */
    0,                     /* xDestroy */
    dolite_log_Open,       /* xOpen - open a cursor */
    dolite_log_Close,      /* xClose - close a cursor */
    dolite_log_Filter,     /* xFilter - configure scan constraints */
    dolite_log_Next,       /* xNext - advance a cursor */
    dolite_log_Eof,        /* xEof - check for end of scan */
    dolite_log_Column,     /* xColumn - read data */
    dolite_log_Rowid,      /* xRowid - read data */
    0,                     /* xUpdate */
    0,                     /* xBegin */
    0,                     /* xSync */
    0,                     /* xCommit */
    0,                     /* xRollback */
    0,                     /* xFindMethod */
    0,                     /* xRename */
    0,                     /* xSavepoint */
    0,                     /* xRelease */
    0,                     /* xRollbackTo */
    0,                     /* xShadowName */
    0                      /* xIntegrity */
};
typedef struct _dolite_diff_vtab dolite_diff_vtab;

struct _dolite_diff_vtab {
  sqlite3_vtab base;
  sqlite3 *db;
  char *dbname;
};

typedef struct _dolite_diff_cursor dolite_diff_cursor;

struct _dolite_diff_cursor {
  sqlite3_vtab_cursor base; /* Base class - must be first */
  sqlite3 *db;
  sqlite3_int64 iRowid;
  changeset diff;
  sqlite3_changeset_iter *diffiter;
  char *commit_str;
  char eof;

  // sql string used to prepare stmt
};

static int dolite_diff_Connect(sqlite3 *db, void *pUnused, int argc, const char *const *argv, sqlite3_vtab **ppVtab,
                               char **pzErrUnused) {
#ifdef DEBUG
  fprintf(stderr, "dolite_diff_Connect\n");
#endif
  dolite_diff_vtab *pNew;
  int rc;

  /* Column numbers */

  (void)pUnused;
  (void)pzErrUnused;
  rc = sqlite3_declare_vtab(db, "CREATE TABLE x(id, operation, indirect, tab, diff, hash HIDDEN)");
  if (rc == SQLITE_OK) {
    *ppVtab = sqlite3_malloc(sizeof(*pNew));
    pNew = (dolite_diff_vtab *)*ppVtab;
    if (pNew == 0)
      return SQLITE_NOMEM;
    memset(pNew, 0, sizeof(*pNew));
    sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
  }

  pNew->db = db;
  pNew->dbname = sqlite3_mprintf("%w", argv[2]);
  return rc;
}

/*
** This method is the destructor for series_cursor objects.
*/
static int dolite_diff_Disconnect(sqlite3_vtab *pVtab) {
  fprintf(stderr, "dolite_diff_Disconnect\n");
  dolite_diff_vtab *p = (dolite_diff_vtab *)pVtab;
  sqlite3_free(p->dbname);
  sqlite3_free(p);
  return SQLITE_OK;
}

/*
** Constructor for a new series_cursor object.
*/
static int dolite_diff_Open(sqlite3_vtab *p, sqlite3_vtab_cursor **ppCursor) {
#ifdef DEBUG
  fprintf(stderr, "dolite_diff_Open\n");
#endif
  dolite_diff_cursor *pCur;
  dolite_diff_vtab *pTab = (dolite_diff_vtab *)p;

  pCur = sqlite3_malloc(sizeof(*pCur));
  if (pCur == 0)
    return SQLITE_NOMEM;

  memset(pCur, 0, sizeof(*pCur));
  *ppCursor = &pCur->base;
  pCur->db = pTab->db;

  return SQLITE_OK;
}

/*
** Destructor for a series_cursor.
*/
static int dolite_diff_Close(sqlite3_vtab_cursor *cur) {
  fprintf(stderr, "dolite_diff_Close\n");
  dolite_diff_cursor *p = (dolite_diff_cursor *)cur;
  sqlite3changeset_finalize(p->diffiter);
  sqlite3_free(p->diff.data);
  sqlite3_free(p->commit_str);
  sqlite3_free(p);
  return SQLITE_OK;
}

/*
** Advance a series_cursor to its next row of output.
*/
static int dolite_diff_Next(sqlite3_vtab_cursor *cur) {
#ifdef DEBUG
  fprintf(stderr, "dolite_diff_Next\n");
#endif
  /*   dolite_diff_cursor *pCur = (dolite_diff_cursor *)cur; */
  /*   pCur->rc = sqlite3_step(pCur->stmt); */
  /* #ifdef DEBUG */
  /*   fprintf(stderr, "sqlite_diff_next: rc %d\n", pCur->rc); */
  /* #endif */
  return SQLITE_OK;
}

/*
** Return values of columns for the row at which the series_cursor
** is currently pointing.
*/
static int dolite_diff_Column(sqlite3_vtab_cursor *cur, /* The cursor */
                              sqlite3_context *ctx,     /* First argument to sqlite3_result_...() */
                              int i                     /* Which column to return */
) {
  dolite_diff_cursor *pCur = (dolite_diff_cursor *)cur;
  // fprintf(stderr, "dolite_diff_Column %d\n", i);
  if (pCur->eof)
    return SQLITE_ERROR;

  if (i == 5) {
    sqlite3_result_text(ctx, pCur->commit_str, strlen(pCur->commit_str), NULL);
    return SQLITE_OK;
  }

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
    fprintf(stderr, "dolite_diff_Column: pOp invalid!\n");
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
    // char *outstr = sqlite3_mprintf("%w", buffer);
    sqlite3_result_text(ctx, buffer, strlen(buffer), NULL);
    break;
  default:
    assert(i < 4);
    break;
  }

  return SQLITE_OK;
}

#ifndef LARGEST_UINT64
#define LARGEST_UINT64 (0xffffffff | (((sqlite3_uint64)0xffffffff) << 32))
#endif

/*
** Return the rowid for the current row, logically equivalent to n+1 where
** "n" is the ascending integer in the aforesaid production definition.
*/
static int dolite_diff_Rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  fprintf(stderr, "dolite_diff_Rowid\n");
  dolite_diff_cursor *pCur = (dolite_diff_cursor *)cur;
  /* sqlite3_uint64 n = pCur->ss.uSeqIndexNow; */
  /* *pRowid = (sqlite3_int64)((n < LARGEST_UINT64) ? n + 1 : 0); */
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int dolite_diff_Eof(sqlite3_vtab_cursor *cur) {
  dolite_diff_cursor *pCur = (dolite_diff_cursor *)cur;

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
#ifdef DEBUG
  fprintf(stderr, "dolite_diff_Eof -> returning %d\n", pCur->eof);
#endif
  return pCur->eof;
}

changeset get_commit_changeset(sqlite3 *db, char *dbname, char *commit_hash) {
  changeset result = {.data = NULL, .len = 0};
  sqlite3_stmt *stmt;
  char *get_commit_diff_sql = sqlite3_mprintf("SELECT diff FROM %w_commits WHERE hash = '%w';", dbname, commit_hash);
  int rc = sqlite3_prepare_v2(db, get_commit_diff_sql, -1, &stmt, 0);
  sqlite3_free(get_commit_diff_sql);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "get_commit_diff: prepare_v2 returned %d (%s) error: %s\n", rc, error_names[rc],
            sqlite3_errmsg(db));
    goto error;
  }
  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    result = changeset_duplicate(sqlite3_column_bytes(stmt, 0), sqlite3_column_blob(stmt, 0));
  }
error:
  sqlite3_finalize(stmt);

  return result;
}

/* True to cause run-time checking of the start=, stop=, and/or step=
** parameters.  The only reason to do this is for testing the
** constraint checking logic for virtual tables in the SQLite core.
*/
#ifndef SQLITE_SERIES_CONSTRAINT_VERIFY
#define SQLITE_SERIES_CONSTRAINT_VERIFY 0
#endif

static int dolite_diff_Filter(sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStrUnused, int argc,
                              sqlite3_value **argv) {

  dolite_diff_cursor *pCur = (dolite_diff_cursor *)pVtabCursor;
  int rc;
  char *dbname = dolite_config_get(pCur->db, "DBNAME");
  sqlite3changeset_finalize(pCur->diffiter);
  sqlite3_free(pCur->diff.data);
  sqlite3_free(pCur->commit_str);

#ifdef DEBUG
  fprintf(stderr, "dolite_diff_Filter(%p, %d, %s, %d, %p)\n", pVtabCursor, idxNum, idxStrUnused, argc, argv);
#endif

  pCur->iRowid = 0;
  if (pCur->diff.len == 0)
    pCur->eof = 1;
  if (argc == 0 || sqlite3_value_type(argv[0]) != SQLITE_TEXT) {
    fprintf(stderr, "Not sure which commit to work on?\n");
    rc = SQLITE_DONE;
    pCur->eof = 1;
    goto cleanup_dbname;
  }
  pCur->commit_str = sqlite3_mprintf("%s", sqlite3_value_text(argv[0]));
  pCur->diff = get_commit_changeset(pCur->db, dbname, sqlite3_value_text(argv[0]));

  fprintf(stderr, "got diff for commit %s, len: %d\n", sqlite3_value_text(argv[0]), pCur->diff.len);
  if (pCur->diff.len == 0 || pCur->diff.data == NULL) {
    pCur->eof = 1;
    rc = SQLITE_NOTFOUND;
    goto cleanup_dbname;
  }
  rc = sqlite3changeset_start(&(pCur->diffiter), pCur->diff.len, pCur->diff.data);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "dolite_diff_Filter: failure fetching changeset, %s rc: %d. %s\n", sqlite3_value_text(argv[0]), rc,
            error_names[rc]);
    goto cleanup_dbname;
  }
  pCur->eof = 0;
  rc = SQLITE_OK;

cleanup_dbname:
  sqlite3_free(dbname);
  return rc;
}

/*
** SQLite will invoke this method one or more times while planning a query
** that uses the generate_series virtual table.  This routine needs to create
** a query plan for each invocation and compute an estimated cost for that
** plan.
**
** In this implementation idxNum is used to represent the
** query plan.  idxStr is unused.
**
** The query plan is represented by bits in idxNum:
**
**  (1)  start = $value  -- constraint exists
**  (2)  stop = $value   -- constraint exists
**  (4)  step = $value   -- constraint exists
**  (8)  output in descending order
*/
static int dolite_diff_BestIndex(sqlite3_vtab *pVTab, sqlite3_index_info *pIdxInfo) {

#ifdef DEBUG
  fprintf(stderr, "dolite_diff_BestIndex\n");
  fprintf(stderr, "nConstraint %d\n", pIdxInfo->nConstraint);
#endif
  int found = 0;

  for (int i = 0; i < pIdxInfo->nConstraint; i++) {
#ifdef DEBUG
    fprintf(stderr, "  iColumn %d\n", pIdxInfo->aConstraint[i].iColumn);
    fprintf(stderr, "  op %d\n", pIdxInfo->aConstraint[i].op);
    fprintf(stderr, "  usable %d\n", pIdxInfo->aConstraint[i].usable);
#endif
    if (pIdxInfo->aConstraint[i].usable) {
      pIdxInfo->aConstraintUsage[i].argvIndex = i + 1;
      found = 1;
    }
  }

  /*
  if (!found) {
    sqlite3_free(pVTab->zErrMsg);
    pVTab->zErrMsg = sqlite3_mprintf("first argument to \"dolite_log()\" missing or unusable");
    return SQLITE_ERROR;
  }
  */
  return SQLITE_OK;
}

static sqlite3_module dolite_diff_Module = {
    0,                      /* iVersion */
    0,                      /* xCreate */
    dolite_diff_Connect,    /* xConnect */
    dolite_diff_BestIndex,  /* xBestIndex */
    dolite_diff_Disconnect, /* xDisconnect */
    0,                      /* xDestroy */
    dolite_diff_Open,       /* xOpen - open a cursor */
    dolite_diff_Close,      /* xClose - close a cursor */
    dolite_diff_Filter,     /* xFilter - configure scan constraints */
    dolite_diff_Next,       /* xNext - advance a cursor */
    dolite_diff_Eof,        /* xEof - check for end of scan */
    dolite_diff_Column,     /* xColumn - read data */
    dolite_diff_Rowid,      /* xRowid - read data */
    0,                      /* xUpdate */
    0,                      /* xBegin */
    0,                      /* xSync */
    0,                      /* xCommit */
    0,                      /* xRollback */
    0,                      /* xFindMethod */
    0,                      /* xRename */
    0,                      /* xSavepoint */
    0,                      /* xRelease */
    0,                      /* xRollbackTo */
    0,                      /* xShadowName */
    0                       /* xIntegrity */
};

#ifdef _WIN32
__declspec(dllexport)
#endif
    int sqlite3_dolite_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
  fprintf(stderr, "dolite_log_init\n");
  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
#ifndef SQLITE_OMIT_VIRTUALTABLE
  if (sqlite3_libversion_number() < 3008012 && pzErrMsg != 0) {
    *pzErrMsg = sqlite3_mprintf("dolite_log() requires SQLite 3.8.12 or later");
    return SQLITE_ERROR;
  }
  rc = sqlite3_create_module(db, "dolite", &dolite_changes_Module, 0);
  fprintf(stderr, "sqlite3_create_module(dolite_changes) returned %d \n", rc);
  rc = sqlite3_create_module(db, "dolite_log", &dolite_log_Module, 0);
  fprintf(stderr, "sqlite3_create_module(dolite_log) returned %d \n", rc);
  rc = sqlite3_create_module(db, "dolite_diff", &dolite_diff_Module, 0);
  fprintf(stderr, "sqlite3_create_module(dolite_diff) returned %d \n", rc);
#endif
  return rc;
}
