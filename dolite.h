#ifndef DOLITE_H_
#define DOLITE_H_
#include "sqlite3.h"
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
int dolite_hash_blob(unsigned char *digest, int digest_len, void *data,
                     int data_len);
#endif // DOLITE_H_
