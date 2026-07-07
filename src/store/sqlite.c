#define _GNU_SOURCE

#include "store/sqlite.h"
#include "store/store.h"
#include "session/session.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @file store/sqlite.c
 * @brief SQLite-backed session store implementation for OpenDBSC.
 *
 * This store persists OpenDBSC sessions in a SQLite database using the same
 * schema as the Go sqlite store: id, user_id, state, public_key, algorithm,
 * challenge, expires_at and created_at.
 */

/**
 * @brief Schema used to initialize the SQLite database.
 */
static const char *OPENDBSC_SQLITE_SCHEMA =
    "CREATE TABLE IF NOT EXISTS sessions ("
    "  id         TEXT PRIMARY KEY,"
    "  user_id    TEXT NOT NULL,"
    "  state      TEXT NOT NULL DEFAULT 'active',"
    "  public_key TEXT,"
    "  algorithm  TEXT,"
    "  challenge  TEXT,"
    "  expires_at DATETIME,"
    "  created_at DATETIME NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);";

/**
 * @brief Implementation context shared between the store vtable and SQLite.
 */
typedef struct {
    sqlite3 *db;          /**< SQLite database handle. */
    OpenDBSC_Store *store; /**< Back pointer to the owning store object. */
} opendbsc_sqlite_ctx;

/* Forward declarations for the vtable implementations. */
static int sqlite_create(void *impl, const OpenDBSC_Session *session);
static int sqlite_get(void *impl, const char *id, OpenDBSC_Session **out);
static int sqlite_update(void *impl, const OpenDBSC_Session *session);
static int sqlite_delete(void *impl, const char *id);
static int sqlite_get_by_user_id(void *impl, const char *user_id,
                                 OpenDBSC_Session **out, size_t *count);
static int sqlite_delete_by_user_id(void *impl, const char *user_id);
static void sqlite_free_sessions(void *impl, OpenDBSC_Session *sessions,
                                 size_t count);
static void sqlite_destroy(void *impl);

/**
 * @brief Format a @c time_t as an RFC 3339 UTC string.
 *
 * @param t      Timestamp to format.
 * @param buf    Output buffer.
 * @param buf_size Size of @p buf in bytes.
 *
 * @return 0 on success, or -1 if formatting failed.
 */
static int format_rfc3339_utc(time_t t, char *buf, size_t buf_size) {
    struct tm tm = {0};
    if (gmtime_r(&t, &tm) == NULL) {
        return -1;
    }
    if (strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief Parse an RFC 3339 timestamp into a @c time_t.
 *
 * The timezone suffix (if any) is ignored; the parsed local time is treated
 * as UTC because the Go store always writes values in UTC.
 *
 * @param s   Null-terminated timestamp string.
 * @param out Pointer that receives the parsed timestamp.
 *
 * @return 0 on success, or -1 if parsing failed.
 */
static int parse_rfc3339_utc(const char *s, time_t *out) {
    struct tm tm = {0};
    const char *rest = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
    if (rest == NULL) {
        return -1;
    }
    *out = timegm(&tm);
    if (*out == (time_t)-1) {
        return -1;
    }
    return 0;
}

/**
 * @brief Bind a nullable text value to a prepared statement parameter.
 *
 * @param stmt Prepared statement.
 * @param idx  Parameter index (1-based).
 * @param text Text value, or @c NULL to bind @c NULL.
 *
 * @return 0 on success, or -1 on failure.
 */
static int bind_text_or_null(sqlite3_stmt *stmt, int idx, const char *text) {
    int rc;
    if (text == NULL) {
        rc = sqlite3_bind_null(stmt, idx);
    } else {
        rc = sqlite3_bind_text(stmt, idx, text, -1, SQLITE_TRANSIENT);
    }
    return rc == SQLITE_OK ? 0 : -1;
}

/**
 * @brief Populate a pre-initialized session from the current result row.
 *
 * Column order is: id, user_id, state, public_key, algorithm, challenge,
 * expires_at, created_at.
 *
 * @param stmt    Prepared statement positioned on a result row.
 * @param session Session object to fill.
 *
 * @return 0 on success, or -1 if a value could not be copied.
 */
static int session_from_stmt(sqlite3_stmt *stmt, OpenDBSC_Session *session) {
    const unsigned char *id = sqlite3_column_text(stmt, 0);
    const unsigned char *user_id = sqlite3_column_text(stmt, 1);
    const unsigned char *state = sqlite3_column_text(stmt, 2);
    const unsigned char *public_key = sqlite3_column_text(stmt, 3);
    const unsigned char *algorithm = sqlite3_column_text(stmt, 4);
    const unsigned char *challenge = sqlite3_column_text(stmt, 5);
    const unsigned char *expires_at = sqlite3_column_text(stmt, 6);
    const unsigned char *created_at = sqlite3_column_text(stmt, 7);

    if (id == NULL || user_id == NULL || state == NULL || created_at == NULL) {
        return -1;
    }

    opendbsc_session_init(session);

    if (opendbsc_session_set_id(session, (const char *)id) != 0 ||
        opendbsc_session_set_user_id(session, (const char *)user_id) != 0 ||
        opendbsc_session_set_state_str(session, (const char *)state) != 0 ||
        opendbsc_session_set_public_key(session,
                                        (const char *)public_key) != 0 ||
        opendbsc_session_set_algorithm(session, (const char *)algorithm) != 0 ||
        opendbsc_session_set_challenge(session, (const char *)challenge) != 0) {
        opendbsc_session_free(session);
        return -1;
    }

    if (expires_at != NULL) {
        time_t expires;
        if (parse_rfc3339_utc((const char *)expires_at, &expires) != 0) {
            opendbsc_session_free(session);
            return -1;
        }
        opendbsc_session_set_expires_at(session, expires);
    }

    time_t created;
    if (parse_rfc3339_utc((const char *)created_at, &created) != 0) {
        opendbsc_session_free(session);
        return -1;
    }
    opendbsc_session_set_created_at(session, created);

    return 0;
}

/**
 * @brief Free an array of sessions and the array itself.
 */
static void free_session_array(OpenDBSC_Session *sessions, size_t count) {
    if (sessions == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        opendbsc_session_free(&sessions[i]);
    }
    free(sessions);
}

static int sqlite_create(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql =
        "INSERT INTO sessions (id, user_id, state, public_key, algorithm, "
        "challenge, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int idx = 1;
    int rc = -1;
    char expires_buf[32];
    char created_buf[32];
    const char *state = opendbsc_session_state_str(session);

    if (sqlite3_bind_text(stmt, idx++, session->id, -1, SQLITE_TRANSIENT) !=
            SQLITE_OK ||
        bind_text_or_null(stmt, idx++, session->user_id) != 0 ||
        bind_text_or_null(stmt, idx++, state) != 0 ||
        bind_text_or_null(stmt, idx++, session->public_key) != 0 ||
        bind_text_or_null(stmt, idx++, session->algorithm) != 0 ||
        bind_text_or_null(stmt, idx++, session->challenge) != 0) {
        goto done;
    }

    if (session->has_expires) {
        if (format_rfc3339_utc(session->expires_at, expires_buf,
                               sizeof(expires_buf)) != 0) {
            goto done;
        }
        if (sqlite3_bind_text(stmt, idx++, expires_buf, -1,
                              SQLITE_TRANSIENT) != SQLITE_OK) {
            goto done;
        }
    } else {
        if (sqlite3_bind_null(stmt, idx++) != SQLITE_OK) {
            goto done;
        }
    }

    if (format_rfc3339_utc(session->created_at, created_buf,
                           sizeof(created_buf)) != 0) {
        goto done;
    }
    if (sqlite3_bind_text(stmt, idx++, created_buf, -1, SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        goto done;
    }

    rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;

done:
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_get(void *impl, const char *id, OpenDBSC_Session **out) {
    if (impl == NULL || id == NULL || out == NULL) {
        return -1;
    }
    *out = NULL;

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql =
        "SELECT id, user_id, state, public_key, algorithm, challenge, "
        "expires_at, created_at FROM sessions WHERE id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int rc = -1;
    if (sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        goto done;
    }

    int step = sqlite3_step(stmt);
    if (step != SQLITE_ROW) {
        rc = -1;
        goto done;
    }

    OpenDBSC_Session *session = (OpenDBSC_Session *)malloc(sizeof(*session));
    if (session == NULL) {
        goto done;
    }
    opendbsc_session_init(session);

    if (session_from_stmt(stmt, session) != 0) {
        free(session);
        goto done;
    }

    time_t now = time(NULL);
    if (session->has_expires && session->expires_at < now) {
        /* Session is expired: clean it up and report not found. */
        sqlite_delete(impl, id);
        opendbsc_session_free(session);
        free(session);
        goto done;
    }

    *out = session;
    rc = 0;

done:
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_update(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql =
        "UPDATE sessions SET user_id = ?, state = ?, public_key = ?, "
        "algorithm = ?, challenge = ?, expires_at = ? WHERE id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int idx = 1;
    int rc = -1;
    char expires_buf[32];
    const char *state = opendbsc_session_state_str(session);

    if (bind_text_or_null(stmt, idx++, session->user_id) != 0 ||
        bind_text_or_null(stmt, idx++, state) != 0 ||
        bind_text_or_null(stmt, idx++, session->public_key) != 0 ||
        bind_text_or_null(stmt, idx++, session->algorithm) != 0 ||
        bind_text_or_null(stmt, idx++, session->challenge) != 0) {
        goto done;
    }

    if (session->has_expires) {
        if (format_rfc3339_utc(session->expires_at, expires_buf,
                               sizeof(expires_buf)) != 0) {
            goto done;
        }
        if (sqlite3_bind_text(stmt, idx++, expires_buf, -1,
                              SQLITE_TRANSIENT) != SQLITE_OK) {
            goto done;
        }
    } else {
        if (sqlite3_bind_null(stmt, idx++) != SQLITE_OK) {
            goto done;
        }
    }

    if (sqlite3_bind_text(stmt, idx++, session->id, -1, SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        goto done;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        goto done;
    }

    rc = sqlite3_changes(ctx->db) > 0 ? 0 : -1;

done:
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_delete(void *impl, const char *id) {
    if (impl == NULL || id == NULL) {
        return -1;
    }

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql = "DELETE FROM sessions WHERE id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int rc = -1;
    if (sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE) {
        rc = 0;
    }

    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_get_by_user_id(void *impl, const char *user_id,
                                 OpenDBSC_Session **out, size_t *count) {
    if (impl == NULL || user_id == NULL || out == NULL || count == NULL) {
        return -1;
    }
    *out = NULL;
    *count = 0;

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql =
        "SELECT id, user_id, state, public_key, algorithm, challenge, "
        "expires_at, created_at FROM sessions WHERE user_id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int rc = -1;
    if (sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        goto done;
    }

    OpenDBSC_Session *sessions = NULL;
    size_t n = 0;
    char **expired_ids = NULL;
    size_t expired_count = 0;
    time_t now = time(NULL);

    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        OpenDBSC_Session tmp;
        if (session_from_stmt(stmt, &tmp) != 0) {
            free_session_array(sessions, n);
            goto done;
        }

        if (tmp.has_expires && tmp.expires_at < now) {
            char *copy = strdup(tmp.id);
            opendbsc_session_free(&tmp);
            if (copy == NULL) {
                free_session_array(sessions, n);
                goto done;
            }
            char **next =
                (char **)realloc(expired_ids, (expired_count + 1) *
                                                  sizeof(*expired_ids));
            if (next == NULL) {
                free(copy);
                free_session_array(sessions, n);
                goto done;
            }
            expired_ids = next;
            expired_ids[expired_count++] = copy;
            continue;
        }

        OpenDBSC_Session *next =
            (OpenDBSC_Session *)realloc(sessions, (n + 1) * sizeof(*sessions));
        if (next == NULL) {
            opendbsc_session_free(&tmp);
            free_session_array(sessions, n);
            goto done;
        }
        sessions = next;
        memcpy(&sessions[n], &tmp, sizeof(tmp));
        n++;
    }

    if (step != SQLITE_DONE) {
        free_session_array(sessions, n);
        goto done;
    }

    /* Clean up expired sessions after closing the read statement. */
    sqlite3_finalize(stmt);
    stmt = NULL;

    for (size_t i = 0; i < expired_count; i++) {
        sqlite_delete(impl, expired_ids[i]);
        free(expired_ids[i]);
    }
    free(expired_ids);

    *out = sessions;
    *count = n;
    return 0;

done:
    sqlite3_finalize(stmt);
    for (size_t i = 0; i < expired_count; i++) {
        free(expired_ids[i]);
    }
    free(expired_ids);
    return rc;
}

static int sqlite_delete_by_user_id(void *impl, const char *user_id) {
    if (impl == NULL || user_id == NULL) {
        return -1;
    }

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    const char *sql = "DELETE FROM sessions WHERE user_id = ?";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    int rc = -1;
    if (sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE) {
        rc = 0;
    }

    sqlite3_finalize(stmt);
    return rc;
}

static void sqlite_free_sessions(void *impl, OpenDBSC_Session *sessions,
                                 size_t count) {
    (void)impl;
    free_session_array(sessions, count);
}

static void sqlite_destroy(void *impl) {
    if (impl == NULL) {
        return;
    }

    opendbsc_sqlite_ctx *ctx = (opendbsc_sqlite_ctx *)impl;
    if (ctx->db != NULL) {
        sqlite3_close(ctx->db);
    }
    free(ctx->store);
    free(ctx);
}

OpenDBSC_Store *opendbsc_sqlite_store_create(const char *path) {
    if (path == NULL) {
        path = ":memory:";
    }

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    if (sqlite3_exec(db, OPENDBSC_SQLITE_SCHEMA, NULL, NULL, NULL) !=
        SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    OpenDBSC_Store *store =
        (OpenDBSC_Store *)malloc(sizeof(*store));
    if (store == NULL) {
        sqlite3_close(db);
        return NULL;
    }

    opendbsc_sqlite_ctx *ctx =
        (opendbsc_sqlite_ctx *)malloc(sizeof(*ctx));
    if (ctx == NULL) {
        free(store);
        sqlite3_close(db);
        return NULL;
    }

    ctx->db = db;
    ctx->store = store;

    store->impl = ctx;
    store->create = sqlite_create;
    store->get = sqlite_get;
    store->update = sqlite_update;
    store->delete = sqlite_delete;
    store->get_by_user_id = sqlite_get_by_user_id;
    store->delete_by_user_id = sqlite_delete_by_user_id;
    store->free_sessions = sqlite_free_sessions;
    store->destroy = sqlite_destroy;

    return store;
}

void opendbsc_sqlite_store_close(OpenDBSC_Store *store) {
    if (store == NULL) {
        return;
    }
    store->destroy(store->impl);
}
