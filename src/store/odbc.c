#define _GNU_SOURCE

#include "store/odbc.h"
#include "store/store.h"
#include "session/session.h"

#include <sql.h>
#include <sqlext.h>

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @file store/odbc.c
 * @brief ODBC-backed session store implementation for OpenDBSC.
 *
 * This store persists OpenDBSC sessions in any RDBMS reachable through an
 * ODBC driver manager (unixODBC or iODBC), using the same schema and
 * semantics as the SQLite backend: id, user_id, state, public_key,
 * algorithm, challenge, expires_at and created_at. Timestamps are stored
 * as RFC 3339 UTC strings.
 */

/**
 * @brief Maximum number of bound parameters used by any statement.
 */
#define OPENDBSC_ODBC_MAX_PARAMS 8

/**
 * @brief Statement wrapper that keeps parameter length indicators alive
 *        until the statement is executed.
 */
typedef struct {
    SQLHSTMT stmt;                            /**< ODBC statement handle. */
    SQLLEN inds[OPENDBSC_ODBC_MAX_PARAMS];    /**< Length/NULL indicators. */
    SQLSMALLINT nparams;                      /**< Number of bound parameters. */
} odbc_stmt;

/**
 * @brief Implementation context shared between the store vtable and ODBC.
 */
typedef struct {
    SQLHENV env;             /**< ODBC environment handle. */
    SQLHDBC dbc;             /**< ODBC connection handle. */
    pthread_mutex_t mutex;   /**< Serializes all store operations. */
    int mutex_init;          /**< Non-zero once the mutex is initialized. */
    char *table_name;        /**< Validated table identifier. */
    OpenDBSC_Store *store;   /**< Back pointer to the owning store object. */
} opendbsc_odbc_ctx;

/* Forward declarations for the vtable implementations. */
static int odbc_create(void *impl, const OpenDBSC_Session *session);
static int odbc_get(void *impl, const char *id, OpenDBSC_Session **out);
static int odbc_update(void *impl, const OpenDBSC_Session *session);
static int odbc_delete(void *impl, const char *id);
static int odbc_get_by_user_id(void *impl, const char *user_id,
                               OpenDBSC_Session **out, size_t *count);
static int odbc_delete_by_user_id(void *impl, const char *user_id);
static void odbc_free_sessions(void *impl, OpenDBSC_Session *sessions,
                               size_t count);
static void odbc_destroy(void *impl);

/**
 * @brief Format a @c time_t as an RFC 3339 UTC string.
 *
 * @param t        Timestamp to format.
 * @param buf      Output buffer.
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
 * The timezone suffix (if any) is ignored; the parsed time is treated as
 * UTC because values are always written in UTC.
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
 * @brief Check that a table name is a safe SQL identifier.
 *
 * Only ASCII alphanumerics and underscores are accepted, so the identifier
 * can be inserted into a query string without quoting.
 *
 * @param name Identifier to validate.
 *
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_identifier(const char *name) {
    if (name == NULL || *name == '\0') {
        return 0;
    }
    for (const char *p = name; *p != '\0'; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Allocate and prepare a statement for the given SQL string.
 *
 * @param ctx Store context.
 * @param sql SQL text to prepare.
 * @param out Statement wrapper to initialize.
 *
 * @return 0 on success, or -1 on failure.
 */
static int odbc_prepare(opendbsc_odbc_ctx *ctx, const char *sql,
                        odbc_stmt *out) {
    out->stmt = SQL_NULL_HSTMT;
    out->nparams = 0;
    if (SQLAllocHandle(SQL_HANDLE_STMT, ctx->dbc, &out->stmt) !=
            SQL_SUCCESS ||
        SQLPrepare(out->stmt, (SQLCHAR *)sql, SQL_NTS) != SQL_SUCCESS) {
        if (out->stmt != SQL_NULL_HSTMT) {
            SQLFreeHandle(SQL_HANDLE_STMT, out->stmt);
            out->stmt = SQL_NULL_HSTMT;
        }
        return -1;
    }
    return 0;
}

/**
 * @brief Bind a nullable text value to the next statement parameter.
 *
 * @param s    Statement wrapper returned by @c odbc_prepare.
 * @param text Text value, or @c NULL to bind SQL @c NULL.
 *
 * @return 0 on success, or -1 on failure.
 */
static int odbc_bind_text(odbc_stmt *s, const char *text) {
    if (s->nparams >= OPENDBSC_ODBC_MAX_PARAMS) {
        return -1;
    }
    SQLUSMALLINT idx = (SQLUSMALLINT)(s->nparams + 1);
    s->inds[s->nparams] = text != NULL ? SQL_NTS : SQL_NULL_DATA;
    SQLLEN *ind = &s->inds[s->nparams];
    s->nparams++;
    SQLRETURN rc = SQLBindParameter(s->stmt, idx, SQL_PARAM_INPUT, SQL_C_CHAR,
                                    SQL_VARCHAR, 1024, 0, (SQLPOINTER)text,
                                    0, ind);
    return SQL_SUCCEEDED(rc) ? 0 : -1;
}

/**
 * @brief Release a statement wrapper.
 */
static void odbc_stmt_close(odbc_stmt *s) {
    if (s->stmt != SQL_NULL_HSTMT) {
        SQLFreeHandle(SQL_HANDLE_STMT, s->stmt);
        s->stmt = SQL_NULL_HSTMT;
    }
}

/**
 * @brief Fetch a nullable text column from the current result row.
 *
 * Reads the column in chunks so arbitrarily long values are supported.
 *
 * @param stmt Statement positioned on a result row.
 * @param col  Column index (1-based).
 * @param out  Receives a @c malloc'ed string, or @c NULL for SQL @c NULL.
 *             Must be freed by the caller.
 *
 * @return 0 on success, or -1 on failure.
 */
static int odbc_get_text(SQLHSTMT stmt, SQLUSMALLINT col, char **out) {
    char chunk[512];
    char *buf = NULL;
    size_t len = 0;
    *out = NULL;

    for (;;) {
        SQLLEN ind = 0;
        SQLRETURN rc =
            SQLGetData(stmt, col, SQL_C_CHAR, chunk, sizeof(chunk), &ind);
        if (rc == SQL_ERROR) {
            free(buf);
            return -1;
        }
        if (ind == SQL_NULL_DATA) {
            free(buf);
            return 0;
        }
        size_t got;
        if (ind == SQL_NO_TOTAL || (size_t)ind > sizeof(chunk) - 1) {
            got = sizeof(chunk) - 1;
        } else {
            got = (size_t)ind;
        }
        char *next = (char *)realloc(buf, len + got + 1);
        if (next == NULL) {
            free(buf);
            return -1;
        }
        buf = next;
        memcpy(buf + len, chunk, got);
        len += got;
        buf[len] = '\0';
        if (rc != SQL_SUCCESS_WITH_INFO) {
            break;
        }
    }

    *out = buf;
    return 0;
}

/**
 * @brief Populate a pre-initialized session from the current result row.
 *
 * Column order is: id, user_id, state, public_key, algorithm, challenge,
 * expires_at, created_at.
 *
 * @param stmt    Statement positioned on a result row.
 * @param session Session object to fill.
 *
 * @return 0 on success, or -1 if a value could not be read or copied.
 */
static int session_from_row(SQLHSTMT stmt, OpenDBSC_Session *session) {
    char *cols[8] = {NULL};
    for (SQLUSMALLINT i = 0; i < 8; i++) {
        if (odbc_get_text(stmt, (SQLUSMALLINT)(i + 1), &cols[i]) != 0) {
            goto fail;
        }
    }

    const char *id = cols[0];
    const char *user_id = cols[1];
    const char *state = cols[2];
    const char *expires_at = cols[6];
    const char *created_at = cols[7];

    if (id == NULL || user_id == NULL || state == NULL || created_at == NULL) {
        goto fail;
    }

    opendbsc_session_init(session);

    if (opendbsc_session_set_id(session, id) != 0 ||
        opendbsc_session_set_user_id(session, user_id) != 0 ||
        opendbsc_session_set_state_str(session, state) != 0 ||
        opendbsc_session_set_public_key(session, cols[3]) != 0 ||
        opendbsc_session_set_algorithm(session, cols[4]) != 0 ||
        opendbsc_session_set_challenge(session, cols[5]) != 0) {
        opendbsc_session_free(session);
        goto fail;
    }

    if (expires_at != NULL) {
        time_t expires;
        if (parse_rfc3339_utc(expires_at, &expires) != 0) {
            opendbsc_session_free(session);
            goto fail;
        }
        opendbsc_session_set_expires_at(session, expires);
    }

    time_t created;
    if (parse_rfc3339_utc(created_at, &created) != 0) {
        opendbsc_session_free(session);
        goto fail;
    }
    opendbsc_session_set_created_at(session, created);

    for (size_t i = 0; i < 8; i++) {
        free(cols[i]);
    }
    return 0;

fail:
    for (size_t i = 0; i < 8; i++) {
        free(cols[i]);
    }
    return -1;
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

/**
 * @brief Delete a session by id. Caller must hold the context mutex.
 */
static int odbc_delete_unlocked(opendbsc_odbc_ctx *ctx, const char *id) {
    char sql[256];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE id = ?", ctx->table_name);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        return -1;
    }

    int rc = -1;
    if (odbc_bind_text(&s, id) == 0 && SQL_SUCCEEDED(SQLExecute(s.stmt))) {
        rc = 0;
    }

    odbc_stmt_close(&s);
    return rc;
}

/**
 * @brief Build a SELECT statement for the sessions table.
 */
static void build_select_sql(opendbsc_odbc_ctx *ctx, const char *where,
                             char *buf, size_t buf_size) {
    snprintf(buf, buf_size,
             "SELECT id, user_id, state, public_key, algorithm, challenge, "
             "expires_at, created_at FROM %s WHERE %s",
             ctx->table_name, where);
}

static int odbc_create(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    int rc = -1;
    char expires_buf[32];
    char created_buf[32];
    const char *state = opendbsc_session_state_str(session);
    const char *expires = NULL;

    if (session->has_expires) {
        if (format_rfc3339_utc(session->expires_at, expires_buf,
                               sizeof(expires_buf)) != 0) {
            return -1;
        }
        expires = expires_buf;
    }
    if (format_rfc3339_utc(session->created_at, created_buf,
                           sizeof(created_buf)) != 0) {
        return -1;
    }

    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (id, user_id, state, public_key, algorithm, "
             "challenge, expires_at, created_at) "
             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             ctx->table_name);

    pthread_mutex_lock(&ctx->mutex);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        goto done;
    }

    if (odbc_bind_text(&s, session->id) != 0 ||
        odbc_bind_text(&s, session->user_id) != 0 ||
        odbc_bind_text(&s, state) != 0 ||
        odbc_bind_text(&s, session->public_key) != 0 ||
        odbc_bind_text(&s, session->algorithm) != 0 ||
        odbc_bind_text(&s, session->challenge) != 0 ||
        odbc_bind_text(&s, expires) != 0 ||
        odbc_bind_text(&s, created_buf) != 0) {
        goto done_stmt;
    }

    rc = SQL_SUCCEEDED(SQLExecute(s.stmt)) ? 0 : -1;

done_stmt:
    odbc_stmt_close(&s);
done:
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

static int odbc_get(void *impl, const char *id, OpenDBSC_Session **out) {
    if (impl == NULL || id == NULL || out == NULL) {
        return -1;
    }
    *out = NULL;

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    int rc = -1;
    char sql[512];
    build_select_sql(ctx, "id = ?", sql, sizeof(sql));

    pthread_mutex_lock(&ctx->mutex);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        goto done;
    }
    if (odbc_bind_text(&s, id) != 0) {
        goto done_stmt;
    }
    if (!SQL_SUCCEEDED(SQLExecute(s.stmt))) {
        goto done_stmt;
    }
    if (SQLFetch(s.stmt) != SQL_SUCCESS) {
        goto done_stmt;
    }

    OpenDBSC_Session *session = (OpenDBSC_Session *)malloc(sizeof(*session));
    if (session == NULL) {
        goto done_stmt;
    }
    opendbsc_session_init(session);

    if (session_from_row(s.stmt, session) != 0) {
        free(session);
        goto done_stmt;
    }

    time_t now = time(NULL);
    if (session->has_expires && session->expires_at < now) {
        /* Session is expired: clean it up and report not found. */
        odbc_stmt_close(&s);
        s.stmt = SQL_NULL_HSTMT;
        odbc_delete_unlocked(ctx, id);
        opendbsc_session_free(session);
        free(session);
        goto done;
    }

    *out = session;
    rc = 0;

done_stmt:
    odbc_stmt_close(&s);
done:
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

static int odbc_update(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    int rc = -1;
    char expires_buf[32];
    const char *state = opendbsc_session_state_str(session);
    const char *expires = NULL;

    if (session->has_expires) {
        if (format_rfc3339_utc(session->expires_at, expires_buf,
                               sizeof(expires_buf)) != 0) {
            return -1;
        }
        expires = expires_buf;
    }

    char sql[512];
    snprintf(sql, sizeof(sql),
             "UPDATE %s SET user_id = ?, state = ?, public_key = ?, "
             "algorithm = ?, challenge = ?, expires_at = ? WHERE id = ?",
             ctx->table_name);

    pthread_mutex_lock(&ctx->mutex);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        goto done;
    }

    if (odbc_bind_text(&s, session->user_id) != 0 ||
        odbc_bind_text(&s, state) != 0 ||
        odbc_bind_text(&s, session->public_key) != 0 ||
        odbc_bind_text(&s, session->algorithm) != 0 ||
        odbc_bind_text(&s, session->challenge) != 0 ||
        odbc_bind_text(&s, expires) != 0 ||
        odbc_bind_text(&s, session->id) != 0) {
        goto done_stmt;
    }

    if (!SQL_SUCCEEDED(SQLExecute(s.stmt))) {
        goto done_stmt;
    }

    SQLLEN affected = 0;
    if (!SQL_SUCCEEDED(SQLRowCount(s.stmt, &affected)) || affected <= 0) {
        goto done_stmt;
    }
    rc = 0;

done_stmt:
    odbc_stmt_close(&s);
done:
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

static int odbc_delete(void *impl, const char *id) {
    if (impl == NULL || id == NULL) {
        return -1;
    }

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    pthread_mutex_lock(&ctx->mutex);
    int rc = odbc_delete_unlocked(ctx, id);
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

static int odbc_get_by_user_id(void *impl, const char *user_id,
                               OpenDBSC_Session **out, size_t *count) {
    if (impl == NULL || user_id == NULL || out == NULL || count == NULL) {
        return -1;
    }
    *out = NULL;
    *count = 0;

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    char sql[512];
    build_select_sql(ctx, "user_id = ?", sql, sizeof(sql));

    OpenDBSC_Session *sessions = NULL;
    size_t n = 0;
    char **expired_ids = NULL;
    size_t expired_count = 0;
    time_t now = time(NULL);
    int rc = -1;

    pthread_mutex_lock(&ctx->mutex);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        goto done;
    }
    if (odbc_bind_text(&s, user_id) != 0 ||
        !SQL_SUCCEEDED(SQLExecute(s.stmt))) {
        goto done_stmt;
    }

    SQLRETURN fetch_rc;
    while ((fetch_rc = SQLFetch(s.stmt)) == SQL_SUCCESS) {
        OpenDBSC_Session tmp;
        if (session_from_row(s.stmt, &tmp) != 0) {
            free_session_array(sessions, n);
            sessions = NULL;
            n = 0;
            goto done_stmt;
        }

        if (tmp.has_expires && tmp.expires_at < now) {
            char *copy = strdup(tmp.id);
            opendbsc_session_free(&tmp);
            if (copy == NULL) {
                free_session_array(sessions, n);
                sessions = NULL;
                n = 0;
                goto done_stmt;
            }
            char **next = (char **)realloc(expired_ids, (expired_count + 1) *
                                                            sizeof(*expired_ids));
            if (next == NULL) {
                free(copy);
                free_session_array(sessions, n);
                sessions = NULL;
                n = 0;
                goto done_stmt;
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
            sessions = NULL;
            n = 0;
            goto done_stmt;
        }
        sessions = next;
        memcpy(&sessions[n], &tmp, sizeof(tmp));
        n++;
    }

    if (fetch_rc != SQL_NO_DATA) {
        free_session_array(sessions, n);
        sessions = NULL;
        n = 0;
        goto done_stmt;
    }

    /* Clean up expired sessions after closing the read statement. */
    odbc_stmt_close(&s);
    s.stmt = SQL_NULL_HSTMT;

    for (size_t i = 0; i < expired_count; i++) {
        odbc_delete_unlocked(ctx, expired_ids[i]);
    }

    rc = 0;

done_stmt:
    odbc_stmt_close(&s);
done:
    pthread_mutex_unlock(&ctx->mutex);
    for (size_t i = 0; i < expired_count; i++) {
        free(expired_ids[i]);
    }
    free(expired_ids);
    if (rc == 0) {
        *out = sessions;
        *count = n;
    }
    return rc;
}

static int odbc_delete_by_user_id(void *impl, const char *user_id) {
    if (impl == NULL || user_id == NULL) {
        return -1;
    }

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    char sql[256];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE user_id = ?",
             ctx->table_name);

    pthread_mutex_lock(&ctx->mutex);

    odbc_stmt s;
    if (odbc_prepare(ctx, sql, &s) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return -1;
    }

    int rc = -1;
    if (odbc_bind_text(&s, user_id) == 0 &&
        SQL_SUCCEEDED(SQLExecute(s.stmt))) {
        rc = 0;
    }

    odbc_stmt_close(&s);
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

static void odbc_free_sessions(void *impl, OpenDBSC_Session *sessions,
                               size_t count) {
    (void)impl;
    free_session_array(sessions, count);
}

static void odbc_destroy(void *impl) {
    if (impl == NULL) {
        return;
    }

    opendbsc_odbc_ctx *ctx = (opendbsc_odbc_ctx *)impl;
    if (ctx->dbc != SQL_NULL_HDBC) {
        SQLDisconnect(ctx->dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, ctx->dbc);
    }
    if (ctx->env != SQL_NULL_HENV) {
        SQLFreeHandle(SQL_HANDLE_ENV, ctx->env);
    }
    if (ctx->mutex_init) {
        pthread_mutex_destroy(&ctx->mutex);
    }
    free(ctx->table_name);
    free(ctx->store);
    free(ctx);
}

/**
 * @brief Execute a single DDL statement, ignoring any error.
 */
static void odbc_exec_ignore(SQLHDBC dbc, const char *sql) {
    SQLHSTMT stmt = SQL_NULL_HSTMT;
    if (SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt) != SQL_SUCCESS) {
        return;
    }
    SQLExecDirect(stmt, (SQLCHAR *)sql, SQL_NTS);
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
}

/**
 * @brief Create the sessions table and indexes on a best-effort basis.
 */
static void odbc_create_schema(SQLHDBC dbc, const char *table) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE %s ("
             "  id         VARCHAR(64) PRIMARY KEY,"
             "  user_id    VARCHAR(255) NOT NULL,"
             "  state      VARCHAR(16) NOT NULL DEFAULT 'active',"
             "  public_key TEXT,"
             "  algorithm  VARCHAR(64),"
             "  challenge  TEXT,"
             "  expires_at VARCHAR(32),"
             "  created_at VARCHAR(32) NOT NULL"
             ")",
             table);
    odbc_exec_ignore(dbc, sql);

    snprintf(sql, sizeof(sql), "CREATE INDEX idx_%s_user_id ON %s(user_id)",
             table, table);
    odbc_exec_ignore(dbc, sql);

    snprintf(sql, sizeof(sql),
             "CREATE INDEX idx_%s_expires_at ON %s(expires_at)", table, table);
    odbc_exec_ignore(dbc, sql);
}

OpenDBSC_Store *opendbsc_odbc_store_create(const OpenDBSC_OdbcConfig *config) {
    if (config == NULL || config->connection_string == NULL) {
        return NULL;
    }

    const char *table =
        config->table_name != NULL ? config->table_name : "sessions";
    if (!is_valid_identifier(table)) {
        return NULL;
    }

    opendbsc_odbc_ctx *ctx =
        (opendbsc_odbc_ctx *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->env = SQL_NULL_HENV;
    ctx->dbc = SQL_NULL_HDBC;

    ctx->table_name = strdup(table);
    if (ctx->table_name == NULL) {
        goto fail;
    }
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        goto fail;
    }
    ctx->mutex_init = 1;

    if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &ctx->env) !=
            SQL_SUCCESS ||
        SQLSetEnvAttr(ctx->env, SQL_ATTR_ODBC_VERSION,
                      (SQLPOINTER)SQL_OV_ODBC3, 0) != SQL_SUCCESS ||
        SQLAllocHandle(SQL_HANDLE_DBC, ctx->env, &ctx->dbc) != SQL_SUCCESS) {
        goto fail;
    }

    if (config->login_timeout_seconds > 0) {
        SQLSetConnectAttr(ctx->dbc, SQL_LOGIN_TIMEOUT,
                          (SQLPOINTER)(intptr_t)config->login_timeout_seconds,
                          0);
    }

    SQLCHAR out_conn[1024];
    SQLSMALLINT out_len = 0;
    if (!SQL_SUCCEEDED(SQLDriverConnect(
            ctx->dbc, NULL, (SQLCHAR *)config->connection_string, SQL_NTS,
            out_conn, sizeof(out_conn), &out_len,
            SQL_DRIVER_NOPROMPT))) {
        goto fail;
    }

    if (config->auto_create_table) {
        odbc_create_schema(ctx->dbc, ctx->table_name);
    }

    OpenDBSC_Store *store = (OpenDBSC_Store *)malloc(sizeof(*store));
    if (store == NULL) {
        goto fail;
    }

    ctx->store = store;

    store->impl = ctx;
    store->create = odbc_create;
    store->get = odbc_get;
    store->update = odbc_update;
    store->delete = odbc_delete;
    store->get_by_user_id = odbc_get_by_user_id;
    store->delete_by_user_id = odbc_delete_by_user_id;
    store->free_sessions = odbc_free_sessions;
    store->destroy = odbc_destroy;

    return store;

fail:
    if (ctx->dbc != SQL_NULL_HDBC) {
        SQLDisconnect(ctx->dbc);
        SQLFreeHandle(SQL_HANDLE_DBC, ctx->dbc);
    }
    if (ctx->env != SQL_NULL_HENV) {
        SQLFreeHandle(SQL_HANDLE_ENV, ctx->env);
    }
    if (ctx->mutex_init) {
        pthread_mutex_destroy(&ctx->mutex);
    }
    free(ctx->table_name);
    free(ctx);
    return NULL;
}
