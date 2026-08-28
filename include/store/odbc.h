#ifndef OPENDBSC_STORE_ODBC_H
#define OPENDBSC_STORE_ODBC_H

#include "store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file store/odbc.h
 * @brief ODBC-backed session store factory for OpenDBSC.
 */

/**
 * @brief Configuration for an ODBC-backed session store.
 */
typedef struct {
    const char *connection_string; /**< ODBC connection string (required). */
    const char *table_name;        /**< Table name, or @c NULL for "sessions". */
    int auto_create_table;         /**< Non-zero to create the schema if missing. */
    int login_timeout_seconds;     /**< Login timeout, or 0 for the driver default. */
} OpenDBSC_OdbcConfig;

/**
 * @brief Create a new ODBC-backed session store.
 *
 * The returned store is allocated with @c malloc and must be released by
 * calling the store's @c destroy operation.
 *
 * The store connects through any ODBC driver manager (unixODBC or iODBC),
 * so sessions can be persisted in MySQL, PostgreSQL, SQL Server, or any
 * other RDBMS with an ODBC driver. Timestamps are stored as RFC 3339 UTC
 * strings, matching the SQLite backend.
 *
 * When @p config->auto_create_table is non-zero, a portable schema is
 * created on a best-effort basis; failure (for example because the table
 * already exists) is ignored.
 *
 * @param config Store configuration. Must provide a connection string.
 *
 * @return A pointer to the newly allocated store, or @c NULL if the
 *         configuration is invalid, allocation failed, or the connection
 *         could not be established.
 */
OpenDBSC_Store *opendbsc_odbc_store_create(const OpenDBSC_OdbcConfig *config);

#ifdef __cplusplus
}
#endif

#endif
