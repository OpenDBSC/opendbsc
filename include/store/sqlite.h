#ifndef OPENDBSC_STORE_SQLITE_H
#define OPENDBSC_STORE_SQLITE_H

#include "store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file store/sqlite.h
 * @brief SQLite-backed session store factory for OpenDBSC.
 */

/**
 * @brief Create a new SQLite-backed session store.
 *
 * The returned store is allocated with @c malloc and must be released with
 * @c opendbsc_sqlite_store_close().
 *
 * The database schema is created automatically if it does not already exist
 * and matches the Go implementation: a @c sessions table with @c id,
 * @c user_id, @c state, @c public_key, @c algorithm, @c challenge,
 * @c expires_at and @c created_at columns.
 *
 * @param path Filesystem path to the SQLite database. Pass @c NULL to create
 *             an in-memory database.
 *
 * @return A pointer to the newly allocated store, or @c NULL if the database
 *         could not be opened or the schema could not be created.
 */
OpenDBSC_Store *opendbsc_sqlite_store_create(const char *path);

/**
 * @brief Close and destroy a SQLite session store.
 *
 * This function closes the underlying SQLite database and frees the store
 * object. After returning, @p store must not be used again.
 *
 * @param store Store to close, or @c NULL.
 */
void opendbsc_sqlite_store_close(OpenDBSC_Store *store);

#ifdef __cplusplus
}
#endif

#endif
