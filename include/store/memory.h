#ifndef OPENDBSC_STORE_MEMORY_H
#define OPENDBSC_STORE_MEMORY_H

#include "store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file store/memory.h
 * @brief In-memory session store factory for OpenDBSC.
 */

/**
 * @brief Create a new thread-safe in-memory session store.
 *
 * The returned store is allocated with @c malloc and must be released with
 * @c store->destroy(store->impl).
 *
 * Sessions are stored in a dynamic array protected by a @c pthread_mutex_t.
 * Retrieval operations return deep copies that must be released via
 * @c store->free_sessions.
 *
 * @return A pointer to the newly allocated store, or @c NULL if allocation
 *         or mutex initialization failed.
 */
OpenDBSC_Store *opendbsc_memory_store_create(void);

#ifdef __cplusplus
}
#endif

#endif
