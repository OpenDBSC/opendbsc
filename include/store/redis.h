#ifndef OPENDBSC_STORE_REDIS_H
#define OPENDBSC_STORE_REDIS_H

#include "store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file store/redis.h
 * @brief Redis-backed session store factory for OpenDBSC.
 */

/**
 * @brief Redis connection configuration.
 */
typedef struct {
    const char *host; /**< Redis host. Defaults to "127.0.0.1" if NULL. */
    int port;         /**< Redis port. Defaults to 6379 if 0. */
    const char *prefix; /**< Key prefix. Defaults to "dbsc" if NULL. */
} OpenDBSC_RedisConfig;

/**
 * @brief Create a new Redis-backed session store.
 *
 * The returned store is allocated with @c malloc and must be released with
 * @c store->destroy(store->impl).
 *
 * @param config Redis connection configuration. May be @c NULL for defaults.
 *
 * @return A pointer to the newly allocated store, or @c NULL if the connection
 *         could not be established or allocation failed.
 */
OpenDBSC_Store *opendbsc_redis_store_create(const OpenDBSC_RedisConfig *config);

#ifdef __cplusplus
}
#endif

#endif
