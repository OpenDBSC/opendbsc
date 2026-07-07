#include "store/memory.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @file store/memory.c
 * @brief Thread-safe in-memory session store implementation.
 */

/**
 * @brief Initial capacity of the dynamic session array.
 */
#define OPENDBSC_MEMORY_STORE_INITIAL_CAPACITY 8

/**
 * @brief Internal state for the in-memory store.
 */
typedef struct {
    OpenDBSC_Session *sessions; /**< Dynamic array of stored sessions. */
    size_t count;               /**< Number of sessions currently stored. */
    size_t capacity;            /**< Allocated capacity of @c sessions. */
    pthread_mutex_t mutex;      /**< Protects all access to the array. */
    OpenDBSC_Store *store;      /**< Owning store, freed on destroy. */
} OpenDBSC_MemoryStore;

/**
 * @brief Cast an opaque implementation pointer to the memory store type.
 */
static OpenDBSC_MemoryStore *memory_store_cast(void *impl) {
    return (OpenDBSC_MemoryStore *)impl;
}

/**
 * @brief Check whether @p session has expired.
 *
 * A session is considered expired when its expiration time is in the past
 * relative to the current wall-clock time.
 *
 * @param session Session to inspect.
 *
 * @return true if the session has a valid expiration and has expired.
 */
static bool memory_store_is_expired(const OpenDBSC_Session *session) {
    if (session == NULL || !session->has_expires) {
        return false;
    }
    time_t now = time(NULL);
    return difftime(now, session->expires_at) > 0.0;
}

/**
 * @brief Ensure the dynamic array has room for at least one more session.
 *
 * Must be called while holding the store mutex.
 *
 * @param ms Memory store.
 *
 * @return 0 on success, or -1 if reallocation failed.
 */
static int memory_store_grow(OpenDBSC_MemoryStore *ms) {
    if (ms->count < ms->capacity) {
        return 0;
    }

    size_t new_capacity = ms->capacity == 0
                              ? OPENDBSC_MEMORY_STORE_INITIAL_CAPACITY
                              : ms->capacity * 2;
    OpenDBSC_Session *new_sessions =
        realloc(ms->sessions, new_capacity * sizeof(OpenDBSC_Session));
    if (new_sessions == NULL) {
        return -1;
    }

    ms->sessions = new_sessions;
    ms->capacity = new_capacity;
    return 0;
}

/**
 * @brief Find the index of a session by identifier.
 *
 * Must be called while holding the store mutex.
 *
 * @param ms Memory store.
 * @param id Session identifier to search for.
 *
 * @return The index of the session, or -1 if not found.
 */
static int memory_store_find(const OpenDBSC_MemoryStore *ms, const char *id) {
    if (id == NULL) {
        return -1;
    }
    for (size_t i = 0; i < ms->count; ++i) {
        if (ms->sessions[i].id != NULL && strcmp(ms->sessions[i].id, id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * @brief Remove the session at a given index.
 *
 * Must be called while holding the store mutex.
 *
 * @param ms Memory store.
 * @param idx Index of the session to remove.
 */
static void memory_store_remove_at(OpenDBSC_MemoryStore *ms, size_t idx) {
    opendbsc_session_free(&ms->sessions[idx]);
    if (idx != ms->count - 1) {
        ms->sessions[idx] = ms->sessions[ms->count - 1];
    }
    ms->count--;
}

/**
 * @brief Remove all expired sessions from the store.
 *
 * Must be called while holding the store mutex.
 *
 * @param ms Memory store.
 */
static void memory_store_expire(OpenDBSC_MemoryStore *ms) {
    size_t i = 0;
    while (i < ms->count) {
        if (memory_store_is_expired(&ms->sessions[i])) {
            memory_store_remove_at(ms, i);
        } else {
            ++i;
        }
    }
}

/**
 * @brief Create a new session in the store.
 *
 * If a session with the same identifier already exists, it is replaced.
 */
static int opendbsc_memory_store_create_impl(void *impl,
                                             const OpenDBSC_Session *session) {
    if (session == NULL || session->id == NULL) {
        return -1;
    }

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    int idx = memory_store_find(ms, session->id);
    if (idx >= 0) {
        opendbsc_session_free(&ms->sessions[(size_t)idx]);
        if (opendbsc_session_copy(&ms->sessions[(size_t)idx], session) != 0) {
            opendbsc_session_free(&ms->sessions[(size_t)idx]);
            opendbsc_session_init(&ms->sessions[(size_t)idx]);
            pthread_mutex_unlock(&ms->mutex);
            return -1;
        }
        pthread_mutex_unlock(&ms->mutex);
        return 0;
    }

    if (memory_store_grow(ms) != 0) {
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    opendbsc_session_init(&ms->sessions[ms->count]);
    if (opendbsc_session_copy(&ms->sessions[ms->count], session) != 0) {
        opendbsc_session_free(&ms->sessions[ms->count]);
        opendbsc_session_init(&ms->sessions[ms->count]);
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }
    ms->count++;

    pthread_mutex_unlock(&ms->mutex);
    return 0;
}

/**
 * @brief Retrieve a deep copy of a session by identifier.
 */
static int opendbsc_memory_store_get_impl(void *impl, const char *id,
                                          OpenDBSC_Session **out) {
    if (out == NULL) {
        return -1;
    }
    *out = NULL;
    if (id == NULL) {
        return -1;
    }

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    int idx = memory_store_find(ms, id);
    if (idx < 0) {
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    OpenDBSC_Session *stored = &ms->sessions[(size_t)idx];
    if (memory_store_is_expired(stored)) {
        memory_store_remove_at(ms, (size_t)idx);
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    OpenDBSC_Session *copy = malloc(sizeof(OpenDBSC_Session));
    if (copy == NULL) {
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }
    opendbsc_session_init(copy);
    if (opendbsc_session_copy(copy, stored) != 0) {
        free(copy);
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    pthread_mutex_unlock(&ms->mutex);
    *out = copy;
    return 0;
}

/**
 * @brief Replace an existing session in the store.
 */
static int opendbsc_memory_store_update_impl(void *impl,
                                             const OpenDBSC_Session *session) {
    if (session == NULL || session->id == NULL) {
        return -1;
    }

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    int idx = memory_store_find(ms, session->id);
    if (idx < 0) {
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    opendbsc_session_free(&ms->sessions[(size_t)idx]);
    if (opendbsc_session_copy(&ms->sessions[(size_t)idx], session) != 0) {
        opendbsc_session_free(&ms->sessions[(size_t)idx]);
        opendbsc_session_init(&ms->sessions[(size_t)idx]);
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    pthread_mutex_unlock(&ms->mutex);
    return 0;
}

/**
 * @brief Remove a session by identifier.
 */
static int opendbsc_memory_store_delete_impl(void *impl, const char *id) {
    if (id == NULL) {
        return 0;
    }

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    int idx = memory_store_find(ms, id);
    if (idx >= 0) {
        memory_store_remove_at(ms, (size_t)idx);
    }

    pthread_mutex_unlock(&ms->mutex);
    return 0;
}

/**
 * @brief Retrieve deep copies of all non-expired sessions for a user.
 */
static int opendbsc_memory_store_get_by_user_id_impl(void *impl,
                                                     const char *user_id,
                                                     OpenDBSC_Session **out,
                                                     size_t *count) {
    if (out == NULL || count == NULL || user_id == NULL) {
        return -1;
    }
    *out = NULL;
    *count = 0;

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    memory_store_expire(ms);

    size_t match_count = 0;
    for (size_t i = 0; i < ms->count; ++i) {
        if (ms->sessions[i].user_id != NULL &&
            strcmp(ms->sessions[i].user_id, user_id) == 0) {
            ++match_count;
        }
    }

    if (match_count == 0) {
        pthread_mutex_unlock(&ms->mutex);
        return 0;
    }

    OpenDBSC_Session *matches = malloc(match_count * sizeof(OpenDBSC_Session));
    if (matches == NULL) {
        pthread_mutex_unlock(&ms->mutex);
        return -1;
    }

    size_t written = 0;
    for (size_t i = 0; i < ms->count; ++i) {
        if (ms->sessions[i].user_id != NULL &&
            strcmp(ms->sessions[i].user_id, user_id) == 0) {
            opendbsc_session_init(&matches[written]);
            if (opendbsc_session_copy(&matches[written], &ms->sessions[i]) !=
                0) {
                opendbsc_session_free(&matches[written]);
                for (size_t j = 0; j < written; ++j) {
                    opendbsc_session_free(&matches[j]);
                }
                free(matches);
                pthread_mutex_unlock(&ms->mutex);
                return -1;
            }
            ++written;
        }
    }

    pthread_mutex_unlock(&ms->mutex);
    *out = matches;
    *count = match_count;
    return 0;
}

/**
 * @brief Remove all sessions belonging to a user.
 */
static int opendbsc_memory_store_delete_by_user_id_impl(void *impl,
                                                       const char *user_id) {
    if (user_id == NULL) {
        return 0;
    }

    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    pthread_mutex_lock(&ms->mutex);

    size_t i = 0;
    while (i < ms->count) {
        if (ms->sessions[i].user_id != NULL &&
            strcmp(ms->sessions[i].user_id, user_id) == 0) {
            memory_store_remove_at(ms, i);
        } else {
            ++i;
        }
    }

    pthread_mutex_unlock(&ms->mutex);
    return 0;
}

/**
 * @brief Free sessions returned by @c get or @c get_by_user_id.
 */
static void opendbsc_memory_store_free_sessions_impl(void *impl,
                                                     OpenDBSC_Session *sessions,
                                                     size_t count) {
    (void)impl;
    if (sessions == NULL) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        opendbsc_session_free(&sessions[i]);
    }
    free(sessions);
}

/**
 * @brief Destroy the memory store and its owning @c OpenDBSC_Store.
 */
static void opendbsc_memory_store_destroy_impl(void *impl) {
    OpenDBSC_MemoryStore *ms = memory_store_cast(impl);
    if (ms == NULL) {
        return;
    }

    pthread_mutex_lock(&ms->mutex);
    for (size_t i = 0; i < ms->count; ++i) {
        opendbsc_session_free(&ms->sessions[i]);
    }
    free(ms->sessions);
    ms->sessions = NULL;
    ms->count = 0;
    ms->capacity = 0;
    pthread_mutex_unlock(&ms->mutex);

    pthread_mutex_destroy(&ms->mutex);

    OpenDBSC_Store *store = ms->store;
    free(ms);
    free(store);
}

OpenDBSC_Store *opendbsc_memory_store_create(void) {
    OpenDBSC_MemoryStore *ms = malloc(sizeof(OpenDBSC_MemoryStore));
    if (ms == NULL) {
        return NULL;
    }

    ms->sessions = NULL;
    ms->count = 0;
    ms->capacity = 0;
    ms->store = NULL;

    if (pthread_mutex_init(&ms->mutex, NULL) != 0) {
        free(ms);
        return NULL;
    }

    OpenDBSC_Store *store = malloc(sizeof(OpenDBSC_Store));
    if (store == NULL) {
        pthread_mutex_destroy(&ms->mutex);
        free(ms);
        return NULL;
    }

    store->impl = ms;
    store->create = opendbsc_memory_store_create_impl;
    store->get = opendbsc_memory_store_get_impl;
    store->update = opendbsc_memory_store_update_impl;
    store->delete = opendbsc_memory_store_delete_impl;
    store->get_by_user_id = opendbsc_memory_store_get_by_user_id_impl;
    store->delete_by_user_id = opendbsc_memory_store_delete_by_user_id_impl;
    store->free_sessions = opendbsc_memory_store_free_sessions_impl;
    store->destroy = opendbsc_memory_store_destroy_impl;

    ms->store = store;
    return store;
}
