#ifndef OPENDBSC_STORE_H
#define OPENDBSC_STORE_H

#include <stddef.h>

#include "session/session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file store/store.h
 * @brief Generic session store interface for OpenDBSC.
 */

/**
 * @brief Generic session store.
 *
 * The store is a virtual table of operations backed by an implementation-
 * specific object accessed through @c impl. All operations are thread-safe
 * when implemented correctly by the backend.
 */
typedef struct {
    void *impl; /**< Opaque pointer to the backend implementation. */

    /**
     * @brief Persist a new session in the store.
     *
     * The store receives a deep copy of @p session; the caller retains
     * ownership of the passed-in object.
     *
     * @param impl Opaque implementation pointer.
     * @param session Session to persist. Must have a valid @c id.
     *
     * @return 0 on success, or -1 if @p session is invalid or allocation
     *         failed.
     */
    int (*create)(void *impl, const OpenDBSC_Session *session);

    /**
     * @brief Retrieve a deep copy of a session by its identifier.
     *
     * The returned session is allocated by the store and must be released
     * by calling @c free_sessions with a count of 1.
     *
     * @param impl Opaque implementation pointer.
     * @param id Session identifier to look up.
     * @param out Pointer that receives the copied session on success.
     *            Set to @c NULL when the session is not found or expired.
     *
     * @return 0 on success, or -1 if the session was not found, expired,
     *         or allocation failed.
     */
    int (*get)(void *impl, const char *id, OpenDBSC_Session **out);

    /**
     * @brief Replace an existing session in the store.
     *
     * The store receives a deep copy of @p session.
     *
     * @param impl Opaque implementation pointer.
     * @param session Session with updated values. Must have a valid @c id.
     *
     * @return 0 on success, or -1 if the session was not found or allocation
     *         failed.
     */
    int (*update)(void *impl, const OpenDBSC_Session *session);

    /**
     * @brief Remove a session by its identifier.
     *
     * Deleting a non-existent session is a no-op.
     *
     * @param impl Opaque implementation pointer.
     * @param id Session identifier to remove.
     *
     * @return 0 on success (including when the session did not exist).
     */
    int (*delete)(void *impl, const char *id);

    /**
     * @brief Retrieve deep copies of all non-expired sessions for a user.
     *
     * The returned array is allocated by the store and must be released by
     * calling @c free_sessions with @p count.
     *
     * @param impl Opaque implementation pointer.
     * @param user_id User identifier to look up.
     * @param out Pointer that receives the array of copied sessions on
     *            success. Set to @c NULL when no sessions match.
     * @param count Pointer that receives the number of sessions in @p out.
     *
     * @return 0 on success (including when no sessions match), or -1 if
     *         allocation failed.
     */
    int (*get_by_user_id)(void *impl, const char *user_id,
                          OpenDBSC_Session **out, size_t *count);

    /**
     * @brief Remove all sessions belonging to a user.
     *
     * @param impl Opaque implementation pointer.
     * @param user_id User identifier whose sessions should be removed.
     *
     * @return 0 on success.
     */
    int (*delete_by_user_id)(void *impl, const char *user_id);

    /**
     * @brief Release sessions returned by @c get or @c get_by_user_id.
     *
     * @param impl Opaque implementation pointer.
     * @param sessions Array of sessions returned by the store, or @c NULL.
     * @param count Number of sessions in @p sessions.
     */
    void (*free_sessions)(void *impl, OpenDBSC_Session *sessions, size_t count);

    /**
     * @brief Destroy the store implementation and the store object itself.
     *
     * After this call, @p store and its implementation pointer are invalid
     * and must not be used again.
     *
     * @param impl Opaque implementation pointer.
     */
    void (*destroy)(void *impl);
} OpenDBSC_Store;

#ifdef __cplusplus
}
#endif

#endif
