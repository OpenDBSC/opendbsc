#ifndef OPENDBSC_SESSION_H
#define OPENDBSC_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file session/session.h
 * @brief Session and context types for OpenDBSC.
 */

/**
 * @brief Possible states of an OpenDBSC session.
 */
typedef enum {
    OPENDBSC_SESSION_STATE_ACTIVE, /**< Session is active but not yet bound. */
    OPENDBSC_SESSION_STATE_BOUND   /**< Session has been bound to a credential. */
} OpenDBSC_SessionState;

/**
 * @brief Session state strings used for persistence and wire formats.
 */
#define OPENDBSC_STATE_ACTIVE_STR "active"
#define OPENDBSC_STATE_BOUND_STR  "bound"

/**
 * @brief Represents an OpenDBSC session.
 *
 * All dynamically allocated string fields are owned by the session and
 * must be managed through the provided setter and free functions.
 */
typedef struct {
    char *id;                   /**< Unique session identifier (UUIDv7). */
    char *user_id;              /**< Identifier of the associated user. */
    OpenDBSC_SessionState state; /**< Current state of the session. */
    char *public_key;           /**< Public key associated with the session (JWK JSON). */
    char *algorithm;            /**< Signature algorithm name. */
    char *challenge;            /**< Challenge data used during binding. */
    time_t expires_at;          /**< Expiration timestamp; valid only when has_expires is true. */
    bool has_expires;           /**< Whether expires_at carries a valid value. */
    time_t created_at;          /**< Creation timestamp. */
} OpenDBSC_Session;

/**
 * @brief Initialize a session object to its default state.
 *
 * @param session Pointer to the session to initialize. May be @c NULL.
 */
void opendbsc_session_init(OpenDBSC_Session *session);

/**
 * @brief Release all resources owned by a session and reset it.
 *
 * @param session Pointer to the session to free. May be @c NULL.
 */
void opendbsc_session_free(OpenDBSC_Session *session);

/**
 * @brief Set the session identifier.
 *
 * @param session Pointer to the session.
 * @param id Null-terminated session identifier string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_id(OpenDBSC_Session *session, const char *id);

/**
 * @brief Set the user identifier associated with the session.
 *
 * @param session Pointer to the session.
 * @param user_id Null-terminated user identifier string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_user_id(OpenDBSC_Session *session, const char *user_id);

/**
 * @brief Set the public key stored in the session.
 *
 * @param session Pointer to the session.
 * @param public_key Null-terminated public key string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_public_key(OpenDBSC_Session *session, const char *public_key);

/**
 * @brief Set the signature algorithm name stored in the session.
 *
 * @param session Pointer to the session.
 * @param algorithm Null-terminated algorithm name, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_algorithm(OpenDBSC_Session *session, const char *algorithm);

/**
 * @brief Set the challenge string stored in the session.
 *
 * @param session Pointer to the session.
 * @param challenge Null-terminated challenge string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_challenge(OpenDBSC_Session *session, const char *challenge);

/**
 * @brief Set the session state.
 *
 * @param session Pointer to the session.
 * @param state State to assign.
 */
void opendbsc_session_set_state(OpenDBSC_Session *session, OpenDBSC_SessionState state);

/**
 * @brief Set the session state from a string.
 *
 * Recognizes "active" and "bound" (case-sensitive).
 *
 * @param session Pointer to the session.
 * @param state Null-terminated state string.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or the string is unknown.
 */
int opendbsc_session_set_state_str(OpenDBSC_Session *session, const char *state);

/**
 * @brief Get the session state as a string.
 *
 * @param session Pointer to the session.
 *
 * @return "active", "bound", or @c NULL if @p session is @c NULL.
 */
const char *opendbsc_session_state_str(const OpenDBSC_Session *session);

/**
 * @brief Determine whether the session is in the bound state.
 *
 * @param session Pointer to the session to inspect.
 *
 * @return true if @p session is non-@c NULL and its state is
 *         @c OPENDBSC_SESSION_STATE_BOUND, false otherwise.
 */
bool opendbsc_session_is_bound(const OpenDBSC_Session *session);

/**
 * @brief Set the expiration time of the session.
 *
 * @param session Pointer to the session.
 * @param expires_at Expiration timestamp, or 0 to clear expiration.
 */
void opendbsc_session_set_expires_at(OpenDBSC_Session *session, time_t expires_at);

/**
 * @brief Set the creation time of the session.
 *
 * @param session Pointer to the session.
 * @param created_at Creation timestamp.
 */
void opendbsc_session_set_created_at(OpenDBSC_Session *session, time_t created_at);

/**
 * @brief Copy a session object.
 *
 * All dynamically allocated string fields are duplicated. The caller must
 * call opendbsc_session_free() on @p dest when done.
 *
 * @param dest Pointer to the destination session.
 * @param src Pointer to the source session.
 *
 * @return 0 on success, or -1 if @p dest or @p src is @c NULL or allocation failed.
 */
int opendbsc_session_copy(OpenDBSC_Session *dest, const OpenDBSC_Session *src);

/**
 * @brief Generate a new UUIDv7 session identifier.
 *
 * @param out Buffer that receives the generated identifier.
 * @param out_size Size of @p out in bytes. Must be at least 37.
 *
 * @return 0 on success, or -1 if the arguments are invalid or
 *         identifier generation failed.
 */
int opendbsc_session_new_id(char *out, size_t out_size);

/**
 * @brief Request context passed during OpenDBSC operations.
 */
typedef struct {
    const char *session_id; /**< Session identifier associated with the request. */
} OpenDBSC_Context;

/**
 * @brief Initialize a context object to its default state.
 *
 * @param ctx Pointer to the context to initialize. May be @c NULL.
 */
void opendbsc_context_init(OpenDBSC_Context *ctx);

/**
 * @brief Associate a session identifier with a context.
 *
 * The context stores a pointer to @p session_id; it does not copy the
 * string. The caller must ensure the string remains valid for the
 * lifetime of the context.
 *
 * @param ctx Pointer to the context. May be @c NULL.
 * @param session_id Session identifier string to associate.
 */
void opendbsc_context_set_session_id(OpenDBSC_Context *ctx, const char *session_id);

/**
 * @brief Retrieve the session identifier from a context.
 *
 * @param ctx Pointer to the context.
 * @param session_id Output pointer that receives the session identifier
 *                   string on success. May be @c NULL.
 *
 * @return true if @p ctx is non-@c NULL, @p session_id is non-@c NULL,
 *         and a session identifier has been set, false otherwise.
 */
bool opendbsc_context_get_session_id(const OpenDBSC_Context *ctx, const char **session_id);

#ifdef __cplusplus
}
#endif

#endif
