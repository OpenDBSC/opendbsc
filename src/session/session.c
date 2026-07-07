#include "session/session.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "uuidv7.h"

/**
 * @brief Initialize a session object to its default state.
 *
 * All pointer fields are set to @c NULL, the state is set to
 * @c OPENDBSC_SESSION_STATE_ACTIVE, the expiry flag is cleared, and
 * timestamps are zeroed.
 *
 * @param session Pointer to the session to initialize. May be @c NULL,
 *                in which case the function does nothing.
 */
void opendbsc_session_init(OpenDBSC_Session *session) {
    if (session == NULL) {
        return;
    }
    session->id = NULL;
    session->user_id = NULL;
    session->state = OPENDBSC_SESSION_STATE_ACTIVE;
    session->public_key = NULL;
    session->algorithm = NULL;
    session->challenge = NULL;
    session->expires_at = 0;
    session->has_expires = false;
    session->created_at = 0;
}

/**
 * @brief Release all resources owned by a session and reset it.
 *
 * The dynamically allocated string fields are freed and the session
 * is re-initialized to its default state by calling
 * opendbsc_session_init().
 *
 * @param session Pointer to the session to free. May be @c NULL,
 *                in which case the function does nothing.
 */
void opendbsc_session_free(OpenDBSC_Session *session) {
    if (session == NULL) {
        return;
    }
    free(session->id);
    free(session->user_id);
    free(session->public_key);
    free(session->algorithm);
    free(session->challenge);
    opendbsc_session_init(session);
}

/**
 * @brief Duplicate a string into a session field.
 *
 * Frees any previously stored value, then stores a copy of @p value.
 * If @p value is @c NULL, the field is cleared instead.
 *
 * @param field Pointer to the string field that receives the copy.
 * @param value Null-terminated string to copy, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if memory allocation failed.
 */
static int set_string(char **field, const char *value) {
    if (value == NULL) {
        free(*field);
        *field = NULL;
        return 0;
    }
    char *copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }
    free(*field);
    *field = copy;
    return 0;
}

/**
 * @brief Set the session identifier.
 *
 * @param session Pointer to the session.
 * @param id Null-terminated session identifier string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_id(OpenDBSC_Session *session, const char *id) {
    if (session == NULL) {
        return -1;
    }
    return set_string(&session->id, id);
}

/**
 * @brief Set the user identifier associated with the session.
 *
 * @param session Pointer to the session.
 * @param user_id Null-terminated user identifier string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_user_id(OpenDBSC_Session *session, const char *user_id) {
    if (session == NULL) {
        return -1;
    }
    return set_string(&session->user_id, user_id);
}

/**
 * @brief Set the public key stored in the session.
 *
 * @param session Pointer to the session.
 * @param public_key Null-terminated public key string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_public_key(OpenDBSC_Session *session, const char *public_key) {
    if (session == NULL) {
        return -1;
    }
    return set_string(&session->public_key, public_key);
}

/**
 * @brief Set the signature algorithm name stored in the session.
 *
 * @param session Pointer to the session.
 * @param algorithm Null-terminated algorithm name, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_algorithm(OpenDBSC_Session *session, const char *algorithm) {
    if (session == NULL) {
        return -1;
    }
    return set_string(&session->algorithm, algorithm);
}

/**
 * @brief Set the challenge string stored in the session.
 *
 * @param session Pointer to the session.
 * @param challenge Null-terminated challenge string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or allocation failed.
 */
int opendbsc_session_set_challenge(OpenDBSC_Session *session, const char *challenge) {
    if (session == NULL) {
        return -1;
    }
    return set_string(&session->challenge, challenge);
}

/**
 * @brief Set the session state.
 *
 * @param session Pointer to the session.
 * @param state State to assign.
 */
void opendbsc_session_set_state(OpenDBSC_Session *session, OpenDBSC_SessionState state) {
    if (session == NULL) {
        return;
    }
    session->state = state;
}

/**
 * @brief Set the session state from a string.
 *
 * @param session Pointer to the session.
 * @param state Null-terminated state string.
 *
 * @return 0 on success, or -1 if @p session is @c NULL or the string is unknown.
 */
int opendbsc_session_set_state_str(OpenDBSC_Session *session, const char *state) {
    if (session == NULL || state == NULL) {
        return -1;
    }
    if (strcmp(state, OPENDBSC_STATE_ACTIVE_STR) == 0) {
        session->state = OPENDBSC_SESSION_STATE_ACTIVE;
        return 0;
    }
    if (strcmp(state, OPENDBSC_STATE_BOUND_STR) == 0) {
        session->state = OPENDBSC_SESSION_STATE_BOUND;
        return 0;
    }
    return -1;
}

/**
 * @brief Get the session state as a string.
 *
 * @param session Pointer to the session.
 *
 * @return "active", "bound", or @c NULL if @p session is @c NULL.
 */
const char *opendbsc_session_state_str(const OpenDBSC_Session *session) {
    if (session == NULL) {
        return NULL;
    }
    switch (session->state) {
        case OPENDBSC_SESSION_STATE_BOUND:
            return OPENDBSC_STATE_BOUND_STR;
        case OPENDBSC_SESSION_STATE_ACTIVE:
        default:
            return OPENDBSC_STATE_ACTIVE_STR;
    }
}

/**
 * @brief Determine whether the session is in the bound state.
 *
 * @param session Pointer to the session to inspect.
 *
 * @return true if @p session is non-@c NULL and its state is
 *         @c OPENDBSC_SESSION_STATE_BOUND, false otherwise.
 */
bool opendbsc_session_is_bound(const OpenDBSC_Session *session) {
    if (session == NULL) {
        return false;
    }
    return session->state == OPENDBSC_SESSION_STATE_BOUND;
}

/**
 * @brief Set the expiration time of the session.
 *
 * @param session Pointer to the session.
 * @param expires_at Expiration timestamp, or 0 to clear expiration.
 */
void opendbsc_session_set_expires_at(OpenDBSC_Session *session, time_t expires_at) {
    if (session == NULL) {
        return;
    }
    session->expires_at = expires_at;
    session->has_expires = expires_at != 0;
}

/**
 * @brief Set the creation time of the session.
 *
 * @param session Pointer to the session.
 * @param created_at Creation timestamp.
 */
void opendbsc_session_set_created_at(OpenDBSC_Session *session, time_t created_at) {
    if (session == NULL) {
        return;
    }
    session->created_at = created_at;
}

/**
 * @brief Copy a session object.
 *
 * @param dest Pointer to the destination session.
 * @param src Pointer to the source session.
 *
 * @return 0 on success, or -1 if @p dest or @p src is @c NULL or allocation failed.
 */
int opendbsc_session_copy(OpenDBSC_Session *dest, const OpenDBSC_Session *src) {
    if (dest == NULL || src == NULL) {
        return -1;
    }
    opendbsc_session_free(dest);
    dest->state = src->state;
    dest->expires_at = src->expires_at;
    dest->has_expires = src->has_expires;
    dest->created_at = src->created_at;
    if (set_string(&dest->id, src->id) != 0) return -1;
    if (set_string(&dest->user_id, src->user_id) != 0) return -1;
    if (set_string(&dest->public_key, src->public_key) != 0) return -1;
    if (set_string(&dest->algorithm, src->algorithm) != 0) return -1;
    if (set_string(&dest->challenge, src->challenge) != 0) return -1;
    return 0;
}

/**
 * @brief Generate a new UUIDv7 session identifier.
 *
 * The identifier is written as a 36-character canonical string plus a
 * terminating null byte (37 bytes total).
 *
 * @param out Buffer that receives the generated identifier.
 * @param out_size Size of @p out in bytes. Must be at least 37.
 *
 * @return 0 on success, or -1 if the arguments are invalid or the
 *         underlying entropy/timestamp generation failed.
 */
int opendbsc_session_new_id(char *out, size_t out_size) {
    if (out == NULL || out_size < 37) {
        return -1;
    }

    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
        return -1;
    }
    uint64_t unix_ts_ms = (uint64_t)tp.tv_sec * 1000 + (uint64_t)tp.tv_nsec / 1000000;

    uint8_t rand_bytes[10];
    if (getentropy(rand_bytes, sizeof(rand_bytes)) != 0) {
        return -1;
    }

    uint8_t uuid[16];
    int8_t status = uuidv7_generate(uuid, unix_ts_ms, rand_bytes, NULL);
    if (status < 0) {
        return -1;
    }

    uuidv7_to_string(uuid, out);
    return 0;
}

/**
 * @brief Initialize a context object to its default state.
 *
 * @param ctx Pointer to the context to initialize. May be @c NULL,
 *            in which case the function does nothing.
 */
void opendbsc_context_init(OpenDBSC_Context *ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->session_id = NULL;
}

/**
 * @brief Associate a session identifier with a context.
 *
 * The context stores a pointer to @p session_id; it does not copy the
 * string. The caller must ensure the string remains valid for the
 * lifetime of the context.
 *
 * @param ctx Pointer to the context. May be @c NULL, in which case
 *            the function does nothing.
 * @param session_id Session identifier string to associate.
 */
void opendbsc_context_set_session_id(OpenDBSC_Context *ctx, const char *session_id) {
    if (ctx == NULL) {
        return;
    }
    ctx->session_id = session_id;
}

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
bool opendbsc_context_get_session_id(const OpenDBSC_Context *ctx, const char **session_id) {
    if (ctx == NULL || session_id == NULL) {
        return false;
    }
    *session_id = ctx->session_id;
    return ctx->session_id != NULL;
}
