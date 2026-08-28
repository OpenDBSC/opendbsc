#ifndef OPENDBSC_MANAGER_H
#define OPENDBSC_MANAGER_H

#include "session/session.h"
#include "store/store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file manager/manager.h
 * @brief High-level DBSC manager for OpenDBSC.
 */

/**
 * @brief Configuration for the DBSC manager.
 */
typedef struct {
    OpenDBSC_Store *store;       /**< Session store backend. */
    const char *cookie_name;     /**< Cookie name. Defaults to "session_id". */
    const char *cookie_path;     /**< Cookie path. Defaults to "/". */
    const char *cookie_domain;   /**< Optional cookie domain. */
    int secure;                  /**< Whether the cookie requires HTTPS. */
    const char *same_site;       /**< "Lax", "Strict", or "None". Defaults to "Lax". */
    int cookie_ttl_seconds;      /**< Browser cookie TTL in seconds. Defaults to 3600. */
    int session_ttl_seconds;     /**< Backend session TTL; 0 means infinite. */

    /**
     * @brief Optional authorization value echoed to the client.
     *
     * When set, it is included in the Secure-Session-Registration header
     * during initiate and verified against the proof JWT's authorization
     * claim during register (spec 9.10). @c NULL disables the feature.
     */
    const char *authorization;

    /**
     * @brief Optional lifecycle event callback.
     *
     * @param type Event type ("LOGIN", "REGISTER", "REFRESH", "LOGIN_FAIL", ...).
     * @param user User identifier.
     * @param session_id Session identifier.
     * @param detail Human-readable detail string.
     * @param userdata User data pointer from @c on_event_userdata.
     */
    void (*on_event)(const char *type, const char *user, const char *session_id,
                     const char *detail, void *userdata);
    void *on_event_userdata;     /**< User data passed to @c on_event. */
} OpenDBSC_ManagerConfig;

/**
 * @brief Response produced by the DBSC manager.
 *
 * The HTTP wrapper translates these fields into HTTP status code, headers,
 * and response body. All string fields are heap-owned and must be freed by
 * the caller.
 */
typedef struct {
    int status_code;          /**< HTTP status code. */
    char *set_cookie;         /**< Full Set-Cookie header value, or @c NULL. */
    char *registration_header; /**< Secure-Session-Registration value, or @c NULL. */
    char *challenge_header;   /**< Secure-Session-Challenge value, or @c NULL. */
    char *body;               /**< JSON response body, or @c NULL. */
} OpenDBSC_ManagerResponse;

/**
 * @brief DBSC manager state.
 */
typedef struct {
    OpenDBSC_ManagerConfig cfg; /**< Manager configuration (copied). */
} OpenDBSC_Manager;

/**
 * @brief Initialize a manager response to its default state.
 *
 * @param resp Pointer to the response. May be @c NULL.
 */
void opendbsc_manager_response_init(OpenDBSC_ManagerResponse *resp);

/**
 * @brief Release all resources owned by a manager response.
 *
 * @param resp Pointer to the response. May be @c NULL.
 */
void opendbsc_manager_response_free(OpenDBSC_ManagerResponse *resp);

/**
 * @brief Initialize a DBSC manager.
 *
 * The configuration is copied into the manager. Default values are applied
 * for fields that are NULL or zero.
 *
 * @param mgr Pointer to the manager to initialize.
 * @param cfg Pointer to the configuration.
 *
 * @return 0 on success, or -1 if @p mgr or @p cfg is @c NULL or the store
 *         is missing.
 */
int opendbsc_manager_init(OpenDBSC_Manager *mgr, const OpenDBSC_ManagerConfig *cfg);

/**
 * @brief Release any resources owned by a manager.
 *
 * @param mgr Pointer to the manager. May be @c NULL.
 */
void opendbsc_manager_destroy(OpenDBSC_Manager *mgr);

/**
 * @brief Initiate a new DBSC session after successful user login.
 *
 * Creates a session, persists it, and produces the initial registration
 * header and session cookie.
 *
 * @param mgr Pointer to the manager.
 * @param user_id User identifier.
 * @param out_session Optional output session (deep copy). May be @c NULL.
 * @param resp Pointer to the response structure that receives headers/body.
 *
 * @return 0 on success, or -1 if allocation or store creation failed.
 */
int opendbsc_manager_initiate(OpenDBSC_Manager *mgr, const char *user_id,
                              OpenDBSC_Session *out_session,
                              OpenDBSC_ManagerResponse *resp);

/**
 * @brief Handle a DBSC registration request.
 *
 * @param mgr Pointer to the manager.
 * @param cookie_session_id Session ID from the session cookie, or @c NULL.
 * @param session_response_header Value of the Secure-Session-Response header,
 *                                or @c NULL.
 * @param resp Pointer to the response structure.
 *
 * @return 0 if a response was produced (check @p resp->status_code),
 *         or -1 on internal error.
 */
int opendbsc_manager_register(OpenDBSC_Manager *mgr,
                              const char *cookie_session_id,
                              const char *session_response_header,
                              OpenDBSC_ManagerResponse *resp);

/**
 * @brief Handle a DBSC refresh request.
 *
 * @param mgr Pointer to the manager.
 * @param session_id Session ID from Sec-Secure-Session-Id header or cookie.
 * @param session_response_header Value of the Secure-Session-Response header,
 *                                or @c NULL for the optimistic refresh.
 * @param resp Pointer to the response structure.
 *
 * @return 0 if a response was produced (check @p resp->status_code),
 *         or -1 on internal error.
 */
int opendbsc_manager_refresh(OpenDBSC_Manager *mgr,
                             const char *session_id,
                             const char *session_response_header,
                             OpenDBSC_ManagerResponse *resp);

/**
 * @brief Close a DBSC session (spec 9.6).
 *
 * Removes the session from the store and produces a response with a
 * @c continue:false instruction body and a session cookie expired via
 * @c Max-Age=0. Emits the "CLOSE" lifecycle event.
 *
 * @param mgr Pointer to the manager.
 * @param session_id Identifier of the session to close.
 * @param resp Pointer to the response structure.
 *
 * @return 0 if a response was produced (check @p resp->status_code),
 *         or -1 on internal error.
 */
int opendbsc_manager_close(OpenDBSC_Manager *mgr, const char *session_id,
                           OpenDBSC_ManagerResponse *resp);

/**
 * @brief Retrieve a session by cookie value.
 *
 * @param mgr Pointer to the manager.
 * @param cookie_session_id Session ID from the session cookie.
 * @param out Pointer that receives a deep copy of the session. The caller
 *            must release it with the store's @c free_sessions method.
 *
 * @return 0 on success, or -1 if the session was not found or expired.
 */
int opendbsc_manager_get_session(OpenDBSC_Manager *mgr,
                                 const char *cookie_session_id,
                                 OpenDBSC_Session **out);

/**
 * @brief Generate a random 32-byte hex challenge.
 *
 * @return Newly allocated challenge string, or @c NULL on error.
 */
char *opendbsc_manager_generate_challenge(void);

#ifdef __cplusplus
}
#endif

#endif
