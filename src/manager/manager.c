#include "manager/manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "protocol/header.h"
#include "protocol/instruction.h"
#include "protocol/jwt.h"

/**
 * @file manager/manager.c
 * @brief DBSC manager implementation.
 */

/**
 * @brief Default manager configuration values.
 */
#define OPENDBSC_DEFAULT_COOKIE_NAME "session_id"
#define OPENDBSC_DEFAULT_COOKIE_PATH "/"
#define OPENDBSC_DEFAULT_SAME_SITE "Lax"
#define OPENDBSC_DEFAULT_COOKIE_TTL 3600

/**
 * @brief Initialize a manager response.
 */
void opendbsc_manager_response_init(OpenDBSC_ManagerResponse *resp) {
    if (resp == NULL) {
        return;
    }
    resp->status_code = 0;
    resp->set_cookie = NULL;
    resp->registration_header = NULL;
    resp->challenge_header = NULL;
    resp->body = NULL;
}

/**
 * @brief Free a manager response.
 */
void opendbsc_manager_response_free(OpenDBSC_ManagerResponse *resp) {
    if (resp == NULL) {
        return;
    }
    free(resp->set_cookie);
    free(resp->registration_header);
    free(resp->challenge_header);
    free(resp->body);
    opendbsc_manager_response_init(resp);
}

/**
 * @brief Emit a lifecycle event if a callback is configured.
 */
static void emit_event(const OpenDBSC_Manager *mgr, const char *type,
                       const char *user, const char *session_id,
                       const char *detail) {
    if (mgr->cfg.on_event != NULL) {
        mgr->cfg.on_event(type, user, session_id, detail, mgr->cfg.on_event_userdata);
    }
}

/**
 * @brief Generate a random 32-byte hex challenge.
 */
char *opendbsc_manager_generate_challenge(void) {
    unsigned char bytes[32];
    if (getentropy(bytes, sizeof(bytes)) != 0) {
        return strdup("fallback-challenge");
    }

    char *out = malloc(sizeof(bytes) * 2 + 1);
    if (out == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(bytes); i++) {
        sprintf(out + i * 2, "%02x", bytes[i]);
    }
    out[sizeof(bytes) * 2] = '\0';
    return out;
}

/**
 * @brief Copy a configuration string safely.
 */
static char *copy_string(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    return strdup(s);
}

/**
 * @brief Initialize a DBSC manager.
 */
int opendbsc_manager_init(OpenDBSC_Manager *mgr, const OpenDBSC_ManagerConfig *cfg) {
    if (mgr == NULL || cfg == NULL || cfg->store == NULL) {
        return -1;
    }
    memset(mgr, 0, sizeof(*mgr));
    mgr->cfg.store = cfg->store;
    mgr->cfg.secure = cfg->secure;
    mgr->cfg.cookie_ttl_seconds = cfg->cookie_ttl_seconds;
    mgr->cfg.session_ttl_seconds = cfg->session_ttl_seconds;
    mgr->cfg.on_event = cfg->on_event;
    mgr->cfg.on_event_userdata = cfg->on_event_userdata;

    mgr->cfg.cookie_name = copy_string(cfg->cookie_name != NULL ? cfg->cookie_name
                                                               : OPENDBSC_DEFAULT_COOKIE_NAME);
    mgr->cfg.cookie_path = copy_string(cfg->cookie_path != NULL ? cfg->cookie_path
                                                               : OPENDBSC_DEFAULT_COOKIE_PATH);
    mgr->cfg.cookie_domain = copy_string(cfg->cookie_domain);
    mgr->cfg.same_site = copy_string(cfg->same_site != NULL ? cfg->same_site
                                                            : OPENDBSC_DEFAULT_SAME_SITE);

    if (mgr->cfg.cookie_ttl_seconds == 0) {
        mgr->cfg.cookie_ttl_seconds = OPENDBSC_DEFAULT_COOKIE_TTL;
    }
    return 0;
}

/**
 * @brief Release manager resources.
 */
void opendbsc_manager_destroy(OpenDBSC_Manager *mgr) {
    if (mgr == NULL) {
        return;
    }
    free((char *)mgr->cfg.cookie_name);
    free((char *)mgr->cfg.cookie_path);
    free((char *)mgr->cfg.cookie_domain);
    free((char *)mgr->cfg.same_site);
    memset(mgr, 0, sizeof(*mgr));
}

/**
 * @brief Build a Set-Cookie header value.
 */
static char *build_set_cookie(const OpenDBSC_Manager *mgr, const char *value) {
    const char *name = mgr->cfg.cookie_name;
    const char *path = mgr->cfg.cookie_path;
    const char *domain = mgr->cfg.cookie_domain;
    const char *same_site = mgr->cfg.same_site;
    int max_age = mgr->cfg.cookie_ttl_seconds;

    int n = snprintf(NULL, 0, "%s=%s; Path=%s; Max-Age=%d; HttpOnly%s%s",
                     name, value, path, max_age,
                     mgr->cfg.secure ? "; Secure" : "",
                     (same_site != NULL && same_site[0] != '\0')
                         ? "; SameSite=" : "");
    if (same_site != NULL && same_site[0] != '\0') {
        n += (int)strlen(same_site);
    }
    if (domain != NULL && domain[0] != '\0') {
        n += snprintf(NULL, 0, "; Domain=%s", domain);
    }

    char *cookie = malloc((size_t)n + 1);
    if (cookie == NULL) {
        return NULL;
    }

    char *w = cookie;
    w += sprintf(w, "%s=%s; Path=%s; Max-Age=%d; HttpOnly%s",
                 name, value, path, max_age, mgr->cfg.secure ? "; Secure" : "");
    if (domain != NULL && domain[0] != '\0') {
        w += sprintf(w, "; Domain=%s", domain);
    }
    if (same_site != NULL && same_site[0] != '\0') {
        w += sprintf(w, "; SameSite=%s", same_site);
    }

    return cookie;
}

/**
 * @brief Build the instruction JSON response body.
 */
static char *build_instruction_body(const OpenDBSC_Manager *mgr,
                                    const OpenDBSC_Session *session) {
    OpenDBSC_SessionInstruction inst;
    opendbsc_instruction_init(&inst);

    opendbsc_instruction_set_session_identifier(&inst, session->id);
    opendbsc_instruction_set_refresh_url(&inst, "/dbsc/refresh");
    opendbsc_scope_set_include_site(&inst.scope, 0);

    OpenDBSC_SessionCredential cred;
    opendbsc_credential_init(&cred);
    opendbsc_credential_set_type(&cred, "cookie");
    opendbsc_credential_set_name(&cred, mgr->cfg.cookie_name);

    int n = snprintf(NULL, 0, "Path=%s; Secure; HttpOnly; SameSite=%s",
                     mgr->cfg.cookie_path, mgr->cfg.same_site);
    char *attrs = malloc((size_t)n + 1);
    if (attrs != NULL) {
        sprintf(attrs, "Path=%s; Secure; HttpOnly; SameSite=%s",
                mgr->cfg.cookie_path, mgr->cfg.same_site);
        opendbsc_credential_set_attributes(&cred, attrs);
        free(attrs);
    }

    opendbsc_instruction_add_credential(&inst, &cred);
    opendbsc_credential_free(&cred);

    char *body = opendbsc_instruction_to_string(&inst);
    opendbsc_instruction_free(&inst);
    return body;
}

/**
 * @brief Set session expiration based on the configured session TTL.
 */
static void apply_session_ttl(OpenDBSC_Session *session, int ttl_seconds) {
    if (ttl_seconds > 0) {
        opendbsc_session_set_expires_at(session, time(NULL) + ttl_seconds);
    } else {
        session->expires_at = 0;
        session->has_expires = false;
    }
}

/**
 * @brief Initiate a new DBSC session.
 */
int opendbsc_manager_initiate(OpenDBSC_Manager *mgr, const char *user_id,
                              OpenDBSC_Session *out_session,
                              OpenDBSC_ManagerResponse *resp) {
    if (mgr == NULL || user_id == NULL || resp == NULL) {
        return -1;
    }
    opendbsc_manager_response_init(resp);

    char id[37];
    if (opendbsc_session_new_id(id, sizeof(id)) != 0) {
        return -1;
    }

    OpenDBSC_Session session;
    opendbsc_session_init(&session);
    opendbsc_session_set_id(&session, id);
    opendbsc_session_set_user_id(&session, user_id);
    opendbsc_session_set_state(&session, OPENDBSC_SESSION_STATE_ACTIVE);

    char *challenge = opendbsc_manager_generate_challenge();
    if (challenge == NULL) {
        opendbsc_session_free(&session);
        return -1;
    }
    opendbsc_session_set_challenge(&session, challenge);
    free(challenge);

    opendbsc_session_set_created_at(&session, time(NULL));
    apply_session_ttl(&session, mgr->cfg.session_ttl_seconds);

    if (mgr->cfg.store->create(mgr->cfg.store->impl, &session) != 0) {
        opendbsc_session_free(&session);
        return -1;
    }

    resp->set_cookie = build_set_cookie(mgr, session.id);

    const char *algs[] = {"ES256", "RS256"};
    resp->registration_header = opendbsc_registration_serialize(
        algs, 2, "/dbsc/register", session.challenge, NULL, NULL, NULL, NULL);
    resp->status_code = 200;

    if (out_session != NULL) {
        opendbsc_session_copy(out_session, &session);
    }

    emit_event(mgr, "LOGIN", user_id, session.id, "login successful");
    opendbsc_session_free(&session);
    return 0;
}

/**
 * @brief Retrieve a session by cookie value.
 */
int opendbsc_manager_get_session(OpenDBSC_Manager *mgr,
                                 const char *cookie_session_id,
                                 OpenDBSC_Session **out) {
    if (mgr == NULL || cookie_session_id == NULL || out == NULL) {
        return -1;
    }
    return mgr->cfg.store->get(mgr->cfg.store->impl, cookie_session_id, out);
}

/**
 * @brief Build a 403 challenge response.
 */
static void set_challenge_response(const OpenDBSC_Manager *mgr,
                                   OpenDBSC_ManagerResponse *resp,
                                   const char *challenge,
                                   const char *session_id,
                                   int status) {
    resp->status_code = status;
    resp->challenge_header = opendbsc_challenge_serialize(challenge, session_id);
    resp->body = strdup("\"Secure-Session-Challenge issued\"");
}

/**
 * @brief Handle DBSC registration.
 */
int opendbsc_manager_register(OpenDBSC_Manager *mgr,
                              const char *cookie_session_id,
                              const char *session_response_header,
                              OpenDBSC_ManagerResponse *resp) {
    if (mgr == NULL || resp == NULL) {
        return -1;
    }
    opendbsc_manager_response_init(resp);

    if (cookie_session_id == NULL || cookie_session_id[0] == '\0') {
        resp->status_code = 401;
        resp->body = strdup("\"missing session cookie\"");
        return 0;
    }

    OpenDBSC_Session *session = NULL;
    if (mgr->cfg.store->get(mgr->cfg.store->impl, cookie_session_id, &session) != 0) {
        resp->status_code = 401;
        resp->body = strdup("\"invalid session\"");
        return 0;
    }

    if (session->state != OPENDBSC_SESSION_STATE_ACTIVE) {
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        resp->status_code = 400;
        resp->body = strdup("\"session is not in active state for registration\"");
        return 0;
    }

    if (session_response_header == NULL || session_response_header[0] == '\0') {
        set_challenge_response(mgr, resp, session->challenge, NULL, 403);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    OpenDBSC_ProofJWT proof;
    opendbsc_proof_jwt_init(&proof);
    if (opendbsc_jwt_decode_and_verify(session_response_header, &proof) != 0) {
        set_challenge_response(mgr, resp, session->challenge, NULL, 403);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    if (proof.challenge == NULL ||
        strcmp(proof.challenge, session->challenge) != 0) {
        set_challenge_response(mgr, resp, session->challenge, NULL, 403);
        opendbsc_proof_jwt_free(&proof);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    /* Bind the session. */
    opendbsc_session_set_state(session, OPENDBSC_SESSION_STATE_BOUND);
    opendbsc_session_set_public_key(session, proof.jwk);
    opendbsc_session_set_algorithm(session, proof.algorithm);

    char *new_challenge = opendbsc_manager_generate_challenge();
    if (new_challenge == NULL) {
        opendbsc_proof_jwt_free(&proof);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return -1;
    }
    opendbsc_session_set_challenge(session, new_challenge);
    free(new_challenge);

    apply_session_ttl(session, mgr->cfg.session_ttl_seconds);

    if (mgr->cfg.store->update(mgr->cfg.store->impl, session) != 0) {
        opendbsc_proof_jwt_free(&proof);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return -1;
    }

    char detail[256];
    snprintf(detail, sizeof(detail), "alg=%s", proof.algorithm);
    emit_event(mgr, "REGISTER", session->user_id, session->id, detail);

    resp->set_cookie = build_set_cookie(mgr, session->id);
    resp->challenge_header = opendbsc_challenge_serialize(session->challenge, NULL);
    resp->body = build_instruction_body(mgr, session);
    resp->status_code = 200;

    opendbsc_proof_jwt_free(&proof);
    mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
    return 0;
}

/**
 * @brief Handle DBSC refresh.
 */
int opendbsc_manager_refresh(OpenDBSC_Manager *mgr,
                             const char *session_id,
                             const char *session_response_header,
                             OpenDBSC_ManagerResponse *resp) {
    if (mgr == NULL || resp == NULL) {
        return -1;
    }
    opendbsc_manager_response_init(resp);

    if (session_id == NULL || session_id[0] == '\0') {
        resp->status_code = 400;
        resp->body = strdup("\"missing session identification\"");
        return 0;
    }

    OpenDBSC_Session *session = NULL;
    if (mgr->cfg.store->get(mgr->cfg.store->impl, session_id, &session) != 0) {
        resp->status_code = 401;
        resp->body = strdup("\"invalid session\"");
        return 0;
    }

    if (session->state != OPENDBSC_SESSION_STATE_BOUND) {
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        resp->status_code = 400;
        resp->body = strdup("\"session is not bound\"");
        return 0;
    }

    if (session_response_header == NULL || session_response_header[0] == '\0') {
        set_challenge_response(mgr, resp, session->challenge, session->id, 403);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    OpenDBSC_ProofJWT proof;
    opendbsc_proof_jwt_init(&proof);
    if (opendbsc_jwt_decode_and_verify(session_response_header, &proof) != 0) {
        set_challenge_response(mgr, resp, session->challenge, session->id, 403);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    if (proof.challenge == NULL ||
        strcmp(proof.challenge, session->challenge) != 0) {
        set_challenge_response(mgr, resp, session->challenge, session->id, 403);
        opendbsc_proof_jwt_free(&proof);
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return 0;
    }

    char *new_challenge = opendbsc_manager_generate_challenge();
    if (new_challenge == NULL) {
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return -1;
    }
    opendbsc_session_set_challenge(session, new_challenge);
    free(new_challenge);

    apply_session_ttl(session, mgr->cfg.session_ttl_seconds);

    if (mgr->cfg.store->update(mgr->cfg.store->impl, session) != 0) {
        mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
        return -1;
    }

    emit_event(mgr, "REFRESH", session->user_id, session->id, "session extended");

    resp->set_cookie = build_set_cookie(mgr, session->id);
    resp->challenge_header = opendbsc_challenge_serialize(session->challenge, NULL);
    resp->body = build_instruction_body(mgr, session);
    resp->status_code = 200;

    opendbsc_proof_jwt_free(&proof);
    mgr->cfg.store->free_sessions(mgr->cfg.store->impl, session, 1);
    return 0;
}
