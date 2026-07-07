#include "store/redis.h"

#include <cJSON.h>
#include "hiredis.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "session/session.h"
#include "store/store.h"

/**
 * @file store/redis.c
 * @brief Redis-backed session store implementation for OpenDBSC.
 */

/**
 * @brief Default Redis connection parameters.
 */
#define OPENDBSC_REDIS_DEFAULT_HOST "127.0.0.1"
#define OPENDBSC_REDIS_DEFAULT_PORT 6379
#define OPENDBSC_REDIS_DEFAULT_PREFIX "dbsc"

/**
 * @brief Internal Redis store context.
 */
typedef struct {
    redisContext *ctx;     /**< hiredis connection context. */
    char *prefix;          /**< Key prefix. */
    OpenDBSC_Store *store; /**< Owning store object. */
} OpenDBSC_RedisCtx;

/**
 * @brief Build a session key string.
 *
 * The returned string is allocated with malloc() and must be freed by the
 * caller.
 */
static char *redis_session_key(const OpenDBSC_RedisCtx *rctx, const char *id) {
    int n = snprintf(NULL, 0, "%s:session:%s", rctx->prefix, id);
    char *key = malloc((size_t)n + 1);
    if (key == NULL) {
        return NULL;
    }
    sprintf(key, "%s:session:%s", rctx->prefix, id);
    return key;
}

/**
 * @brief Build a user set key string.
 */
static char *redis_user_key(const OpenDBSC_RedisCtx *rctx, const char *user_id) {
    int n = snprintf(NULL, 0, "%s:user:%s", rctx->prefix, user_id);
    char *key = malloc((size_t)n + 1);
    if (key == NULL) {
        return NULL;
    }
    sprintf(key, "%s:user:%s", rctx->prefix, user_id);
    return key;
}

/**
 * @brief Convert a session to a JSON string.
 *
 * The returned string is allocated with malloc() and must be freed by the
 * caller.
 */
static char *session_to_json(const OpenDBSC_Session *session) {
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }

    if (session->id != NULL) {
        cJSON_AddStringToObject(obj, "id", session->id);
    }
    if (session->user_id != NULL) {
        cJSON_AddStringToObject(obj, "user_id", session->user_id);
    }
    cJSON_AddStringToObject(obj, "state", opendbsc_session_state_str(session));
    if (session->public_key != NULL) {
        cJSON *jwk = cJSON_Parse(session->public_key);
        if (jwk != NULL) {
            cJSON_AddItemToObject(obj, "public_key", jwk);
        } else {
            cJSON_AddStringToObject(obj, "public_key", session->public_key);
        }
    }
    if (session->algorithm != NULL) {
        cJSON_AddStringToObject(obj, "algorithm", session->algorithm);
    }
    if (session->challenge != NULL) {
        cJSON_AddStringToObject(obj, "challenge", session->challenge);
    }
    if (session->has_expires) {
        cJSON_AddNumberToObject(obj, "expires_at", (double)session->expires_at);
    }
    cJSON_AddNumberToObject(obj, "created_at", (double)session->created_at);

    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return str;
}

/**
 * @brief Parse a JSON string into a session.
 *
 * @return 0 on success, or -1 on error.
 */
static int session_from_json(const char *json, OpenDBSC_Session *session) {
    cJSON *obj = cJSON_Parse(json);
    if (obj == NULL) {
        return -1;
    }

    opendbsc_session_init(session);

    cJSON *id = cJSON_GetObjectItemCaseSensitive(obj, "id");
    cJSON *user_id = cJSON_GetObjectItemCaseSensitive(obj, "user_id");
    cJSON *state = cJSON_GetObjectItemCaseSensitive(obj, "state");
    cJSON *public_key = cJSON_GetObjectItemCaseSensitive(obj, "public_key");
    cJSON *algorithm = cJSON_GetObjectItemCaseSensitive(obj, "algorithm");
    cJSON *challenge = cJSON_GetObjectItemCaseSensitive(obj, "challenge");
    cJSON *expires_at = cJSON_GetObjectItemCaseSensitive(obj, "expires_at");
    cJSON *created_at = cJSON_GetObjectItemCaseSensitive(obj, "created_at");

    if (cJSON_IsString(id)) {
        opendbsc_session_set_id(session, id->valuestring);
    }
    if (cJSON_IsString(user_id)) {
        opendbsc_session_set_user_id(session, user_id->valuestring);
    }
    if (cJSON_IsString(state)) {
        opendbsc_session_set_state_str(session, state->valuestring);
    }
    if (cJSON_IsObject(public_key)) {
        char *jwk = cJSON_PrintUnformatted(public_key);
        opendbsc_session_set_public_key(session, jwk);
        free(jwk);
    } else if (cJSON_IsString(public_key)) {
        opendbsc_session_set_public_key(session, public_key->valuestring);
    }
    if (cJSON_IsString(algorithm)) {
        opendbsc_session_set_algorithm(session, algorithm->valuestring);
    }
    if (cJSON_IsString(challenge)) {
        opendbsc_session_set_challenge(session, challenge->valuestring);
    }
    if (cJSON_IsNumber(expires_at)) {
        opendbsc_session_set_expires_at(session, (time_t)expires_at->valuedouble);
    }
    if (cJSON_IsNumber(created_at)) {
        opendbsc_session_set_created_at(session, (time_t)created_at->valuedouble);
    }

    cJSON_Delete(obj);
    return 0;
}

/**
 * @brief Free a redisReply and clear the pointer.
 */
static void free_reply(redisReply **reply) {
    if (reply != NULL && *reply != NULL) {
        freeReplyObject(*reply);
        *reply = NULL;
    }
}

/**
 * @brief Check whether a session has expired.
 */
static bool is_expired(const OpenDBSC_Session *session) {
    if (session == NULL || !session->has_expires) {
        return false;
    }
    return difftime(time(NULL), session->expires_at) > 0.0;
}

static int redis_create(void *impl, const OpenDBSC_Session *session);
static int redis_get(void *impl, const char *id, OpenDBSC_Session **out);
static int redis_update(void *impl, const OpenDBSC_Session *session);
static int redis_delete(void *impl, const char *id);
static int redis_get_by_user_id(void *impl, const char *user_id,
                                OpenDBSC_Session **out, size_t *count);
static int redis_delete_by_user_id(void *impl, const char *user_id);
static void redis_free_sessions(void *impl, OpenDBSC_Session *sessions,
                                size_t count);
static void redis_destroy(void *impl);

/**
 * @brief Persist a new session to Redis.
 */
static int redis_create(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;

    char *json = session_to_json(session);
    if (json == NULL) {
        return -1;
    }

    char *skey = redis_session_key(rctx, session->id);
    char *ukey = redis_user_key(rctx, session->user_id);
    if (skey == NULL || ukey == NULL) {
        free(json);
        free(skey);
        free(ukey);
        return -1;
    }

    redisReply *reply = NULL;
    int rc = -1;

    if (session->has_expires) {
        time_t ttl = session->expires_at - time(NULL);
        if (ttl <= 0) ttl = 1;
        reply = redisCommand(rctx->ctx, "SET %s %s EX %lld", skey, json,
                             (long long)ttl);
    } else {
        reply = redisCommand(rctx->ctx, "SET %s %s", skey, json);
    }
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        free_reply(&reply);
        goto done;
    }
    free_reply(&reply);

    reply = redisCommand(rctx->ctx, "SADD %s %s", ukey, session->id);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        free_reply(&reply);
        goto done;
    }

    rc = 0;
done:
    free(json);
    free(skey);
    free(ukey);
    free_reply(&reply);
    return rc;
}

/**
 * @brief Retrieve a session by identifier from Redis.
 */
static int redis_get(void *impl, const char *id, OpenDBSC_Session **out) {
    if (impl == NULL || id == NULL || out == NULL) {
        return -1;
    }
    *out = NULL;
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;

    char *skey = redis_session_key(rctx, id);
    if (skey == NULL) {
        return -1;
    }

    redisReply *reply = redisCommand(rctx->ctx, "GET %s", skey);
    free(skey);
    if (reply == NULL) {
        return -1;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        free_reply(&reply);
        return -1;
    }
    if (reply->type != REDIS_REPLY_STRING) {
        free_reply(&reply);
        return -1;
    }

    OpenDBSC_Session *session = malloc(sizeof(*session));
    if (session == NULL) {
        free_reply(&reply);
        return -1;
    }
    opendbsc_session_init(session);

    if (session_from_json(reply->str, session) != 0) {
        free(session);
        free_reply(&reply);
        return -1;
    }
    free_reply(&reply);

    if (is_expired(session)) {
        redis_delete(impl, id);
        opendbsc_session_free(session);
        free(session);
        return -1;
    }

    *out = session;
    return 0;
}

/**
 * @brief Update an existing session in Redis.
 */
static int redis_update(void *impl, const OpenDBSC_Session *session) {
    if (impl == NULL || session == NULL || session->id == NULL) {
        return -1;
    }

    /* Ensure the session exists before overwriting. */
    OpenDBSC_Session *existing = NULL;
    if (redis_get(impl, session->id, &existing) != 0) {
        return -1;
    }
    redis_free_sessions(impl, existing, 1);

    /* Re-use create to overwrite the key and update the user set. */
    return redis_create(impl, session);
}

/**
 * @brief Delete a session from Redis.
 */
static int redis_delete(void *impl, const char *id) {
    if (impl == NULL || id == NULL) {
        return -1;
    }
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;

    OpenDBSC_Session *session = NULL;
    char *ukey = NULL;
    if (redis_get(impl, id, &session) == 0) {
        ukey = redis_user_key(rctx, session->user_id);
        redis_free_sessions(impl, session, 1);
    }

    char *skey = redis_session_key(rctx, id);
    if (skey == NULL) {
        free(ukey);
        return -1;
    }

    redisReply *reply = redisCommand(rctx->ctx, "DEL %s", skey);
    free(skey);
    if (reply != NULL) {
        free_reply(&reply);
    }

    if (ukey != NULL) {
        reply = redisCommand(rctx->ctx, "SREM %s %s", ukey, id);
        free(ukey);
        if (reply != NULL) {
            free_reply(&reply);
        }
    }

    return 0;
}

/**
 * @brief Retrieve all non-expired sessions for a user from Redis.
 */
static int redis_get_by_user_id(void *impl, const char *user_id,
                                OpenDBSC_Session **out, size_t *count) {
    if (impl == NULL || user_id == NULL || out == NULL || count == NULL) {
        return -1;
    }
    *out = NULL;
    *count = 0;
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;

    char *ukey = redis_user_key(rctx, user_id);
    if (ukey == NULL) {
        return -1;
    }

    redisReply *reply = redisCommand(rctx->ctx, "SMEMBERS %s", ukey);
    free(ukey);
    if (reply == NULL) {
        return -1;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        free_reply(&reply);
        return 0;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        free_reply(&reply);
        return -1;
    }

    OpenDBSC_Session *sessions = NULL;
    size_t n = 0;

    for (size_t i = 0; i < reply->elements; i++) {
        if (reply->element[i]->type != REDIS_REPLY_STRING) {
            continue;
        }
        OpenDBSC_Session *session = NULL;
        if (redis_get(impl, reply->element[i]->str, &session) != 0) {
            continue;
        }
        OpenDBSC_Session *next = realloc(sessions, (n + 1) * sizeof(*sessions));
        if (next == NULL) {
            opendbsc_session_free(session);
            free(session);
            redis_free_sessions(impl, sessions, n);
            free_reply(&reply);
            return -1;
        }
        sessions = next;
        memcpy(&sessions[n], session, sizeof(*session));
        n++;
        free(session);
    }

    free_reply(&reply);
    *out = sessions;
    *count = n;
    return 0;
}

/**
 * @brief Delete all sessions belonging to a user from Redis.
 */
static int redis_delete_by_user_id(void *impl, const char *user_id) {
    if (impl == NULL || user_id == NULL) {
        return -1;
    }
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;

    OpenDBSC_Session *sessions = NULL;
    size_t count = 0;
    if (redis_get_by_user_id(impl, user_id, &sessions, &count) != 0) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        redis_delete(impl, sessions[i].id);
    }
    redis_free_sessions(impl, sessions, count);

    char *ukey = redis_user_key(rctx, user_id);
    if (ukey != NULL) {
        redisReply *reply = redisCommand(rctx->ctx, "DEL %s", ukey);
        free(ukey);
        if (reply != NULL) {
            free_reply(&reply);
        }
    }

    return 0;
}

/**
 * @brief Free sessions returned by the Redis store.
 */
static void redis_free_sessions(void *impl, OpenDBSC_Session *sessions,
                                size_t count) {
    (void)impl;
    if (sessions == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        opendbsc_session_free(&sessions[i]);
    }
    free(sessions);
}

/**
 * @brief Destroy the Redis store.
 */
static void redis_destroy(void *impl) {
    if (impl == NULL) {
        return;
    }
    OpenDBSC_RedisCtx *rctx = (OpenDBSC_RedisCtx *)impl;
    if (rctx->ctx != NULL) {
        redisFree(rctx->ctx);
    }
    free(rctx->prefix);
    free(rctx->store);
    free(rctx);
}

OpenDBSC_Store *opendbsc_redis_store_create(const OpenDBSC_RedisConfig *config) {
    const char *host = OPENDBSC_REDIS_DEFAULT_HOST;
    int port = OPENDBSC_REDIS_DEFAULT_PORT;
    const char *prefix = OPENDBSC_REDIS_DEFAULT_PREFIX;

    if (config != NULL) {
        if (config->host != NULL) host = config->host;
        if (config->port != 0) port = config->port;
        if (config->prefix != NULL) prefix = config->prefix;
    }

    redisContext *ctx = redisConnect(host, port);
    if (ctx == NULL || ctx->err) {
        if (ctx != NULL) redisFree(ctx);
        return NULL;
    }

    OpenDBSC_RedisCtx *rctx = malloc(sizeof(*rctx));
    if (rctx == NULL) {
        redisFree(ctx);
        return NULL;
    }

    rctx->ctx = ctx;
    rctx->prefix = strdup(prefix);
    rctx->store = NULL;
    if (rctx->prefix == NULL) {
        redisFree(ctx);
        free(rctx);
        return NULL;
    }

    OpenDBSC_Store *store = malloc(sizeof(*store));
    if (store == NULL) {
        redisFree(ctx);
        free(rctx->prefix);
        free(rctx);
        return NULL;
    }

    store->impl = rctx;
    store->create = redis_create;
    store->get = redis_get;
    store->update = redis_update;
    store->delete = redis_delete;
    store->get_by_user_id = redis_get_by_user_id;
    store->delete_by_user_id = redis_delete_by_user_id;
    store->free_sessions = redis_free_sessions;
    store->destroy = redis_destroy;

    rctx->store = store;
    return store;
}
