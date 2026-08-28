/**
 * @file examples/server.c
 * @brief Example HTTPS DBSC server using OpenDBSC and mongoose.
 *
 * Run with:
 *   ./server [memory|sqlite|redis|odbc] [odbc_connection_string]
 *
 * For the ODBC backend the connection string is taken from the second
 * command-line argument or the DBSC_ODBC_CONN environment variable.
 *
 * The server listens on https://0.0.0.0:8447 and expects TLS certificates
 * at cert/cert.pem and cert/key.pem relative to the working directory.
 * See README.md "TLS certificates" for generation instructions.
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "manager/manager.h"
#include "store/memory.h"
#ifdef OPENDBSC_HAVE_ODBC
#include "store/odbc.h"
#endif
#include "store/redis.h"
#include "store/sqlite.h"
#include "wrapper/http.h"

/**
 * @brief Example user database.
 */
typedef struct {
    const char *username;
    const char *password;
} User;

static const User users[] = {
    {"alice", "password123"},
    {"bob", "hunter2"},
};

/**
 * @brief Event log entry.
 */
typedef struct {
    char time[16];
    char type[32];
    char user[64];
    char session[64];
    char detail[256];
} Event;

#define MAX_EVENTS 100
static Event event_log[MAX_EVENTS];
static size_t event_count = 0;
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Global server handle for signal handling.
 */
static OpenDBSC_HTTPServer *g_server = NULL;

/**
 * @brief Validate user credentials.
 */
static int validate_login(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        return 0;
    }
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Add an entry to the event log.
 */
static void add_event(const char *type, const char *user, const char *session_id,
                      const char *detail, void *userdata) {
    (void)userdata;
    pthread_mutex_lock(&event_mutex);

    Event *e = &event_log[event_count % MAX_EVENTS];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(e->time, sizeof(e->time), "%H:%M:%S", &tm);

    strncpy(e->type, type ? type : "", sizeof(e->type) - 1);
    e->type[sizeof(e->type) - 1] = '\0';
    strncpy(e->user, user ? user : "", sizeof(e->user) - 1);
    e->user[sizeof(e->user) - 1] = '\0';
    strncpy(e->session, session_id ? session_id : "", sizeof(e->session) - 1);
    e->session[sizeof(e->session) - 1] = '\0';
    strncpy(e->detail, detail ? detail : "", sizeof(e->detail) - 1);
    e->detail[sizeof(e->detail) - 1] = '\0';

    if (event_count < MAX_EVENTS) {
        event_count++;
    }

    printf("[%s] user=%s session=%s %s\n", e->type, e->user, e->session, e->detail);
    pthread_mutex_unlock(&event_mutex);
}

/**
 * @brief Parse a URL-encoded form value from a buffer.
 */
static char *get_form_value(const char *body, const char *name) {
    if (body == NULL || name == NULL) {
        return NULL;
    }
    size_t name_len = strlen(name);
    const char *p = body;

    while (*p != '\0') {
        const char *start = p;
        while (*p != '\0' && *p != '=' && *p != '&') p++;

        if (*p == '=' && (size_t)(p - start) == name_len &&
            strncmp(start, name, name_len) == 0) {
            p++;
            const char *value_start = p;
            while (*p != '\0' && *p != '&') p++;
            size_t len = (size_t)(p - value_start);
            char *value = malloc(len + 1);
            if (value == NULL) return NULL;
            memcpy(value, value_start, len);
            value[len] = '\0';
            return value;
        }

        if (*p == '=') {
            while (*p != '\0' && *p != '&') p++;
        }
        if (*p == '&') p++;
    }

    return NULL;
}

/**
 * @brief Application route handler.
 */
static int app_route(const char *method, const char *uri, const char *body,
                     size_t body_len, OpenDBSC_Manager *mgr, void *userdata,
                     OpenDBSC_ManagerResponse *resp) {
    (void)body_len;
    (void)userdata;

    /* POST /login */
    if (strcmp(method, "POST") == 0 && strcmp(uri, "/login") == 0) {
        char *username = get_form_value(body, "username");
        char *password = get_form_value(body, "password");

        if (username == NULL || password == NULL ||
            !validate_login(username, password)) {
            add_event("LOGIN_FAIL", username ? username : "", "",
                      "invalid credentials", NULL);
            free(username);
            free(password);
            resp->status_code = 401;
            resp->body = strdup("{\"error\":\"invalid credentials\"}");
            return 0;
        }

        OpenDBSC_Session session;
        opendbsc_session_init(&session);
        int rc = opendbsc_manager_initiate(mgr, username, &session, resp);
        if (rc != 0) {
            opendbsc_session_free(&session);
            free(username);
            free(password);
            resp->status_code = 500;
            resp->body = strdup("{\"error\":\"failed to initiate session\"}");
            return 0;
        }

        char body_buf[512];
        snprintf(body_buf, sizeof(body_buf),
                 "{\"message\":\"login successful\",\"session_id\":\"%s\"}",
                 session.id);
        resp->body = strdup(body_buf);
        opendbsc_session_free(&session);
        free(username);
        free(password);
        return 0;
    }

    /* GET /api/events */
    if (strcmp(method, "GET") == 0 && strcmp(uri, "/api/events") == 0) {
        pthread_mutex_lock(&event_mutex);
        size_t count = event_count < MAX_EVENTS ? event_count : MAX_EVENTS;
        size_t total = event_count;
        pthread_mutex_unlock(&event_mutex);

        /* Compute required buffer size. */
        size_t size = 128;
        for (size_t i = 0; i < count; i++) {
            size += strlen(event_log[i].time) + strlen(event_log[i].type) +
                    strlen(event_log[i].user) + strlen(event_log[i].session) +
                    strlen(event_log[i].detail) + 128;
        }

        char *json = malloc(size);
        if (json == NULL) {
            resp->status_code = 500;
            resp->body = strdup("{\"error\":\"out of memory\"}");
            return 0;
        }

        char *w = json;
        w += sprintf(w, "{\"total\":%zu,\"events\":[", total);
        for (size_t i = 0; i < count; i++) {
            if (i > 0) w += sprintf(w, ",");
            w += sprintf(w,
                         "{\"time\":\"%s\",\"type\":\"%s\",\"user\":\"%s\","
                         "\"session\":\"%s\",\"detail\":\"%s\"}",
                         event_log[i].time, event_log[i].type, event_log[i].user,
                         event_log[i].session, event_log[i].detail);
        }
        w += sprintf(w, "]}");

        resp->status_code = 200;
        resp->body = json;
        return 0;
    }

    /* GET /api/status */
    if (strcmp(method, "GET") == 0 && strcmp(uri, "/api/status") == 0) {
        resp->status_code = 200;
        resp->body = strdup("{\"service\":\"opendbsc\",\"mode\":\"mongoose\","
                            "\"status\":\"running\"}");
        return 0;
    }

    /* GET /api/me */
    if (strcmp(method, "GET") == 0 && strcmp(uri, "/api/me") == 0) {
        /* Note: body is not available here for cookie extraction, so this
         * endpoint is handled inside the mongoose wrapper for the actual
         * request. We leave a placeholder that always falls through. */
        (void)mgr;
        return -1;
    }

    return -1;
}

/**
 * @brief Signal handler for graceful shutdown.
 *
 * Only sets the running flag; the main loop performs cleanup after returning.
 */
static void signal_handler(int sig) {
    (void)sig;
    opendbsc_http_server_request_stop(g_server);
}

/**
 * @brief Create a session store based on the command-line argument.
 */
static OpenDBSC_Store *create_store(const char *type, const char *odbc_conn) {
    if (type == NULL || strcmp(type, "memory") == 0) {
        return opendbsc_memory_store_create();
    }
    if (strcmp(type, "sqlite") == 0) {
        return opendbsc_sqlite_store_create("dbsc_sessions.db");
    }
    if (strcmp(type, "redis") == 0) {
        return opendbsc_redis_store_create(NULL);
    }
    if (strcmp(type, "odbc") == 0) {
#ifdef OPENDBSC_HAVE_ODBC
        if (odbc_conn == NULL) {
            odbc_conn = getenv("DBSC_ODBC_CONN");
        }
        if (odbc_conn == NULL) {
            fprintf(stderr,
                    "odbc store requires a connection string (second argument "
                    "or DBSC_ODBC_CONN)\n");
            return NULL;
        }
        OpenDBSC_OdbcConfig odbc_cfg = {
            .connection_string = odbc_conn,
            .table_name = NULL,
            .auto_create_table = 1,
            .login_timeout_seconds = 0,
        };
        return opendbsc_odbc_store_create(&odbc_cfg);
#else
        fprintf(stderr, "odbc store not available: built without ODBC support\n");
        return NULL;
#endif
    }
    fprintf(stderr,
            "unknown store type: %s (use memory, sqlite, redis, or odbc)\n",
            type);
    return NULL;
}

int main(int argc, char **argv) {
    const char *store_type = argc > 1 ? argv[1] : "memory";
    const char *odbc_conn = argc > 2 ? argv[2] : NULL;

    OpenDBSC_Store *store = create_store(store_type, odbc_conn);
    if (store == NULL) {
        fprintf(stderr, "failed to create %s store\n", store_type);
        return 1;
    }

    OpenDBSC_ManagerConfig cfg = {
        .store = store,
        .cookie_name = "session_id",
        .cookie_path = "/",
        .secure = 1,
        .same_site = "None",
        .cookie_ttl_seconds = 600,
        .session_ttl_seconds = 0,
        .on_event = add_event,
    };

    OpenDBSC_Manager mgr;
    if (opendbsc_manager_init(&mgr, &cfg) != 0) {
        fprintf(stderr, "failed to initialize manager\n");
        store->destroy(store->impl);
        return 1;
    }

    OpenDBSC_HTTPServerConfig server_cfg = {
        .manager = &mgr,
        .listen_addr = "https://0.0.0.0:8447",
        .cert_path = "cert/cert.pem",
        .key_path = "cert/key.pem",
        .static_root = "examples/static",
        .route = app_route,
    };

    g_server = opendbsc_http_server_start(&server_cfg);
    if (g_server == NULL) {
        fprintf(stderr, "failed to start HTTP server\n");
        opendbsc_manager_destroy(&mgr);
        store->destroy(store->impl);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("[opendbsc] HTTPS server running on https://0.0.0.0:8447 "
           "(store=%s)\n", store_type);
    printf("[opendbsc] Press Ctrl+C to stop.\n");

    opendbsc_http_server_run(g_server);

    opendbsc_manager_destroy(&mgr);
    store->destroy(store->impl);

    printf("[opendbsc] Server stopped.\n");
    return 0;
}
