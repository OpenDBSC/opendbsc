#include "wrapper/http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mongoose.h"

/**
 * @file wrapper/http.c
 * @brief mongoose-based HTTP server wrapper for OpenDBSC.
 */

/**
 * @brief Internal HTTP server state.
 */
struct OpenDBSC_HTTPServer {
    struct mg_mgr mgr;              /**< Mongoose event manager. */
    OpenDBSC_Manager *manager;      /**< DBSC manager. */
    OpenDBSC_HTTPRoute route;       /**< Application route callback. */
    void *route_userdata;           /**< User data for route callback. */
    const char *static_root;        /**< Static file root. */
    int running;                    /**< Event loop flag. */
    char *tls_cert;                 /**< TLS certificate PEM contents. */
    char *tls_key;                  /**< TLS private key PEM contents. */
};

/**
 * @brief Copy a mongoose string to a newly allocated C string.
 */
static char *mg_str_dup(const struct mg_str *str) {
    if (str == NULL || str->buf == NULL || str->len == 0) {
        return NULL;
    }
    char *copy = malloc(str->len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, str->buf, str->len);
    copy[str->len] = '\0';
    return copy;
}

/**
 * @brief Strip a single pair of surrounding double quotes.
 *
 * Secure-Session-Response may be transmitted as a quoted structured-field
 * string. The returned pointer must be freed by the caller.
 */
static char *strip_quotes(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        char *out = malloc(len - 1);
        if (out == NULL) {
            return NULL;
        }
        memcpy(out, s + 1, len - 2);
        out[len - 2] = '\0';
        return out;
    }
    return strdup(s);
}

/**
 * @brief Extract a cookie value from a mongoose HTTP message.
 */
char *opendbsc_http_get_cookie(void *hm, const char *name) {
    struct mg_http_message *msg = (struct mg_http_message *)hm;
    struct mg_str *cookie = mg_http_get_header(msg, "Cookie");
    if (cookie == NULL || name == NULL) {
        return NULL;
    }

    size_t name_len = strlen(name);
    const char *p = cookie->buf;
    const char *end = cookie->buf + cookie->len;

    while (p < end) {
        /* Skip leading whitespace. */
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end) break;

        const char *start = p;
        while (p < end && *p != '=' && *p != ';') p++;
        if (p >= end || *p != '=') break;

        size_t key_len = (size_t)(p - start);
        p++;
        const char *value_start = p;
        while (p < end && *p != ';') p++;
        size_t value_len = (size_t)(p - value_start);

        if (key_len == name_len && strncmp(start, name, name_len) == 0) {
            char *out = malloc(value_len + 1);
            if (out == NULL) return NULL;
            memcpy(out, value_start, value_len);
            out[value_len] = '\0';
            return out;
        }

        if (p < end && *p == ';') p++;
    }

    return NULL;
}

/**
 * @brief Send a manager response over a mongoose connection.
 */
static void send_response(struct mg_connection *c,
                          const OpenDBSC_ManagerResponse *resp) {
    /* Build a header string from the response fields. */
    size_t headers_size = 256;
    char *headers = malloc(headers_size);
    if (headers == NULL) {
        mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                      "Internal Server Error");
        return;
    }
    headers[0] = '\0';

    if (resp->set_cookie != NULL) {
        size_t need = strlen(headers) + strlen(resp->set_cookie) + 64;
        if (need > headers_size) {
            headers_size = need * 2;
            char *tmp = realloc(headers, headers_size);
            if (tmp == NULL) {
                free(headers);
                mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                              "Internal Server Error");
                return;
            }
            headers = tmp;
        }
        strcat(headers, "Set-Cookie: ");
        strcat(headers, resp->set_cookie);
        strcat(headers, "\r\n");
    }
    if (resp->registration_header != NULL) {
        size_t need = strlen(headers) + strlen(resp->registration_header) + 64;
        if (need > headers_size) {
            headers_size = need * 2;
            char *tmp = realloc(headers, headers_size);
            if (tmp == NULL) {
                free(headers);
                mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                              "Internal Server Error");
                return;
            }
            headers = tmp;
        }
        strcat(headers, "Secure-Session-Registration: ");
        strcat(headers, resp->registration_header);
        strcat(headers, "\r\n");
    }
    if (resp->challenge_header != NULL) {
        size_t need = strlen(headers) + strlen(resp->challenge_header) + 64;
        if (need > headers_size) {
            headers_size = need * 2;
            char *tmp = realloc(headers, headers_size);
            if (tmp == NULL) {
                free(headers);
                mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                              "Internal Server Error");
                return;
            }
            headers = tmp;
        }
        strcat(headers, "Secure-Session-Challenge: ");
        strcat(headers, resp->challenge_header);
        strcat(headers, "\r\n");
    }

    const char *content_type = "Content-Type: application/json\r\n";
    size_t final_size = strlen(headers) + strlen(content_type) + 1;
    char *final_headers = malloc(final_size);
    if (final_headers == NULL) {
        free(headers);
        mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                      "Internal Server Error");
        return;
    }
    strcpy(final_headers, headers);
    strcat(final_headers, content_type);
    free(headers);

    const char *body = resp->body != NULL ? resp->body : "";
    mg_http_reply(c, resp->status_code, final_headers, "%s", body);
    free(final_headers);
}

/**
 * @brief Mongoose event handler for DBSC requests.
 */
static void dbsc_event_handler(struct mg_connection *c, int ev, void *ev_data) {
    OpenDBSC_HTTPServer *server = (OpenDBSC_HTTPServer *)c->fn_data;
    if (server == NULL) {
        return;
    }

    if (ev == MG_EV_ACCEPT && server->tls_cert != NULL && server->tls_key != NULL) {
        struct mg_tls_opts tls_opts = {
            .cert = mg_str_n(server->tls_cert, strlen(server->tls_cert)),
            .key = mg_str_n(server->tls_key, strlen(server->tls_key)),
        };
        mg_tls_init(c, &tls_opts);
        return;
    }

    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        char *uri = mg_str_dup(&hm->uri);
        char *method = mg_str_dup(&hm->method);
        char *body = mg_str_dup(&hm->body);
        size_t body_len = hm->body.len;

        if (uri == NULL || method == NULL) {
            free(uri);
            free(method);
            free(body);
            mg_http_reply(c, 500, "Content-Type: text/plain\r\n",
                          "Internal Server Error");
            return;
        }

        OpenDBSC_ManagerResponse resp;
        opendbsc_manager_response_init(&resp);

        /* Let the application route handle custom endpoints first. */
        if (server->route != NULL &&
            server->route(method, uri, body, body_len, server->manager,
                          server->route_userdata, &resp) == 0) {
            send_response(c, &resp);
            opendbsc_manager_response_free(&resp);
            free(uri);
            free(method);
            free(body);
            return;
        }

        /* Default DBSC endpoints. */
        if (strcmp(method, "POST") == 0 && strcmp(uri, "/dbsc/register") == 0) {
            char *cookie = opendbsc_http_get_cookie(hm,
                                                    server->manager->cfg.cookie_name);
            struct mg_str *proof_hdr = mg_http_get_header(hm, "Secure-Session-Response");
            char *proof_raw = mg_str_dup(proof_hdr);
            char *proof = strip_quotes(proof_raw);
            free(proof_raw);

            opendbsc_manager_register(server->manager, cookie, proof, &resp);
            send_response(c, &resp);

            free(cookie);
            free(proof);
            opendbsc_manager_response_free(&resp);
            free(uri);
            free(method);
            free(body);
            return;
        }

        if (strcmp(method, "POST") == 0 && strcmp(uri, "/dbsc/refresh") == 0) {
            struct mg_str *sid_hdr = mg_http_get_header(hm, "Sec-Secure-Session-Id");
            char *session_id = mg_str_dup(sid_hdr);
            if (session_id == NULL) {
                session_id = opendbsc_http_get_cookie(hm,
                                                      server->manager->cfg.cookie_name);
            }
            struct mg_str *proof_hdr = mg_http_get_header(hm, "Secure-Session-Response");
            char *proof_raw = mg_str_dup(proof_hdr);
            char *proof = strip_quotes(proof_raw);
            free(proof_raw);

            opendbsc_manager_refresh(server->manager, session_id, proof, &resp);
            send_response(c, &resp);

            free(session_id);
            free(proof);
            opendbsc_manager_response_free(&resp);
            free(uri);
            free(method);
            free(body);
            return;
        }

        /* GET /api/me */
        if (strcmp(method, "GET") == 0 && strcmp(uri, "/api/me") == 0) {
            char *cookie = opendbsc_http_get_cookie(hm,
                                                    server->manager->cfg.cookie_name);
            OpenDBSC_Session *session = NULL;
            if (cookie != NULL &&
                opendbsc_manager_get_session(server->manager, cookie, &session) == 0) {
                char buf[512];
                snprintf(buf, sizeof(buf),
                         "{\"user\":\"%s\",\"time\":\"%ld\"}",
                         session->user_id, (long)time(NULL));
                resp.status_code = 200;
                resp.body = strdup(buf);
                server->manager->cfg.store->free_sessions(
                    server->manager->cfg.store->impl, session, 1);
            } else {
                resp.status_code = 401;
                resp.body = strdup("{\"error\":\"unauthorized\"}");
            }
            send_response(c, &resp);
            free(cookie);
            opendbsc_manager_response_free(&resp);
            free(uri);
            free(method);
            free(body);
            return;
        }

        /* Static files. */
        if (server->static_root != NULL) {
            struct mg_http_serve_opts opts = {
                .root_dir = server->static_root,
            };
            mg_http_serve_dir(c, hm, &opts);
            free(uri);
            free(method);
            free(body);
            return;
        }

        mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Not Found");
        free(uri);
        free(method);
        free(body);
    }
}

OpenDBSC_HTTPServer *opendbsc_http_server_start(const OpenDBSC_HTTPServerConfig *config) {
    if (config == NULL || config->manager == NULL || config->listen_addr == NULL) {
        return NULL;
    }

    OpenDBSC_HTTPServer *server = calloc(1, sizeof(*server));
    if (server == NULL) {
        return NULL;
    }

    server->manager = config->manager;
    server->route = config->route;
    server->route_userdata = config->route_userdata;
    server->static_root = config->static_root;
    server->running = 1;

    mg_mgr_init(&server->mgr);

    struct mg_connection *c = mg_http_listen(&server->mgr, config->listen_addr,
                                              dbsc_event_handler, server);
    if (c == NULL) {
        mg_mgr_free(&server->mgr);
        free(server);
        return NULL;
    }

    /* Load TLS certificate/key contents for accepted connections. */
    if (config->cert_path != NULL && config->key_path != NULL) {
        struct mg_str cert_data = mg_file_read(&mg_fs_posix, config->cert_path);
        struct mg_str key_data = mg_file_read(&mg_fs_posix, config->key_path);
        if (cert_data.buf != NULL && key_data.buf != NULL) {
            server->tls_cert = malloc(cert_data.len + 1);
            server->tls_key = malloc(key_data.len + 1);
            if (server->tls_cert != NULL && server->tls_key != NULL) {
                memcpy(server->tls_cert, cert_data.buf, cert_data.len);
                server->tls_cert[cert_data.len] = '\0';
                memcpy(server->tls_key, key_data.buf, key_data.len);
                server->tls_key[key_data.len] = '\0';
            } else {
                free(server->tls_cert);
                free(server->tls_key);
                server->tls_cert = NULL;
                server->tls_key = NULL;
            }
        }
        free((void *)cert_data.buf);
        free((void *)key_data.buf);
    }

    return server;
}

void opendbsc_http_server_run(OpenDBSC_HTTPServer *server) {
    if (server == NULL) {
        return;
    }
    while (server->running) {
        mg_mgr_poll(&server->mgr, 1000);
    }
}

void opendbsc_http_server_request_stop(OpenDBSC_HTTPServer *server) {
    if (server == NULL) {
        return;
    }
    server->running = 0;
}

void opendbsc_http_server_stop(OpenDBSC_HTTPServer *server) {
    if (server == NULL) {
        return;
    }
    server->running = 0;
    mg_mgr_free(&server->mgr);
    free(server->tls_cert);
    free(server->tls_key);
    free(server);
}
