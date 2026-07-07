#ifndef OPENDBSC_WRAPPER_HTTP_H
#define OPENDBSC_WRAPPER_HTTP_H

#include "manager/manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file wrapper/http.h
 * @brief mongoose-based HTTP server wrapper for OpenDBSC.
 */

/**
 * @brief Application route callback.
 *
 * @param method HTTP method.
 * @param uri Request URI path.
 * @param body Request body.
 * @param body_len Request body length.
 * @param mgr DBSC manager.
 * @param userdata User data pointer.
 * @param resp Response to fill.
 *
 * @return 0 if the route handled the request, or -1 to fall through to the
 *         default handlers.
 */
typedef int (*OpenDBSC_HTTPRoute)(const char *method, const char *uri,
                                  const char *body, size_t body_len,
                                  OpenDBSC_Manager *mgr, void *userdata,
                                  OpenDBSC_ManagerResponse *resp);

/**
 * @brief HTTP server configuration.
 */
typedef struct {
    OpenDBSC_Manager *manager; /**< DBSC manager instance. */
    const char *listen_addr;   /**< Address to listen on, e.g. "https://0.0.0.0:8447". */
    const char *cert_path;     /**< TLS certificate path. */
    const char *key_path;      /**< TLS private key path. */
    const char *static_root;   /**< Root directory for static files. May be NULL. */
    OpenDBSC_HTTPRoute route;  /**< Optional application route handler. */
    void *route_userdata;      /**< User data passed to @c route. */
} OpenDBSC_HTTPServerConfig;

/**
 * @brief Opaque HTTP server handle.
 */
typedef struct OpenDBSC_HTTPServer OpenDBSC_HTTPServer;

/**
 * @brief Create and start an HTTP server.
 *
 * @param config Server configuration.
 *
 * @return A server handle on success, or @c NULL on error.
 */
OpenDBSC_HTTPServer *opendbsc_http_server_start(const OpenDBSC_HTTPServerConfig *config);

/**
 * @brief Run the server event loop until the server is stopped.
 *
 * @param server Server handle.
 */
void opendbsc_http_server_run(OpenDBSC_HTTPServer *server);

/**
 * @brief Stop and destroy an HTTP server.
 *
 * @param server Server handle, or @c NULL.
 */
void opendbsc_http_server_stop(OpenDBSC_HTTPServer *server);

/**
 * @brief Request the server event loop to stop.
 *
 * This function is safe to call from a signal handler. It only sets the
 * internal running flag; resources are released by
 * opendbsc_http_server_stop() after opendbsc_http_server_run() returns.
 *
 * @param server Server handle, or @c NULL.
 */
void opendbsc_http_server_request_stop(OpenDBSC_HTTPServer *server);

/**
 * @brief Extract a cookie value from a mongoose HTTP message.
 *
 * @param hm Mongoose HTTP message.
 * @param name Cookie name.
 *
 * @return Newly allocated cookie value, or @c NULL if not found. The caller
 *         must free the returned string.
 */
char *opendbsc_http_get_cookie(void *hm, const char *name);

#ifdef __cplusplus
}
#endif

#endif
