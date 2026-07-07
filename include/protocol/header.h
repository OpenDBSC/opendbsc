#ifndef OPENDBSC_PROTOCOL_HEADER_H
#define OPENDBSC_PROTOCOL_HEADER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file protocol/header.h
 * @brief Structured header serialization and parsing for OpenDBSC.
 */

/**
 * @brief A single entry for the Secure-Session-Skipped header.
 */
typedef struct {
    const char *reason;     /**< Coarse-grained skip reason. */
    const char *session_id; /**< Identifier of the skipped session. */
} OpenDBSC_SkippedEntry;

/**
 * @brief Serialize a Secure-Session-Registration header value.
 *
 * Produces an RFC 9651 structured header value of the form:
 * @code
 * (ES256 RS256);path="reg";challenge="cv";authorization="ac";provider_key="...";
 * provider_session_id="...";provider_url="..."
 * @endcode
 *
 * Empty or @c NULL optional parameters are omitted.
 *
 * @param algorithms Array of supported algorithm names. May be @c NULL when
 *                   @p count is 0.
 * @param count Number of algorithms in @p algorithms.
 * @param path Registration endpoint path, or @c NULL to omit.
 * @param challenge Challenge value, or @c NULL to omit.
 * @param authorization Authorization string, or @c NULL to omit.
 * @param provider_key Optional provider public key, or @c NULL to omit.
 * @param provider_session_id Optional provider session id, or @c NULL to omit.
 * @param provider_url Optional provider URL, or @c NULL to omit.
 *
 * @return Newly allocated, null-terminated header value, or @c NULL on error.
 *         The caller must free the returned string with @c free().
 */
char *opendbsc_registration_serialize(const char * const *algorithms,
                                      size_t count,
                                      const char *path,
                                      const char *challenge,
                                      const char *authorization,
                                      const char *provider_key,
                                      const char *provider_session_id,
                                      const char *provider_url);

/**
 * @brief Serialize a Secure-Session-Challenge header value.
 *
 * Produces a structured header value of the form:
 * @code
 * "value";id="session_id"
 * @endcode
 *
 * The @c id parameter is omitted when @p session_id is @c NULL or empty.
 *
 * @param value Challenge value.
 * @param session_id Session identifier, or @c NULL to omit.
 *
 * @return Newly allocated string, or @c NULL on error.
 */
char *opendbsc_challenge_serialize(const char *value, const char *session_id);

/**
 * @brief Serialize a Secure-Session-Response header value.
 *
 * Produces a structured header value of the form:
 * @code
 * "jwt"
 * @endcode
 *
 * @param jwt DBSC proof JWT.
 *
 * @return Newly allocated string, or @c NULL on error.
 */
char *opendbsc_session_response_serialize(const char *jwt);

/**
 * @brief Serialize a Sec-Secure-Session-Id header value.
 *
 * Produces a structured header value of the form:
 * @code
 * "id"
 * @endcode
 *
 * @param id Session identifier.
 *
 * @return Newly allocated string, or @c NULL on error.
 */
char *opendbsc_session_id_serialize(const char *id);

/**
 * @brief Serialize a Secure-Session-Skipped header value.
 *
 * Produces a comma-separated list of entries of the form:
 * @code
 * unreachable;session_identifier="123", quota_exceeded;session_identifier="456"
 * @endcode
 *
 * @param entries Array of skipped session entries. May be @c NULL when
 *                @p count is 0.
 * @param count Number of entries in @p entries.
 *
 * @return Newly allocated string, or @c NULL on error. When @p count is 0,
 *         an empty allocated string is returned.
 */
char *opendbsc_session_skipped_serialize(const OpenDBSC_SkippedEntry *entries,
                                         size_t count);

/**
 * @brief Parse a Secure-Session-Response header value and extract the JWT.
 *
 * Accepts a quoted structured header string and returns the unquoted JWT.
 * Leading and trailing whitespace is ignored. Extra characters after the
 * closing quote cause the parse to fail.
 *
 * @param value Header value.
 *
 * @return Newly allocated JWT string, or @c NULL if @p value is @c NULL or
 *         not a properly quoted string.
 */
char *opendbsc_parse_session_response(const char *value);

/**
 * @brief Parse a Sec-Secure-Session-Id header value and extract the session id.
 *
 * @param value Header value.
 *
 * @return Newly allocated session identifier, or @c NULL if @p value is
 *         @c NULL or not a properly quoted string.
 */
char *opendbsc_parse_session_id(const char *value);

#ifdef __cplusplus
}
#endif

#endif
