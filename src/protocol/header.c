#include "protocol/header.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- internal helpers ---------------------------------------------------- */

/**
 * @brief Test whether a character is a horizontal or vertical whitespace.
 */
static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == '\f' || c == '\v';
}

/**
 * @brief Duplicate a substring of exactly @p len bytes.
 */
static char *memdup_str(const char *src, size_t len)
{
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

/**
 * @brief Join an array of strings with a single separator character.
 *
 * @return Newly allocated string, or @c NULL on error. An empty array
 *         returns an empty allocated string.
 */
static char *join_strings(const char * const *arr, size_t count, char sep)
{
    if (count == 0) {
        return memdup_str("", 0);
    }

    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        total += strlen(arr[i]);
    }
    total += count - 1; /* separators */

    char *out = malloc(total + 1);
    if (!out) {
        return NULL;
    }

    size_t pos = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t len = strlen(arr[i]);
        memcpy(out + pos, arr[i], len);
        pos += len;
        if (i + 1 < count) {
            out[pos++] = sep;
        }
    }
    out[pos] = '\0';
    return out;
}

/**
 * @brief Extract the contents of a quoted structured-header string.
 *
 * Allows escaped characters inside the string. Leading and trailing whitespace
 * is ignored. Anything after the closing quote causes failure.
 */
static char *unquote(const char *value)
{
    if (!value) {
        return NULL;
    }

    while (is_space(*value)) {
        ++value;
    }

    if (*value != '"') {
        return NULL;
    }

    const char *start = value + 1;
    const char *p = start;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) {
            p += 2;
        } else {
            ++p;
        }
    }

    if (*p != '"') {
        return NULL;
    }

    const char *tail = p + 1;
    while (*tail && is_space(*tail)) {
        ++tail;
    }
    if (*tail != '\0') {
        return NULL;
    }

    return memdup_str(start, (size_t)(p - start));
}

/* --- serialization ------------------------------------------------------- */

char *opendbsc_registration_serialize(const char * const *algorithms,
                                      size_t count,
                                      const char *path,
                                      const char *challenge,
                                      const char *authorization,
                                      const char *provider_key,
                                      const char *provider_session_id,
                                      const char *provider_url)
{
    if (count > 0 && !algorithms) {
        return NULL;
    }

    char *algs = join_strings(algorithms, count, ' ');
    if (!algs) {
        return NULL;
    }

    int n = snprintf(NULL, 0, "(%s)", algs);
    if (path && *path) {
        n += snprintf(NULL, 0, ";path=\"%s\"", path);
    }
    if (challenge && *challenge) {
        n += snprintf(NULL, 0, ";challenge=\"%s\"", challenge);
    }
    if (authorization && *authorization) {
        n += snprintf(NULL, 0, ";authorization=\"%s\"", authorization);
    }
    if (provider_key && *provider_key) {
        n += snprintf(NULL, 0, ";provider_key=\"%s\"", provider_key);
    }
    if (provider_session_id && *provider_session_id) {
        n += snprintf(NULL, 0, ";provider_session_id=\"%s\"", provider_session_id);
    }
    if (provider_url && *provider_url) {
        n += snprintf(NULL, 0, ";provider_url=\"%s\"", provider_url);
    }

    char *out = malloc((size_t)n + 1);
    if (!out) {
        free(algs);
        return NULL;
    }

    char *w = out;
    w += sprintf(w, "(%s)", algs);
    if (path && *path) {
        w += sprintf(w, ";path=\"%s\"", path);
    }
    if (challenge && *challenge) {
        w += sprintf(w, ";challenge=\"%s\"", challenge);
    }
    if (authorization && *authorization) {
        w += sprintf(w, ";authorization=\"%s\"", authorization);
    }
    if (provider_key && *provider_key) {
        w += sprintf(w, ";provider_key=\"%s\"", provider_key);
    }
    if (provider_session_id && *provider_session_id) {
        w += sprintf(w, ";provider_session_id=\"%s\"", provider_session_id);
    }
    if (provider_url && *provider_url) {
        w += sprintf(w, ";provider_url=\"%s\"", provider_url);
    }

    free(algs);
    return out;
}

char *opendbsc_challenge_serialize(const char *value, const char *session_id)
{
    if (!value) {
        return NULL;
    }

    int n = snprintf(NULL, 0, "\"%s\"", value);
    if (session_id && *session_id) {
        n += snprintf(NULL, 0, ";id=\"%s\"", session_id);
    }

    char *out = malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }

    char *w = out;
    w += sprintf(w, "\"%s\"", value);
    if (session_id && *session_id) {
        w += sprintf(w, ";id=\"%s\"", session_id);
    }

    return out;
}

char *opendbsc_session_response_serialize(const char *jwt)
{
    if (!jwt) {
        return NULL;
    }

    int n = snprintf(NULL, 0, "\"%s\"", jwt);
    char *out = malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    sprintf(out, "\"%s\"", jwt);
    return out;
}

char *opendbsc_session_id_serialize(const char *id)
{
    if (!id) {
        return NULL;
    }

    int n = snprintf(NULL, 0, "\"%s\"", id);
    char *out = malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    sprintf(out, "\"%s\"", id);
    return out;
}

char *opendbsc_session_skipped_serialize(const OpenDBSC_SkippedEntry *entries,
                                         size_t count)
{
    if (count > 0 && !entries) {
        return NULL;
    }

    int n = 0;
    for (size_t i = 0; i < count; ++i) {
        const char *reason = entries[i].reason ? entries[i].reason : "";
        const char *sid = entries[i].session_id ? entries[i].session_id : "";
        n += snprintf(NULL, 0, "%s", reason);
        if (*sid) {
            n += snprintf(NULL, 0, ";session_identifier=\"%s\"", sid);
        }
        if (i + 1 < count) {
            n += 2; /* ", " */
        }
    }

    char *out = malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }

    char *w = out;
    for (size_t i = 0; i < count; ++i) {
        const char *reason = entries[i].reason ? entries[i].reason : "";
        const char *sid = entries[i].session_id ? entries[i].session_id : "";
        w += sprintf(w, "%s", reason);
        if (*sid) {
            w += sprintf(w, ";session_identifier=\"%s\"", sid);
        }
        if (i + 1 < count) {
            w += sprintf(w, ", ");
        }
    }

    return out;
}

/* --- parsing ------------------------------------------------------------- */

char *opendbsc_parse_session_response(const char *value)
{
    return unquote(value);
}

char *opendbsc_parse_session_id(const char *value)
{
    return unquote(value);
}

/**
 * @brief Test whether a character is valid in a structured-header token.
 */
static int is_token_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' ||
           c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
           c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
           c == '|' || c == '~' || c == ':' || c == '/';
}

/**
 * @brief Test whether a reason token is defined by the DBSC specification.
 */
static int is_valid_skip_reason(const char *reason, size_t len)
{
    static const char *const valid[] = {
        "unreachable", "server_error", "quota_exceeded",
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        if (strlen(valid[i]) == len && strncmp(reason, valid[i], len) == 0) {
            return 1;
        }
    }
    return 0;
}

int opendbsc_parse_session_skipped(const char *value,
                                   OpenDBSC_SkippedEntry **out,
                                   size_t *count)
{
    if (!value || !out || !count) {
        return -1;
    }
    *out = NULL;
    *count = 0;

    OpenDBSC_SkippedEntry *entries = NULL;
    size_t n_entries = 0;
    size_t capacity = 0;

    const char *p = value;
    while (*p) {
        while (is_space(*p) || *p == ',') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        /* Reason token. */
        const char *tok_start = p;
        while (is_token_char(*p)) {
            ++p;
        }
        size_t tok_len = (size_t)(p - tok_start);
        if (tok_len == 0) {
            goto fail;
        }

        /* Parameters: ;key="value" pairs; only session_identifier is used. */
        char *session_id = NULL;
        while (*p == ';') {
            ++p;
            while (is_space(*p)) {
                ++p;
            }
            const char *key_start = p;
            while (is_token_char(*p)) {
                ++p;
            }
            size_t key_len = (size_t)(p - key_start);
            while (is_space(*p)) {
                ++p;
            }
            if (*p != '=') {
                goto fail;
            }
            ++p;
            while (is_space(*p)) {
                ++p;
            }
            if (*p != '"') {
                goto fail;
            }
            ++p;
            const char *val_start = p;
            while (*p && *p != '"') {
                if (*p == '\\' && *(p + 1)) {
                    p += 2;
                } else {
                    ++p;
                }
            }
            if (*p != '"') {
                goto fail;
            }
            size_t val_len = (size_t)(p - val_start);
            ++p;

            if (key_len == strlen("session_identifier") &&
                strncmp(key_start, "session_identifier", key_len) == 0) {
                free(session_id);
                session_id = memdup_str(val_start, val_len);
                if (!session_id) {
                    goto fail;
                }
            }
        }

        /* Keep only spec-defined reasons with a session identifier. */
        if (is_valid_skip_reason(tok_start, tok_len) && session_id != NULL) {
            if (n_entries == capacity) {
                size_t new_capacity = capacity == 0 ? 4 : capacity * 2;
                OpenDBSC_SkippedEntry *tmp =
                    realloc(entries, new_capacity * sizeof(*tmp));
                if (!tmp) {
                    free(session_id);
                    goto fail;
                }
                entries = tmp;
                capacity = new_capacity;
            }
            char *reason = memdup_str(tok_start, tok_len);
            if (!reason) {
                free(session_id);
                goto fail;
            }
            entries[n_entries].reason = reason;
            entries[n_entries].session_id = session_id;
            ++n_entries;
        } else {
            free(session_id);
        }
    }

    *out = entries;
    *count = n_entries;
    return 0;

fail:
    for (size_t i = 0; i < n_entries; ++i) {
        free((void *)entries[i].reason);
        free((void *)entries[i].session_id);
    }
    free(entries);
    return -1;
}
