#ifndef OPENDBSC_INSTRUCTION_H
#define OPENDBSC_INSTRUCTION_H

#include <stdbool.h>
#include <stddef.h>

#include <cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file protocol/instruction.h
 * @brief OpenDBSC session instruction types and JSON serialization.
 */

/**
 * @brief A single scope rule in a session instruction.
 */
typedef struct {
    char *type;   /**< Rule type, e.g. "include" or "exclude". */
    char *domain; /**< Domain pattern the rule applies to. */
    char *path;   /**< Path pattern the rule applies to. */
} OpenDBSC_ScopeRule;

/**
 * @brief Scope of a session instruction.
 */
typedef struct {
    char *origin;              /**< Origin the scope applies to. */
    int include_site;          /**< Whether the scope includes subdomains. */
    OpenDBSC_ScopeRule *specification; /**< Array of scope rules. */
    size_t specification_count;        /**< Number of rules in @p specification. */
    size_t specification_capacity;     /**< Allocated capacity of @p specification. */
} OpenDBSC_SessionScope;

/**
 * @brief A credential requested by a session instruction.
 */
typedef struct {
    char *type;       /**< Credential type, e.g. "cookie". */
    char *name;       /**< Credential name. */
    char *attributes; /**< Cookie attribute string, e.g. "Path=/; Secure". */
} OpenDBSC_SessionCredential;

/**
 * @brief An OpenDBSC session instruction.
 *
 * The @p scope field is embedded in the instruction and is initialized and
 * freed by opendbsc_instruction_init() and opendbsc_instruction_free().
 * String fields and array contents are heap-owned.
 */
typedef struct {
    char *session_identifier; /**< Session identifier. */
    char *refresh_url;        /**< URL used to refresh the session. */
    int continue_session;     /**< Value of the continue flag (default true). */
    int has_continue;         /**< Whether @p continue_session is set. */
    OpenDBSC_SessionScope scope; /**< Scope of the instruction. */
    OpenDBSC_SessionCredential *credentials; /**< Array of requested credentials. */
    size_t credentials_count;    /**< Number of credentials. */
    size_t credentials_capacity; /**< Allocated capacity of @p credentials. */
    char **allowed_refresh_initiators; /**< Origins allowed to trigger refreshes. */
    size_t allowed_refresh_initiators_count;    /**< Number of initiator origins. */
    size_t allowed_refresh_initiators_capacity; /**< Allocated capacity. */
} OpenDBSC_SessionInstruction;

/**
 * @brief Initialize an instruction to its default state.
 *
 * @param instruction Pointer to the instruction to initialize. May be @c NULL.
 */
void opendbsc_instruction_init(OpenDBSC_SessionInstruction *instruction);

/**
 * @brief Release all resources owned by an instruction and reset it.
 *
 * @param instruction Pointer to the instruction to free. May be @c NULL.
 */
void opendbsc_instruction_free(OpenDBSC_SessionInstruction *instruction);

/**
 * @brief Set the session identifier of an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param session_identifier Null-terminated identifier, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p instruction is @c NULL or allocation failed.
 */
int opendbsc_instruction_set_session_identifier(OpenDBSC_SessionInstruction *instruction,
                                                const char *session_identifier);

/**
 * @brief Set the refresh URL of an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param refresh_url Null-terminated URL, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p instruction is @c NULL or allocation failed.
 */
int opendbsc_instruction_set_refresh_url(OpenDBSC_SessionInstruction *instruction,
                                         const char *refresh_url);

/**
 * @brief Set the continue_session flag of an instruction.
 *
 * This also marks the field as present so it will be serialized.
 *
 * @param instruction Pointer to the instruction.
 * @param continue_session Non-zero to continue the session, zero otherwise.
 */
void opendbsc_instruction_set_continue_session(OpenDBSC_SessionInstruction *instruction,
                                               int continue_session);

/**
 * @brief Set the continue flag of an instruction (spec spelling).
 *
 * Defaults to true. When set to false, serialization omits
 * session_identifier, scope, and credentials and emits only
 * @c "continue": false, as allowed by the DBSC specification.
 *
 * @param instruction Pointer to the instruction.
 * @param continue_session true to continue the session, false otherwise.
 */
void opendbsc_instruction_set_continue(OpenDBSC_SessionInstruction *instruction,
                                       bool continue_session);

/**
 * @brief Add an origin to the allowed_refresh_initiators list.
 *
 * The origin is copied into the instruction's internal array. When the list
 * is non-empty it is serialized as @c "allowed_refresh_initiators": [...].
 *
 * @param instruction Pointer to the instruction.
 * @param origin Null-terminated initiator origin.
 *
 * @return 0 on success, or -1 if @p instruction or @p origin is @c NULL
 *         or allocation failed.
 */
int opendbsc_instruction_add_refresh_initiator(OpenDBSC_SessionInstruction *instruction,
                                               const char *origin);

/**
 * @brief Add a credential to an instruction.
 *
 * The credential is copied into the instruction's internal array.
 *
 * @param instruction Pointer to the instruction.
 * @param credential Pointer to the credential to copy.
 *
 * @return 0 on success, or -1 if @p instruction or @p credential is @c NULL
 *         or allocation failed.
 */
int opendbsc_instruction_add_credential(OpenDBSC_SessionInstruction *instruction,
                                        const OpenDBSC_SessionCredential *credential);

/**
 * @brief Initialize a scope to its default state.
 *
 * @param scope Pointer to the scope to initialize. May be @c NULL.
 */
void opendbsc_scope_init(OpenDBSC_SessionScope *scope);

/**
 * @brief Release all resources owned by a scope and reset it.
 *
 * @param scope Pointer to the scope to free. May be @c NULL.
 */
void opendbsc_scope_free(OpenDBSC_SessionScope *scope);

/**
 * @brief Set the origin of a scope.
 *
 * @param scope Pointer to the scope.
 * @param origin Null-terminated origin, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p scope is @c NULL or allocation failed.
 */
int opendbsc_scope_set_origin(OpenDBSC_SessionScope *scope, const char *origin);

/**
 * @brief Set the include_site flag of a scope.
 *
 * @param scope Pointer to the scope.
 * @param include_site Non-zero to include the site, zero otherwise.
 */
void opendbsc_scope_set_include_site(OpenDBSC_SessionScope *scope, int include_site);

/**
 * @brief Add a rule to a scope.
 *
 * The rule is copied into the scope's internal array.
 *
 * @param scope Pointer to the scope.
 * @param rule Pointer to the rule to copy.
 *
 * @return 0 on success, or -1 if @p scope or @p rule is @c NULL
 *         or allocation failed.
 */
int opendbsc_scope_add_rule(OpenDBSC_SessionScope *scope,
                            const OpenDBSC_ScopeRule *rule);

/**
 * @brief Initialize a scope rule to its default state.
 *
 * @param rule Pointer to the rule to initialize. May be @c NULL.
 */
void opendbsc_rule_init(OpenDBSC_ScopeRule *rule);

/**
 * @brief Release all resources owned by a scope rule and reset it.
 *
 * @param rule Pointer to the rule to free. May be @c NULL.
 */
void opendbsc_rule_free(OpenDBSC_ScopeRule *rule);

/**
 * @brief Set the type of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param type Null-terminated type, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_type(OpenDBSC_ScopeRule *rule, const char *type);

/**
 * @brief Set the domain of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param domain Null-terminated domain, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_domain(OpenDBSC_ScopeRule *rule, const char *domain);

/**
 * @brief Set the path of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param path Null-terminated path, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_path(OpenDBSC_ScopeRule *rule, const char *path);

/**
 * @brief Initialize a credential to its default state.
 *
 * @param credential Pointer to the credential to initialize. May be @c NULL.
 */
void opendbsc_credential_init(OpenDBSC_SessionCredential *credential);

/**
 * @brief Release all resources owned by a credential and reset it.
 *
 * @param credential Pointer to the credential to free. May be @c NULL.
 */
void opendbsc_credential_free(OpenDBSC_SessionCredential *credential);

/**
 * @brief Set the type of a credential.
 *
 * @param credential Pointer to the credential.
 * @param type Null-terminated type, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p credential is @c NULL or allocation failed.
 */
int opendbsc_credential_set_type(OpenDBSC_SessionCredential *credential,
                                 const char *type);

/**
 * @brief Set the name of a credential.
 *
 * @param credential Pointer to the credential.
 * @param name Null-terminated name, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p credential is @c NULL or allocation failed.
 */
int opendbsc_credential_set_name(OpenDBSC_SessionCredential *credential,
                                 const char *name);

/**
 * @brief Set the attributes string of a credential.
 *
 * @param credential Pointer to the credential.
 * @param attributes Null-terminated attribute string, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p credential is @c NULL or allocation failed.
 */
int opendbsc_credential_set_attributes(OpenDBSC_SessionCredential *credential,
                                       const char *attributes);

/**
 * @brief Convert an instruction to a cJSON object.
 *
 * The returned cJSON object is owned by the caller and must be released with
 * cJSON_Delete().
 *
 * @param instruction Pointer to the instruction to convert.
 *
 * @return A cJSON object on success, or @c NULL if @p instruction is @c NULL
 *         or allocation failed.
 */
cJSON *opendbsc_instruction_to_json(const OpenDBSC_SessionInstruction *instruction);

/**
 * @brief Convert an instruction to a formatted JSON string.
 *
 * The returned string is allocated with malloc() and must be freed by the
 * caller.
 *
 * @param instruction Pointer to the instruction to convert.
 *
 * @return A heap-allocated JSON string on success, or @c NULL if
 *         @p instruction is @c NULL or allocation failed.
 */
char *opendbsc_instruction_to_string(const OpenDBSC_SessionInstruction *instruction);

#ifdef __cplusplus
}
#endif

#endif
