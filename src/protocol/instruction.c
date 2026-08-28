#include "protocol/instruction.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Duplicate a string into a heap-owned field.
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
 * @brief Grow a dynamic array to make room for one more element.
 *
 * @param array Pointer to the array pointer.
 * @param count Current number of elements in the array.
 * @param capacity Pointer to the current allocated capacity.
 * @param elem_size Size of each element in bytes.
 *
 * @return 0 on success, or -1 if memory allocation failed.
 */
static int grow_array(void **array, size_t count, size_t *capacity, size_t elem_size) {
    if (count < *capacity) {
        return 0;
    }

    size_t new_capacity = *capacity == 0 ? 4 : *capacity * 2;
    void *new_array = realloc(*array, new_capacity * elem_size);
    if (new_array == NULL) {
        return -1;
    }

    *array = new_array;
    *capacity = new_capacity;
    return 0;
}

/**
 * @brief Initialize an instruction to its default state.
 *
 * @param instruction Pointer to the instruction to initialize. May be @c NULL,
 *                    in which case the function does nothing.
 */
void opendbsc_instruction_init(OpenDBSC_SessionInstruction *instruction) {
    if (instruction == NULL) {
        return;
    }

    instruction->session_identifier = NULL;
    instruction->refresh_url = NULL;
    instruction->continue_session = 1;
    instruction->has_continue = 0;
    opendbsc_scope_init(&instruction->scope);
    instruction->credentials = NULL;
    instruction->credentials_count = 0;
    instruction->credentials_capacity = 0;
    instruction->allowed_refresh_initiators = NULL;
    instruction->allowed_refresh_initiators_count = 0;
    instruction->allowed_refresh_initiators_capacity = 0;
}

/**
 * @brief Release all resources owned by an instruction and reset it.
 *
 * @param instruction Pointer to the instruction to free. May be @c NULL,
 *                    in which case the function does nothing.
 */
void opendbsc_instruction_free(OpenDBSC_SessionInstruction *instruction) {
    if (instruction == NULL) {
        return;
    }

    free(instruction->session_identifier);
    free(instruction->refresh_url);

    for (size_t i = 0; i < instruction->credentials_count; i++) {
        opendbsc_credential_free(&instruction->credentials[i]);
    }
    free(instruction->credentials);

    for (size_t i = 0; i < instruction->allowed_refresh_initiators_count; i++) {
        free(instruction->allowed_refresh_initiators[i]);
    }
    free(instruction->allowed_refresh_initiators);

    opendbsc_scope_free(&instruction->scope);
    opendbsc_instruction_init(instruction);
}

/**
 * @brief Set the session identifier of an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param session_identifier Null-terminated identifier, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p instruction is @c NULL or allocation failed.
 */
int opendbsc_instruction_set_session_identifier(OpenDBSC_SessionInstruction *instruction,
                                                const char *session_identifier) {
    if (instruction == NULL) {
        return -1;
    }
    return set_string(&instruction->session_identifier, session_identifier);
}

/**
 * @brief Set the refresh URL of an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param refresh_url Null-terminated URL, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p instruction is @c NULL or allocation failed.
 */
int opendbsc_instruction_set_refresh_url(OpenDBSC_SessionInstruction *instruction,
                                         const char *refresh_url) {
    if (instruction == NULL) {
        return -1;
    }
    return set_string(&instruction->refresh_url, refresh_url);
}

/**
 * @brief Set the continue_session flag of an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param continue_session Non-zero to continue the session, zero otherwise.
 */
void opendbsc_instruction_set_continue_session(OpenDBSC_SessionInstruction *instruction,
                                               int continue_session) {
    if (instruction == NULL) {
        return;
    }

    instruction->continue_session = continue_session ? 1 : 0;
    instruction->has_continue = 1;
}

/**
 * @brief Set the continue flag of an instruction (spec spelling).
 */
void opendbsc_instruction_set_continue(OpenDBSC_SessionInstruction *instruction,
                                       bool continue_session) {
    opendbsc_instruction_set_continue_session(instruction, continue_session ? 1 : 0);
}

/**
 * @brief Add an origin to the allowed_refresh_initiators list.
 */
int opendbsc_instruction_add_refresh_initiator(OpenDBSC_SessionInstruction *instruction,
                                               const char *origin) {
    if (instruction == NULL || origin == NULL) {
        return -1;
    }

    if (grow_array((void **)&instruction->allowed_refresh_initiators,
                   instruction->allowed_refresh_initiators_count,
                   &instruction->allowed_refresh_initiators_capacity,
                   sizeof(char *)) != 0) {
        return -1;
    }

    char *copy = strdup(origin);
    if (copy == NULL) {
        return -1;
    }

    instruction->allowed_refresh_initiators[
        instruction->allowed_refresh_initiators_count++] = copy;
    return 0;
}

/**
 * @brief Add a credential to an instruction.
 *
 * @param instruction Pointer to the instruction.
 * @param credential Pointer to the credential to copy.
 *
 * @return 0 on success, or -1 if @p instruction or @p credential is @c NULL
 *         or allocation failed.
 */
int opendbsc_instruction_add_credential(OpenDBSC_SessionInstruction *instruction,
                                        const OpenDBSC_SessionCredential *credential) {
    if (instruction == NULL || credential == NULL) {
        return -1;
    }

    if (grow_array((void **)&instruction->credentials,
                   instruction->credentials_count,
                   &instruction->credentials_capacity,
                   sizeof(OpenDBSC_SessionCredential)) != 0) {
        return -1;
    }

    OpenDBSC_SessionCredential *dst = &instruction->credentials[instruction->credentials_count];
    opendbsc_credential_init(dst);

    if (opendbsc_credential_set_type(dst, credential->type) != 0) {
        goto fail;
    }
    if (opendbsc_credential_set_name(dst, credential->name) != 0) {
        goto fail;
    }
    if (opendbsc_credential_set_attributes(dst, credential->attributes) != 0) {
        goto fail;
    }

    instruction->credentials_count++;
    return 0;

fail:
    opendbsc_credential_free(dst);
    return -1;
}

/**
 * @brief Initialize a scope to its default state.
 *
 * @param scope Pointer to the scope to initialize. May be @c NULL,
 *              in which case the function does nothing.
 */
void opendbsc_scope_init(OpenDBSC_SessionScope *scope) {
    if (scope == NULL) {
        return;
    }

    scope->origin = NULL;
    scope->include_site = 0;
    scope->specification = NULL;
    scope->specification_count = 0;
    scope->specification_capacity = 0;
}

/**
 * @brief Release all resources owned by a scope and reset it.
 *
 * @param scope Pointer to the scope to free. May be @c NULL,
 *              in which case the function does nothing.
 */
void opendbsc_scope_free(OpenDBSC_SessionScope *scope) {
    if (scope == NULL) {
        return;
    }

    free(scope->origin);

    for (size_t i = 0; i < scope->specification_count; i++) {
        opendbsc_rule_free(&scope->specification[i]);
    }
    free(scope->specification);

    opendbsc_scope_init(scope);
}

/**
 * @brief Set the origin of a scope.
 *
 * @param scope Pointer to the scope.
 * @param origin Null-terminated origin, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p scope is @c NULL or allocation failed.
 */
int opendbsc_scope_set_origin(OpenDBSC_SessionScope *scope, const char *origin) {
    if (scope == NULL) {
        return -1;
    }
    return set_string(&scope->origin, origin);
}

/**
 * @brief Set the include_site flag of a scope.
 *
 * @param scope Pointer to the scope.
 * @param include_site Non-zero to include the site, zero otherwise.
 */
void opendbsc_scope_set_include_site(OpenDBSC_SessionScope *scope, int include_site) {
    if (scope == NULL) {
        return;
    }

    scope->include_site = include_site ? 1 : 0;
}

/**
 * @brief Add a rule to a scope.
 *
 * @param scope Pointer to the scope.
 * @param rule Pointer to the rule to copy.
 *
 * @return 0 on success, or -1 if @p scope or @p rule is @c NULL
 *         or allocation failed.
 */
int opendbsc_scope_add_rule(OpenDBSC_SessionScope *scope,
                            const OpenDBSC_ScopeRule *rule) {
    if (scope == NULL || rule == NULL) {
        return -1;
    }

    if (grow_array((void **)&scope->specification,
                   scope->specification_count,
                   &scope->specification_capacity,
                   sizeof(OpenDBSC_ScopeRule)) != 0) {
        return -1;
    }

    OpenDBSC_ScopeRule *dst = &scope->specification[scope->specification_count];
    opendbsc_rule_init(dst);

    if (opendbsc_rule_set_type(dst, rule->type) != 0) {
        goto fail;
    }
    if (opendbsc_rule_set_domain(dst, rule->domain) != 0) {
        goto fail;
    }
    if (opendbsc_rule_set_path(dst, rule->path) != 0) {
        goto fail;
    }

    scope->specification_count++;
    return 0;

fail:
    opendbsc_rule_free(dst);
    return -1;
}

/**
 * @brief Initialize a scope rule to its default state.
 *
 * @param rule Pointer to the rule to initialize. May be @c NULL,
 *             in which case the function does nothing.
 */
void opendbsc_rule_init(OpenDBSC_ScopeRule *rule) {
    if (rule == NULL) {
        return;
    }

    rule->type = NULL;
    rule->domain = NULL;
    rule->path = NULL;
}

/**
 * @brief Release all resources owned by a scope rule and reset it.
 *
 * @param rule Pointer to the rule to free. May be @c NULL,
 *             in which case the function does nothing.
 */
void opendbsc_rule_free(OpenDBSC_ScopeRule *rule) {
    if (rule == NULL) {
        return;
    }

    free(rule->type);
    free(rule->domain);
    free(rule->path);
    opendbsc_rule_init(rule);
}

/**
 * @brief Set the type of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param type Null-terminated type, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_type(OpenDBSC_ScopeRule *rule, const char *type) {
    if (rule == NULL) {
        return -1;
    }
    return set_string(&rule->type, type);
}

/**
 * @brief Set the domain of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param domain Null-terminated domain, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_domain(OpenDBSC_ScopeRule *rule, const char *domain) {
    if (rule == NULL) {
        return -1;
    }
    return set_string(&rule->domain, domain);
}

/**
 * @brief Set the path of a scope rule.
 *
 * @param rule Pointer to the rule.
 * @param path Null-terminated path, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p rule is @c NULL or allocation failed.
 */
int opendbsc_rule_set_path(OpenDBSC_ScopeRule *rule, const char *path) {
    if (rule == NULL) {
        return -1;
    }
    return set_string(&rule->path, path);
}

/**
 * @brief Initialize a credential to its default state.
 *
 * @param credential Pointer to the credential to initialize. May be @c NULL,
 *                   in which case the function does nothing.
 */
void opendbsc_credential_init(OpenDBSC_SessionCredential *credential) {
    if (credential == NULL) {
        return;
    }

    credential->type = NULL;
    credential->name = NULL;
    credential->attributes = NULL;
}

/**
 * @brief Release all resources owned by a credential and reset it.
 *
 * @param credential Pointer to the credential to free. May be @c NULL,
 *                   in which case the function does nothing.
 */
void opendbsc_credential_free(OpenDBSC_SessionCredential *credential) {
    if (credential == NULL) {
        return;
    }

    free(credential->type);
    free(credential->name);
    free(credential->attributes);

    opendbsc_credential_init(credential);
}

/**
 * @brief Set the type of a credential.
 *
 * @param credential Pointer to the credential.
 * @param type Null-terminated type, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p credential is @c NULL or allocation failed.
 */
int opendbsc_credential_set_type(OpenDBSC_SessionCredential *credential,
                                 const char *type) {
    if (credential == NULL) {
        return -1;
    }
    return set_string(&credential->type, type);
}

/**
 * @brief Set the name of a credential.
 *
 * @param credential Pointer to the credential.
 * @param name Null-terminated name, or @c NULL to clear.
 *
 * @return 0 on success, or -1 if @p credential is @c NULL or allocation failed.
 */
int opendbsc_credential_set_name(OpenDBSC_SessionCredential *credential,
                                 const char *name) {
    if (credential == NULL) {
        return -1;
    }
    return set_string(&credential->name, name);
}

/**
 * @brief Add an attribute to a credential.
 *
 * @param credential Pointer to the credential.
 * @param attribute Null-terminated attribute string.
 *
 * @return 0 on success, or -1 if @p credential or @p attribute is @c NULL
 *         or allocation failed.
 */
int opendbsc_credential_set_attributes(OpenDBSC_SessionCredential *credential,
                                       const char *attributes) {
    if (credential == NULL) {
        return -1;
    }
    return set_string(&credential->attributes, attributes);
}

/**
 * @brief Convert a scope rule to a cJSON object.
 *
 * @param rule Pointer to the rule to convert.
 *
 * @return A cJSON object on success, or @c NULL if @p rule is @c NULL
 *         or allocation failed.
 */
static cJSON *scope_rule_to_json(const OpenDBSC_ScopeRule *rule) {
    if (rule == NULL) {
        return NULL;
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }

    if (rule->type != NULL && cJSON_AddStringToObject(obj, "type", rule->type) == NULL) {
        goto fail;
    }
    if (rule->domain != NULL && cJSON_AddStringToObject(obj, "domain", rule->domain) == NULL) {
        goto fail;
    }
    if (rule->path != NULL && cJSON_AddStringToObject(obj, "path", rule->path) == NULL) {
        goto fail;
    }

    return obj;

fail:
    cJSON_Delete(obj);
    return NULL;
}

/**
 * @brief Convert a scope to a cJSON object.
 *
 * @param scope Pointer to the scope to convert.
 *
 * @return A cJSON object on success, or @c NULL if @p scope is @c NULL
 *         or allocation failed.
 */
static cJSON *scope_to_json(const OpenDBSC_SessionScope *scope) {
    if (scope == NULL) {
        return NULL;
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }

    if (scope->origin != NULL &&
        cJSON_AddStringToObject(obj, "origin", scope->origin) == NULL) {
        goto fail;
    }
    if (cJSON_AddBoolToObject(obj, "include_site", scope->include_site ? 1 : 0) == NULL) {
        goto fail;
    }

    cJSON *spec = cJSON_CreateArray();
    if (spec == NULL) {
        goto fail;
    }

    for (size_t i = 0; i < scope->specification_count; i++) {
        cJSON *rule = scope_rule_to_json(&scope->specification[i]);
        if (rule == NULL || !cJSON_AddItemToArray(spec, rule)) {
            cJSON_Delete(rule);
            goto fail_spec;
        }
    }

    if (!cJSON_AddItemToObject(obj, "scope_specification", spec)) {
        goto fail_spec;
    }

    return obj;

fail_spec:
    cJSON_Delete(spec);
fail:
    cJSON_Delete(obj);
    return NULL;
}

/**
 * @brief Convert a credential to a cJSON object.
 *
 * @param credential Pointer to the credential to convert.
 *
 * @return A cJSON object on success, or @c NULL if @p credential is @c NULL
 *         or allocation failed.
 */
static cJSON *credential_to_json(const OpenDBSC_SessionCredential *credential) {
    if (credential == NULL) {
        return NULL;
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }

    if (credential->type != NULL &&
        cJSON_AddStringToObject(obj, "type", credential->type) == NULL) {
        goto fail;
    }
    if (credential->name != NULL &&
        cJSON_AddStringToObject(obj, "name", credential->name) == NULL) {
        goto fail;
    }
    if (credential->attributes != NULL &&
        cJSON_AddStringToObject(obj, "attributes", credential->attributes) == NULL) {
        goto fail;
    }

    return obj;

fail:
    cJSON_Delete(obj);
    return NULL;
}

/**
 * @brief Convert an instruction to a cJSON object.
 *
 * @param instruction Pointer to the instruction to convert.
 *
 * @return A cJSON object on success, or @c NULL if @p instruction is @c NULL
 *         or allocation failed.
 */
cJSON *opendbsc_instruction_to_json(const OpenDBSC_SessionInstruction *instruction) {
    if (instruction == NULL) {
        return NULL;
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return NULL;
    }

    /* When continue is false, all other keys may be omitted (spec 9.6). */
    if (instruction->has_continue && !instruction->continue_session) {
        if (cJSON_AddBoolToObject(obj, "continue", 0) == NULL) {
            goto fail;
        }
        return obj;
    }

    if (instruction->session_identifier != NULL &&
        cJSON_AddStringToObject(obj, "session_identifier", instruction->session_identifier) == NULL) {
        goto fail;
    }
    if (instruction->refresh_url != NULL &&
        cJSON_AddStringToObject(obj, "refresh_url", instruction->refresh_url) == NULL) {
        goto fail;
    }
    if (instruction->has_continue &&
        cJSON_AddBoolToObject(obj, "continue", instruction->continue_session ? 1 : 0) == NULL) {
        goto fail;
    }

    if (instruction->allowed_refresh_initiators_count > 0) {
        cJSON *initiators = cJSON_CreateArray();
        if (initiators == NULL) {
            goto fail;
        }
        for (size_t i = 0; i < instruction->allowed_refresh_initiators_count; i++) {
            cJSON *origin =
                cJSON_CreateString(instruction->allowed_refresh_initiators[i]);
            if (origin == NULL || !cJSON_AddItemToArray(initiators, origin)) {
                cJSON_Delete(origin);
                cJSON_Delete(initiators);
                goto fail;
            }
        }
        if (!cJSON_AddItemToObject(obj, "allowed_refresh_initiators", initiators)) {
            cJSON_Delete(initiators);
            goto fail;
        }
    }

    cJSON *scope = scope_to_json(&instruction->scope);
    if (scope == NULL || !cJSON_AddItemToObject(obj, "scope", scope)) {
        cJSON_Delete(scope);
        goto fail;
    }

    cJSON *creds = cJSON_CreateArray();
    if (creds == NULL) {
        goto fail;
    }

    for (size_t i = 0; i < instruction->credentials_count; i++) {
        cJSON *cred = credential_to_json(&instruction->credentials[i]);
        if (cred == NULL || !cJSON_AddItemToArray(creds, cred)) {
            cJSON_Delete(cred);
            goto fail_creds;
        }
    }

    if (!cJSON_AddItemToObject(obj, "credentials", creds)) {
        goto fail_creds;
    }

    return obj;

fail_creds:
    cJSON_Delete(creds);
fail:
    cJSON_Delete(obj);
    return NULL;
}

/**
 * @brief Convert an instruction to a formatted JSON string.
 *
 * @param instruction Pointer to the instruction to convert.
 *
 * @return A heap-allocated JSON string on success, or @c NULL if
 *         @p instruction is @c NULL or allocation failed.
 */
char *opendbsc_instruction_to_string(const OpenDBSC_SessionInstruction *instruction) {
    cJSON *json = opendbsc_instruction_to_json(instruction);
    if (json == NULL) {
        return NULL;
    }

    char *str = cJSON_Print(json);
    cJSON_Delete(json);
    return str;
}
