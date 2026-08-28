#include "protocol/jwt.h"

#include <cJSON.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @file protocol/jwt.c
 * @brief DBSC proof JWT decoding and signature verification.
 */

/**
 * @brief Standard base64url alphabet.
 */
static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @brief Decode a single base64url digit.
 *
 * @return The digit value, or -1 for invalid characters.
 */
static int b64url_digit(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

/**
 * @brief Base64url decode a string.
 */
int opendbsc_base64url_decode(const char *in, unsigned char **out, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    size_t len = strlen(in);
    if (len == 0) {
        return -1;
    }

    /* Add padding copy so classic base64 decoding works. */
    size_t padded_len = len;
    size_t pad = (4 - (len % 4)) % 4;
    padded_len += pad;

    char *padded = malloc(padded_len + 1);
    if (padded == NULL) {
        return -1;
    }
    memcpy(padded, in, len);
    for (size_t i = 0; i < pad; i++) {
        padded[len + i] = '=';
    }
    padded[padded_len] = '\0';

    /* Convert base64url alphabet to standard base64. */
    for (size_t i = 0; i < len; i++) {
        if (padded[i] == '-') padded[i] = '+';
        else if (padded[i] == '_') padded[i] = '/';
    }

    size_t decoded_max = (padded_len / 4) * 3;
    unsigned char *decoded = malloc(decoded_max);
    if (decoded == NULL) {
        free(padded);
        return -1;
    }

    size_t decoded_len = 0;
    for (size_t i = 0; i < padded_len; i += 4) {
        int d0 = b64url_digit(padded[i]);
        int d1 = b64url_digit(padded[i + 1]);
        int d2 = (padded[i + 2] == '=') ? 0 : b64url_digit(padded[i + 2]);
        int d3 = (padded[i + 3] == '=') ? 0 : b64url_digit(padded[i + 3]);
        if (d0 < 0 || d1 < 0 || (padded[i + 2] != '=' && d2 < 0) ||
            (padded[i + 3] != '=' && d3 < 0)) {
            free(padded);
            free(decoded);
            return -1;
        }
        decoded[decoded_len++] = (unsigned char)((d0 << 2) | (d1 >> 4));
        if (padded[i + 2] != '=') {
            decoded[decoded_len++] = (unsigned char)(((d1 & 0x0f) << 4) | (d2 >> 2));
        }
        if (padded[i + 3] != '=') {
            decoded[decoded_len++] = (unsigned char)(((d2 & 0x03) << 6) | d3);
        }
    }

    free(padded);
    *out = decoded;
    *out_len = decoded_len;
    return 0;
}

/**
 * @brief Base64url encode a buffer.
 */
char *opendbsc_base64url_encode(const unsigned char *in, size_t in_len) {
    if (in == NULL || in_len == 0) {
        return NULL;
    }
    size_t out_len = ((in_len + 2) / 3) * 4;
    char *out = malloc(out_len + 1);
    if (out == NULL) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        unsigned int b = in[i] << 16;
        if (i + 1 < in_len) b |= in[i + 1] << 8;
        if (i + 2 < in_len) b |= in[i + 2];
        out[j++] = b64url_table[(b >> 18) & 0x3f];
        out[j++] = b64url_table[(b >> 12) & 0x3f];
        out[j++] = (i + 1 < in_len) ? b64url_table[(b >> 6) & 0x3f] : '\0';
        out[j++] = (i + 2 < in_len) ? b64url_table[b & 0x3f] : '\0';
    }
    out[j] = '\0';

    /* Trim padding zeros. */
    while (j > 0 && out[j - 1] == '\0') {
        j--;
    }
    out[j] = '\0';
    return out;
}

/**
 * @brief Split a JWT into its three base64url parts.
 *
 * @return 0 on success, or -1 if the format is invalid. The returned pointers
 *         are offsets into @p token and must not be freed.
 */
static int split_jwt(const char *token, const char **header, const char **payload,
                     const char **signature) {
    if (token == NULL || header == NULL || payload == NULL || signature == NULL) {
        return -1;
    }

    const char *first = strchr(token, '.');
    if (first == NULL) {
        return -1;
    }
    const char *second = strchr(first + 1, '.');
    if (second == NULL) {
        return -1;
    }
    if (strchr(second + 1, '.') != NULL) {
        return -1;
    }

    *header = token;
    *payload = first + 1;
    *signature = second + 1;
    return 0;
}

/**
 * @brief Duplicate a substring.
 */
static char *strndup_null(const char *s, size_t n) {
    if (s == NULL) {
        return NULL;
    }
    char *copy = malloc(n + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, n);
    copy[n] = '\0';
    return copy;
}

/**
 * @brief Initialize a proof JWT structure.
 */
void opendbsc_proof_jwt_init(OpenDBSC_ProofJWT *proof) {
    if (proof == NULL) {
        return;
    }
    proof->algorithm = NULL;
    proof->type = NULL;
    proof->jwk = NULL;
    proof->challenge = NULL;
    proof->authorization = NULL;
    proof->signature = NULL;
}

/**
 * @brief Release all resources owned by a proof JWT structure.
 */
void opendbsc_proof_jwt_free(OpenDBSC_ProofJWT *proof) {
    if (proof == NULL) {
        return;
    }
    free(proof->algorithm);
    free(proof->type);
    free(proof->jwk);
    free(proof->challenge);
    free(proof->authorization);
    free(proof->signature);
    opendbsc_proof_jwt_init(proof);
}

/**
 * @brief Parse a JSON object into a proof JWT structure.
 *
 * @param header_json Decoded header JSON bytes.
 * @param payload_json Decoded payload JSON bytes.
 * @param signature_raw Raw signature string from the JWT (base64url).
 * @param proof Output structure.
 *
 * @return 0 on success, or -1 on error.
 */
static int parse_proof(const unsigned char *header_json, size_t header_len,
                       const unsigned char *payload_json, size_t payload_len,
                       const char *signature_raw, OpenDBSC_ProofJWT *proof) {
    cJSON *header = cJSON_ParseWithLength((const char *)header_json, header_len);
    if (header == NULL) {
        return -1;
    }
    cJSON *payload = cJSON_ParseWithLength((const char *)payload_json, payload_len);
    if (payload == NULL) {
        cJSON_Delete(header);
        return -1;
    }

    opendbsc_proof_jwt_init(proof);

    cJSON *alg = cJSON_GetObjectItemCaseSensitive(header, "alg");
    cJSON *typ = cJSON_GetObjectItemCaseSensitive(header, "typ");
    cJSON *jwk = cJSON_GetObjectItemCaseSensitive(header, "jwk");
    cJSON *jti = cJSON_GetObjectItemCaseSensitive(payload, "jti");
    cJSON *authorization = cJSON_GetObjectItemCaseSensitive(payload, "authorization");

    if (cJSON_IsString(alg)) {
        proof->algorithm = strdup(alg->valuestring);
    }
    if (cJSON_IsString(typ)) {
        proof->type = strdup(typ->valuestring);
    }
    if (cJSON_IsObject(jwk)) {
        proof->jwk = cJSON_PrintUnformatted(jwk);
    }
    if (cJSON_IsString(jti)) {
        proof->challenge = strdup(jti->valuestring);
    }
    if (cJSON_IsString(authorization)) {
        proof->authorization = strdup(authorization->valuestring);
    }
    if (signature_raw != NULL) {
        proof->signature = strdup(signature_raw);
    }

    cJSON_Delete(header);
    cJSON_Delete(payload);

    if (proof->algorithm == NULL || proof->challenge == NULL) {
        opendbsc_proof_jwt_free(proof);
        return -1;
    }
    return 0;
}

/**
 * @brief Decode a DBSC proof JWT without verifying its signature.
 */
int opendbsc_jwt_decode(const char *token, OpenDBSC_ProofJWT *proof) {
    if (token == NULL || proof == NULL) {
        return -1;
    }

    const char *h_start, *p_start, *s_start;
    if (split_jwt(token, &h_start, &p_start, &s_start) != 0) {
        return -1;
    }

    size_t h_len = (size_t)(p_start - h_start - 1);
    size_t p_len = (size_t)(s_start - p_start - 1);
    size_t s_len = strlen(s_start);

    char *header_b64 = strndup_null(h_start, h_len);
    char *payload_b64 = strndup_null(p_start, p_len);
    char *sig_copy = strndup_null(s_start, s_len);
    if (header_b64 == NULL || payload_b64 == NULL || sig_copy == NULL) {
        free(header_b64);
        free(payload_b64);
        free(sig_copy);
        return -1;
    }

    unsigned char *header_json = NULL;
    size_t header_len = 0;
    unsigned char *payload_json = NULL;
    size_t payload_len = 0;

    if (opendbsc_base64url_decode(header_b64, &header_json, &header_len) != 0) {
        free(header_b64);
        free(payload_b64);
        free(sig_copy);
        return -1;
    }
    if (opendbsc_base64url_decode(payload_b64, &payload_json, &payload_len) != 0) {
        free(header_json);
        free(header_b64);
        free(payload_b64);
        free(sig_copy);
        return -1;
    }

    int rc = parse_proof(header_json, header_len, payload_json, payload_len,
                         sig_copy, proof);

    free(header_json);
    free(payload_json);
    free(header_b64);
    free(payload_b64);
    free(sig_copy);
    return rc;
}

/**
 * @brief Extract a base64url-decoded JWK field.
 *
 * @return 0 on success, or -1 if the field is missing or invalid.
 */
static int jwk_get_b64(cJSON *jwk, const char *key, unsigned char **out,
                       size_t *out_len) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(jwk, key);
    if (!cJSON_IsString(item)) {
        return -1;
    }
    return opendbsc_base64url_decode(item->valuestring, out, out_len);
}

/**
 * @brief Create an EVP_PKEY from an EC JWK (P-256).
 *
 * @return A new EVP_PKEY on success, or @c NULL on error.
 */
static EVP_PKEY *evp_pkey_from_ec_jwk(cJSON *jwk) {
    unsigned char *x = NULL;
    size_t x_len = 0;
    unsigned char *y = NULL;
    size_t y_len = 0;

    if (jwk_get_b64(jwk, "x", &x, &x_len) != 0 ||
        jwk_get_b64(jwk, "y", &y, &y_len) != 0) {
        free(x);
        free(y);
        return NULL;
    }

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec == NULL) {
        free(x);
        free(y);
        return NULL;
    }

    BIGNUM *bx = BN_bin2bn(x, (int)x_len, NULL);
    BIGNUM *by = BN_bin2bn(y, (int)y_len, NULL);
    free(x);
    free(y);

    if (bx == NULL || by == NULL) {
        BN_free(bx);
        BN_free(by);
        EC_KEY_free(ec);
        return NULL;
    }

    if (EC_KEY_set_public_key_affine_coordinates(ec, bx, by) != 1) {
        BN_free(bx);
        BN_free(by);
        EC_KEY_free(ec);
        return NULL;
    }

    BN_free(bx);
    BN_free(by);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

/**
 * @brief Create an EVP_PKEY from an RSA JWK.
 *
 * @return A new EVP_PKEY on success, or @c NULL on error.
 */
static EVP_PKEY *evp_pkey_from_rsa_jwk(cJSON *jwk) {
    unsigned char *n = NULL;
    size_t n_len = 0;
    unsigned char *e = NULL;
    size_t e_len = 0;

    if (jwk_get_b64(jwk, "n", &n, &n_len) != 0 ||
        jwk_get_b64(jwk, "e", &e, &e_len) != 0) {
        free(n);
        free(e);
        return NULL;
    }

    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        free(n);
        free(e);
        return NULL;
    }

    BIGNUM *bn_n = BN_bin2bn(n, (int)n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e, (int)e_len, NULL);
    free(n);
    free(e);

    if (bn_n == NULL || bn_e == NULL || RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
        BN_free(bn_n);
        BN_free(bn_e);
        RSA_free(rsa);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

/**
 * @brief Create an EVP_PKEY from a JWK JSON object.
 */
static EVP_PKEY *evp_pkey_from_jwk(cJSON *jwk) {
    cJSON *kty = cJSON_GetObjectItemCaseSensitive(jwk, "kty");
    if (!cJSON_IsString(kty)) {
        return NULL;
    }
    if (strcmp(kty->valuestring, "EC") == 0) {
        cJSON *crv = cJSON_GetObjectItemCaseSensitive(jwk, "crv");
        if (!cJSON_IsString(crv) || strcmp(crv->valuestring, "P-256") != 0) {
            return NULL;
        }
        return evp_pkey_from_ec_jwk(jwk);
    }
    if (strcmp(kty->valuestring, "RSA") == 0) {
        return evp_pkey_from_rsa_jwk(jwk);
    }
    return NULL;
}

/**
 * @brief Convert a raw JWS ES256 signature (R || S, 64 bytes) to DER form.
 *
 * OpenSSL's EVP_DigestVerifyFinal expects a DER-encoded ECDSA_SIG, while
 * RFC 7518 defines the JWS ES256 signature as the raw concatenation of R
 * and S. Returns 0 on success and replaces @p sig/@p sig_len with a newly
 * allocated DER buffer.
 */
static int es256_raw_to_der(unsigned char **sig, size_t *sig_len) {
    if (*sig_len != 64) {
        return -1;
    }
    ECDSA_SIG *ecsig = ECDSA_SIG_new();
    if (ecsig == NULL) {
        return -1;
    }
    int rc = -1;
    unsigned char *der = NULL;
    if (ECDSA_SIG_set0(ecsig,
                       BN_bin2bn(*sig, 32, NULL),
                       BN_bin2bn(*sig + 32, 32, NULL)) == 1) {
        int der_len = i2d_ECDSA_SIG(ecsig, &der);
        if (der_len > 0) {
            free(*sig);
            *sig = der;
            *sig_len = (size_t)der_len;
            rc = 0;
        }
    }
    ECDSA_SIG_free(ecsig);
    return rc;
}

/**
 * @brief Verify the signature of a DBSC proof JWT against a given JWK.
 *
 * @param token Null-terminated JWT string.
 * @param proof Decoded proof JWT containing the algorithm and signature.
 * @param jwk_json JWK JSON string to verify against. May be @c NULL only
 *                 when the algorithm is "none".
 *
 * @return 0 if the signature is valid, or -1 otherwise.
 */
static int verify_signature_with_jwk(const char *token,
                                     const OpenDBSC_ProofJWT *proof,
                                     const char *jwk_json) {
    if (token == NULL || proof == NULL || proof->algorithm == NULL) {
        return -1;
    }

    if (strcmp(proof->algorithm, "none") == 0) {
        return 0;
    }
    if (strcmp(proof->algorithm, "ES256") != 0 && strcmp(proof->algorithm, "RS256") != 0) {
        return -1;
    }
    if (jwk_json == NULL || proof->signature == NULL) {
        return -1;
    }

    const char *h_start, *p_start, *s_start;
    if (split_jwt(token, &h_start, &p_start, &s_start) != 0) {
        return -1;
    }
    size_t signed_len = (size_t)(s_start - token - 1);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (opendbsc_base64url_decode(proof->signature, &sig, &sig_len) != 0) {
        return -1;
    }
    if (strcmp(proof->algorithm, "ES256") == 0 &&
        es256_raw_to_der(&sig, &sig_len) != 0) {
        free(sig);
        return -1;
    }

    cJSON *jwk = cJSON_Parse(jwk_json);
    if (jwk == NULL) {
        free(sig);
        return -1;
    }

    EVP_PKEY *pkey = evp_pkey_from_jwk(jwk);
    cJSON_Delete(jwk);
    if (pkey == NULL) {
        free(sig);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        free(sig);
        return -1;
    }

    int init = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    int update = EVP_DigestVerifyUpdate(ctx, token, signed_len);
    int final = EVP_DigestVerifyFinal(ctx, sig, sig_len);

    int rc = -1;
    if (init == 1 && update == 1 && final == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig);
    return rc;
}

/**
 * @brief Verify the signature of a DBSC proof JWT.
 */
int opendbsc_jwt_verify_signature(const char *token, const OpenDBSC_ProofJWT *proof) {
    if (proof == NULL) {
        return -1;
    }
    return verify_signature_with_jwk(token, proof, proof->jwk);
}

/**
 * @brief Check that the JWT typ claim is the DBSC proof type.
 *
 * @return 0 when @p proof has typ "dbsc+jwt", or -1 otherwise.
 */
static int check_proof_type(const OpenDBSC_ProofJWT *proof) {
    if (proof->type == NULL || strcmp(proof->type, "dbsc+jwt") != 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief Enforce the registration-flow jwk/alg rules.
 *
 * ES256 and RS256 tokens must carry a @c jwk header claim; "none" tokens
 * must not.
 *
 * @return 0 when the rules hold, or -1 otherwise.
 */
static int check_registration_jwk_rules(const OpenDBSC_ProofJWT *proof) {
    if (strcmp(proof->algorithm, "none") == 0) {
        return proof->jwk == NULL ? 0 : -1;
    }
    return proof->jwk != NULL ? 0 : -1;
}

/**
 * @brief Decode and verify a DBSC proof JWT.
 */
int opendbsc_jwt_decode_and_verify(const char *token, OpenDBSC_ProofJWT *proof) {
    OpenDBSC_ProofJWT local;
    opendbsc_proof_jwt_init(&local);

    OpenDBSC_ProofJWT *target = proof != NULL ? proof : &local;

    if (opendbsc_jwt_decode(token, target) != 0) {
        opendbsc_proof_jwt_free(&local);
        return -1;
    }

    int rc = check_proof_type(target) != 0 ||
             check_registration_jwk_rules(target) != 0 ||
             verify_signature_with_jwk(token, target, target->jwk) != 0;
    if (rc != 0) {
        if (proof == NULL) {
            opendbsc_proof_jwt_free(&local);
        }
        return -1;
    }

    if (proof == NULL) {
        opendbsc_proof_jwt_free(&local);
    }
    return 0;
}

/**
 * @brief Verify a DBSC proof JWT against a stored JWK.
 */
int opendbsc_jwt_verify_with_jwk(const char *token, const char *jwk_json,
                                 OpenDBSC_ProofJWT *proof) {
    if (token == NULL || jwk_json == NULL) {
        return -1;
    }

    OpenDBSC_ProofJWT local;
    opendbsc_proof_jwt_init(&local);

    OpenDBSC_ProofJWT *target = proof != NULL ? proof : &local;

    if (opendbsc_jwt_decode(token, target) != 0) {
        opendbsc_proof_jwt_free(&local);
        return -1;
    }

    /* Refresh proofs must not embed a key; the registered key is pinned. */
    int rc = target->jwk != NULL ||
             check_proof_type(target) != 0 ||
             strcmp(target->algorithm, "none") == 0 ||
             verify_signature_with_jwk(token, target, jwk_json) != 0;
    if (rc != 0) {
        if (proof == NULL) {
            opendbsc_proof_jwt_free(&local);
        }
        return -1;
    }

    if (proof == NULL) {
        opendbsc_proof_jwt_free(&local);
    }
    return 0;
}
