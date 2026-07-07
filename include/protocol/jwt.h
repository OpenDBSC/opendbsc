#ifndef OPENDBSC_PROTOCOL_JWT_H
#define OPENDBSC_PROTOCOL_JWT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file protocol/jwt.h
 * @brief DBSC proof JWT decoding and signature verification.
 */

/**
 * @brief A decoded DBSC proof JWT.
 *
 * All string fields are heap-owned and must be freed by the caller using
 * opendbsc_proof_jwt_free().
 */
typedef struct {
    char *algorithm;   /**< Signing algorithm ("ES256", "RS256", "none"). */
    char *type;        /**< JWT type, expected "dbsc+jwt". */
    char *jwk;         /**< Public key as JWK JSON (NULL for "none"). */
    char *challenge;   /**< Challenge value from the "jti" claim. */
    char *authorization; /**< Optional authorization value. */
    char *signature;   /**< Raw base64url-encoded signature. */
} OpenDBSC_ProofJWT;

/**
 * @brief Initialize a proof JWT structure to its default state.
 *
 * @param proof Pointer to the structure to initialize. May be @c NULL.
 */
void opendbsc_proof_jwt_init(OpenDBSC_ProofJWT *proof);

/**
 * @brief Release all resources owned by a proof JWT structure.
 *
 * @param proof Pointer to the structure to free. May be @c NULL.
 */
void opendbsc_proof_jwt_free(OpenDBSC_ProofJWT *proof);

/**
 * @brief Decode a DBSC proof JWT without verifying its signature.
 *
 * Parses the header and payload and fills @p proof. The @p signature field
 * receives the raw base64url-encoded signature string.
 *
 * @param token Null-terminated JWT string.
 * @param proof Pointer to the structure that receives the decoded values.
 *
 * @return 0 on success, or -1 if @p token is malformed or allocation failed.
 */
int opendbsc_jwt_decode(const char *token, OpenDBSC_ProofJWT *proof);

/**
 * @brief Decode and verify a DBSC proof JWT.
 *
 * This function extracts the public key from the JWT header's @c jwk claim
 * and verifies the signature according to the @c alg claim.
 *
 * Supported algorithms:
 * - ES256: ECDSA using P-256 and SHA-256.
 * - RS256: RSASSA-PKCS1-v1_5 using SHA-256.
 * - none: No signature; only header/payload parsing is performed.
 *
 * @param token Null-terminated JWT string.
 * @param proof Pointer to the structure that receives the decoded values.
 *              May be @c NULL if only verification is required.
 *
 * @return 0 if the JWT is valid, or -1 if it is malformed, uses an
 *         unsupported algorithm, or the signature does not verify.
 */
int opendbsc_jwt_decode_and_verify(const char *token, OpenDBSC_ProofJWT *proof);

/**
 * @brief Verify the signature of an already-decoded proof JWT.
 *
 * @param token Null-terminated JWT string.
 * @param proof Decoded proof JWT containing algorithm, JWK, and signature.
 *
 * @return 0 if the signature is valid, or -1 otherwise.
 */
int opendbsc_jwt_verify_signature(const char *token, const OpenDBSC_ProofJWT *proof);

/**
 * @brief Base64url decode a string.
 *
 * The returned buffer is allocated with malloc() and must be freed by the
 * caller. Padding is optional and is added internally if missing.
 *
 * @param in Null-terminated base64url-encoded string.
 * @param out Pointer that receives the decoded bytes.
 * @param out_len Pointer that receives the number of decoded bytes.
 *
 * @return 0 on success, or -1 if @p in is invalid or allocation failed.
 */
int opendbsc_base64url_decode(const char *in, unsigned char **out, size_t *out_len);

/**
 * @brief Base64url encode a buffer.
 *
 * The returned string is allocated with malloc() and must be freed by the
 * caller. The output does not include padding.
 *
 * @param in Input bytes.
 * @param in_len Number of input bytes.
 *
 * @return Newly allocated null-terminated base64url string, or @c NULL on error.
 */
char *opendbsc_base64url_encode(const unsigned char *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
