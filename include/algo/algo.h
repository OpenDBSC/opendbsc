#ifndef ALGO_H
#define ALGO_H

#include <stdbool.h>

/**
 * @file algo/algo.h
 * @brief Signature algorithm identifiers for OpenDBSC.
 */

/**
 * @brief Supported signature algorithms.
 */
enum OpenDBSC_Algo {
    ALGO_ES256, /**< ECDSA using P-256 and SHA-256. */
    ALGO_RS256, /**< RSASSA-PKCS1-v1_5 using SHA-256. */
    ALGO_NONE   /**< No digital signature. */
};

/**
 * @brief Check whether a signature algorithm identifier is supported.
 *
 * @param algo The algorithm identifier to validate.
 *
 * @return true if @p algo is a supported signature algorithm,
 *         false otherwise.
 */
bool dbsc_sign_is_valid (enum OpenDBSC_Algo algo);

#endif
