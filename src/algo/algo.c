#include <algo/algo.h>

/**
 * @brief Check whether a signature algorithm identifier is supported.
 *
 * @param algo The algorithm identifier to validate.
 *
 * @return true if @p algo is a supported signature algorithm,
 *         false otherwise.
 */
bool dbsc_sign_is_valid (enum OpenDBSC_Algo algo) {
    bool is_valid = false;
    switch(algo) {
        case ALGO_ES256:
        /* fall through */
        case ALGO_RS256:
        /* fall through */
        case ALGO_NONE:
            is_valid = true;
        default:
            break;
    }
    return is_valid;
}
