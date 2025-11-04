#ifndef TEST_RSA_TEST_HELPERS_H
#define TEST_RSA_TEST_HELPERS_H

#include "mbedtls/private/rsa.h"

/* Helper function to fill an RSA context.
 * - rsa: context to fill;
 * - bindary_data: tells if the input parameters are in raw binary format (1),
 *                 or strings (0);
 * - [P|Q|N|E]_data: input parameters as strings.
 */
int mbedtls_rsa_test_fill_context(mbedtls_rsa_context *rsa,
                                  const unsigned char *P_data, size_t P_len,
                                  const unsigned char *Q_data, size_t Q_len,
                                  const unsigned char *N_data, size_t N_len,
                                  const unsigned char *E_data, size_t E_len);

#endif /* TEST_RSA_TEST_HELPERS_H */
