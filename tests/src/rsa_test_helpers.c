/* We're in test code so it's OK to access private funtions and structures' parameters. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_BIGNUM_C)

#include "test/rsa_test_helpers.h"
#include "mbedtls/private/rsa.h"
#include "mbedtls/private/bignum.h"
#include "test/bignum_helpers.h"
#include "rsa_alt_helpers.h"

int mbedtls_rsa_test_fill_context(mbedtls_rsa_context *rsa,
                                  const unsigned char *P_data, size_t P_len,
                                  const unsigned char *Q_data, size_t Q_len,
                                  const unsigned char *N_data, size_t N_len,
                                  const unsigned char *E_data, size_t E_len)
{
    mbedtls_mpi N; mbedtls_mpi P; mbedtls_mpi Q;
    mbedtls_mpi E; mbedtls_mpi D;
    int ret;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&E); mbedtls_mpi_init(&D);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&P, P_data, P_len));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Q, Q_data, Q_len));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&N, N_data, N_len));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&E, E_data, E_len));

    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_private_exponent(&P, &Q, &E, &D));

    MBEDTLS_MPI_CHK(mbedtls_rsa_import(rsa, &N, &P, &Q, &D, &E));

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&P, &Q, &D, &rsa->DP, &rsa->DQ, &rsa->QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

cleanup:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&E); mbedtls_mpi_free(&D);
    return ret;
}

#endif /* MBEDTLS_RSA_C && MBEDTLS_BIGNUM_C */
