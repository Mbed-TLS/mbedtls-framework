/* Automatically generated by generate_psa_wrappers.py, do not edit! */

/* Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <mbedtls/build_info.h>

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_TEST_HOOKS) && \
    !defined(RECORD_PSA_STATUS_COVERAGE_LOG)

#include <psa/crypto.h>

#include <test/memory.h>
#include <test/psa_crypto_helpers.h>
#include <test/psa_test_wrappers.h>

/* Wrapper for mbedtls_psa_inject_entropy */
#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
psa_status_t mbedtls_test_wrap_mbedtls_psa_inject_entropy(
    const uint8_t *arg0_seed,
    size_t arg1_seed_size)
{
    psa_status_t status = (mbedtls_psa_inject_entropy)(arg0_seed, arg1_seed_size);
    return status;
}
#endif /* defined(MBEDTLS_PSA_INJECT_ENTROPY) */

/* Wrapper for mbedtls_psa_platform_get_builtin_key */
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
psa_status_t mbedtls_test_wrap_mbedtls_psa_platform_get_builtin_key(
    mbedtls_svc_key_id_t arg0_key_id,
    psa_key_lifetime_t *arg1_lifetime,
    psa_drv_slot_number_t *arg2_slot_number)
{
    psa_status_t status = (mbedtls_psa_platform_get_builtin_key)(arg0_key_id, arg1_lifetime, arg2_slot_number);
    return status;
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS) */

/* Wrapper for mbedtls_psa_register_se_key */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
psa_status_t mbedtls_test_wrap_mbedtls_psa_register_se_key(
    const psa_key_attributes_t *arg0_attributes)
{
    psa_status_t status = (mbedtls_psa_register_se_key)(arg0_attributes);
    return status;
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_SE_C) */

/* Wrapper for psa_aead_abort */
psa_status_t mbedtls_test_wrap_psa_aead_abort(
    psa_aead_operation_t *arg0_operation)
{
    psa_status_t status = (psa_aead_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_aead_decrypt */
psa_status_t mbedtls_test_wrap_psa_aead_decrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_nonce,
    size_t arg3_nonce_length,
    const uint8_t *arg4_additional_data,
    size_t arg5_additional_data_length,
    const uint8_t *arg6_ciphertext,
    size_t arg7_ciphertext_length,
    uint8_t *arg8_plaintext,
    size_t arg9_plaintext_size,
    size_t *arg10_plaintext_length)
{
    psa_status_t status = (psa_aead_decrypt)(arg0_key, arg1_alg, arg2_nonce, arg3_nonce_length, arg4_additional_data, arg5_additional_data_length, arg6_ciphertext, arg7_ciphertext_length, arg8_plaintext, arg9_plaintext_size, arg10_plaintext_length);
    return status;
}

/* Wrapper for psa_aead_decrypt_setup */
psa_status_t mbedtls_test_wrap_psa_aead_decrypt_setup(
    psa_aead_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_aead_decrypt_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_aead_encrypt */
psa_status_t mbedtls_test_wrap_psa_aead_encrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_nonce,
    size_t arg3_nonce_length,
    const uint8_t *arg4_additional_data,
    size_t arg5_additional_data_length,
    const uint8_t *arg6_plaintext,
    size_t arg7_plaintext_length,
    uint8_t *arg8_ciphertext,
    size_t arg9_ciphertext_size,
    size_t *arg10_ciphertext_length)
{
    psa_status_t status = (psa_aead_encrypt)(arg0_key, arg1_alg, arg2_nonce, arg3_nonce_length, arg4_additional_data, arg5_additional_data_length, arg6_plaintext, arg7_plaintext_length, arg8_ciphertext, arg9_ciphertext_size, arg10_ciphertext_length);
    return status;
}

/* Wrapper for psa_aead_encrypt_setup */
psa_status_t mbedtls_test_wrap_psa_aead_encrypt_setup(
    psa_aead_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_aead_encrypt_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_aead_finish */
psa_status_t mbedtls_test_wrap_psa_aead_finish(
    psa_aead_operation_t *arg0_operation,
    uint8_t *arg1_ciphertext,
    size_t arg2_ciphertext_size,
    size_t *arg3_ciphertext_length,
    uint8_t *arg4_tag,
    size_t arg5_tag_size,
    size_t *arg6_tag_length)
{
    psa_status_t status = (psa_aead_finish)(arg0_operation, arg1_ciphertext, arg2_ciphertext_size, arg3_ciphertext_length, arg4_tag, arg5_tag_size, arg6_tag_length);
    return status;
}

/* Wrapper for psa_aead_generate_nonce */
psa_status_t mbedtls_test_wrap_psa_aead_generate_nonce(
    psa_aead_operation_t *arg0_operation,
    uint8_t *arg1_nonce,
    size_t arg2_nonce_size,
    size_t *arg3_nonce_length)
{
    psa_status_t status = (psa_aead_generate_nonce)(arg0_operation, arg1_nonce, arg2_nonce_size, arg3_nonce_length);
    return status;
}

/* Wrapper for psa_aead_set_lengths */
psa_status_t mbedtls_test_wrap_psa_aead_set_lengths(
    psa_aead_operation_t *arg0_operation,
    size_t arg1_ad_length,
    size_t arg2_plaintext_length)
{
    psa_status_t status = (psa_aead_set_lengths)(arg0_operation, arg1_ad_length, arg2_plaintext_length);
    return status;
}

/* Wrapper for psa_aead_set_nonce */
psa_status_t mbedtls_test_wrap_psa_aead_set_nonce(
    psa_aead_operation_t *arg0_operation,
    const uint8_t *arg1_nonce,
    size_t arg2_nonce_length)
{
    psa_status_t status = (psa_aead_set_nonce)(arg0_operation, arg1_nonce, arg2_nonce_length);
    return status;
}

/* Wrapper for psa_aead_update */
psa_status_t mbedtls_test_wrap_psa_aead_update(
    psa_aead_operation_t *arg0_operation,
    const uint8_t *arg1_input,
    size_t arg2_input_length,
    uint8_t *arg3_output,
    size_t arg4_output_size,
    size_t *arg5_output_length)
{
    psa_status_t status = (psa_aead_update)(arg0_operation, arg1_input, arg2_input_length, arg3_output, arg4_output_size, arg5_output_length);
    return status;
}

/* Wrapper for psa_aead_update_ad */
psa_status_t mbedtls_test_wrap_psa_aead_update_ad(
    psa_aead_operation_t *arg0_operation,
    const uint8_t *arg1_input,
    size_t arg2_input_length)
{
    psa_status_t status = (psa_aead_update_ad)(arg0_operation, arg1_input, arg2_input_length);
    return status;
}

/* Wrapper for psa_aead_verify */
psa_status_t mbedtls_test_wrap_psa_aead_verify(
    psa_aead_operation_t *arg0_operation,
    uint8_t *arg1_plaintext,
    size_t arg2_plaintext_size,
    size_t *arg3_plaintext_length,
    const uint8_t *arg4_tag,
    size_t arg5_tag_length)
{
    psa_status_t status = (psa_aead_verify)(arg0_operation, arg1_plaintext, arg2_plaintext_size, arg3_plaintext_length, arg4_tag, arg5_tag_length);
    return status;
}

/* Wrapper for psa_asymmetric_decrypt */
psa_status_t mbedtls_test_wrap_psa_asymmetric_decrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    const uint8_t *arg4_salt,
    size_t arg5_salt_length,
    uint8_t *arg6_output,
    size_t arg7_output_size,
    size_t *arg8_output_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_salt, arg5_salt_length);
    MBEDTLS_TEST_MEMORY_POISON(arg6_output, arg7_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_asymmetric_decrypt)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_salt, arg5_salt_length, arg6_output, arg7_output_size, arg8_output_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_salt, arg5_salt_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg6_output, arg7_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_asymmetric_encrypt */
psa_status_t mbedtls_test_wrap_psa_asymmetric_encrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    const uint8_t *arg4_salt,
    size_t arg5_salt_length,
    uint8_t *arg6_output,
    size_t arg7_output_size,
    size_t *arg8_output_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_salt, arg5_salt_length);
    MBEDTLS_TEST_MEMORY_POISON(arg6_output, arg7_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_asymmetric_encrypt)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_salt, arg5_salt_length, arg6_output, arg7_output_size, arg8_output_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_salt, arg5_salt_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg6_output, arg7_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_cipher_abort */
psa_status_t mbedtls_test_wrap_psa_cipher_abort(
    psa_cipher_operation_t *arg0_operation)
{
    psa_status_t status = (psa_cipher_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_cipher_decrypt */
psa_status_t mbedtls_test_wrap_psa_cipher_decrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    uint8_t *arg4_output,
    size_t arg5_output_size,
    size_t *arg6_output_length)
{
    psa_status_t status = (psa_cipher_decrypt)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_output, arg5_output_size, arg6_output_length);
    return status;
}

/* Wrapper for psa_cipher_decrypt_setup */
psa_status_t mbedtls_test_wrap_psa_cipher_decrypt_setup(
    psa_cipher_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_cipher_decrypt_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_cipher_encrypt */
psa_status_t mbedtls_test_wrap_psa_cipher_encrypt(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    uint8_t *arg4_output,
    size_t arg5_output_size,
    size_t *arg6_output_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_output, arg5_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_cipher_encrypt)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_output, arg5_output_size, arg6_output_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_output, arg5_output_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_cipher_encrypt_setup */
psa_status_t mbedtls_test_wrap_psa_cipher_encrypt_setup(
    psa_cipher_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_cipher_encrypt_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_cipher_finish */
psa_status_t mbedtls_test_wrap_psa_cipher_finish(
    psa_cipher_operation_t *arg0_operation,
    uint8_t *arg1_output,
    size_t arg2_output_size,
    size_t *arg3_output_length)
{
    psa_status_t status = (psa_cipher_finish)(arg0_operation, arg1_output, arg2_output_size, arg3_output_length);
    return status;
}

/* Wrapper for psa_cipher_generate_iv */
psa_status_t mbedtls_test_wrap_psa_cipher_generate_iv(
    psa_cipher_operation_t *arg0_operation,
    uint8_t *arg1_iv,
    size_t arg2_iv_size,
    size_t *arg3_iv_length)
{
    psa_status_t status = (psa_cipher_generate_iv)(arg0_operation, arg1_iv, arg2_iv_size, arg3_iv_length);
    return status;
}

/* Wrapper for psa_cipher_set_iv */
psa_status_t mbedtls_test_wrap_psa_cipher_set_iv(
    psa_cipher_operation_t *arg0_operation,
    const uint8_t *arg1_iv,
    size_t arg2_iv_length)
{
    psa_status_t status = (psa_cipher_set_iv)(arg0_operation, arg1_iv, arg2_iv_length);
    return status;
}

/* Wrapper for psa_cipher_update */
psa_status_t mbedtls_test_wrap_psa_cipher_update(
    psa_cipher_operation_t *arg0_operation,
    const uint8_t *arg1_input,
    size_t arg2_input_length,
    uint8_t *arg3_output,
    size_t arg4_output_size,
    size_t *arg5_output_length)
{
    psa_status_t status = (psa_cipher_update)(arg0_operation, arg1_input, arg2_input_length, arg3_output, arg4_output_size, arg5_output_length);
    return status;
}

/* Wrapper for psa_copy_key */
psa_status_t mbedtls_test_wrap_psa_copy_key(
    mbedtls_svc_key_id_t arg0_source_key,
    const psa_key_attributes_t *arg1_attributes,
    mbedtls_svc_key_id_t *arg2_target_key)
{
    psa_status_t status = (psa_copy_key)(arg0_source_key, arg1_attributes, arg2_target_key);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_cipher_suite */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_cipher_suite(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    psa_pake_cipher_suite_t *arg1_cipher_suite)
{
    psa_status_t status = (psa_crypto_driver_pake_get_cipher_suite)(arg0_inputs, arg1_cipher_suite);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_password */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_password(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    uint8_t *arg1_buffer,
    size_t arg2_buffer_size,
    size_t *arg3_buffer_length)
{
    psa_status_t status = (psa_crypto_driver_pake_get_password)(arg0_inputs, arg1_buffer, arg2_buffer_size, arg3_buffer_length);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_password_len */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_password_len(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    size_t *arg1_password_len)
{
    psa_status_t status = (psa_crypto_driver_pake_get_password_len)(arg0_inputs, arg1_password_len);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_peer */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_peer(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    uint8_t *arg1_peer_id,
    size_t arg2_peer_id_size,
    size_t *arg3_peer_id_length)
{
    psa_status_t status = (psa_crypto_driver_pake_get_peer)(arg0_inputs, arg1_peer_id, arg2_peer_id_size, arg3_peer_id_length);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_peer_len */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_peer_len(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    size_t *arg1_peer_len)
{
    psa_status_t status = (psa_crypto_driver_pake_get_peer_len)(arg0_inputs, arg1_peer_len);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_user */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_user(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    uint8_t *arg1_user_id,
    size_t arg2_user_id_size,
    size_t *arg3_user_id_len)
{
    psa_status_t status = (psa_crypto_driver_pake_get_user)(arg0_inputs, arg1_user_id, arg2_user_id_size, arg3_user_id_len);
    return status;
}

/* Wrapper for psa_crypto_driver_pake_get_user_len */
psa_status_t mbedtls_test_wrap_psa_crypto_driver_pake_get_user_len(
    const psa_crypto_driver_pake_inputs_t *arg0_inputs,
    size_t *arg1_user_len)
{
    psa_status_t status = (psa_crypto_driver_pake_get_user_len)(arg0_inputs, arg1_user_len);
    return status;
}

/* Wrapper for psa_crypto_init */
psa_status_t mbedtls_test_wrap_psa_crypto_init(void)
{
    psa_status_t status = (psa_crypto_init)();
    return status;
}

/* Wrapper for psa_destroy_key */
psa_status_t mbedtls_test_wrap_psa_destroy_key(
    mbedtls_svc_key_id_t arg0_key)
{
    psa_status_t status = (psa_destroy_key)(arg0_key);
    return status;
}

/* Wrapper for psa_export_key */
psa_status_t mbedtls_test_wrap_psa_export_key(
    mbedtls_svc_key_id_t arg0_key,
    uint8_t *arg1_data,
    size_t arg2_data_size,
    size_t *arg3_data_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg1_data, arg2_data_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_export_key)(arg0_key, arg1_data, arg2_data_size, arg3_data_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg1_data, arg2_data_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_export_public_key */
psa_status_t mbedtls_test_wrap_psa_export_public_key(
    mbedtls_svc_key_id_t arg0_key,
    uint8_t *arg1_data,
    size_t arg2_data_size,
    size_t *arg3_data_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg1_data, arg2_data_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_export_public_key)(arg0_key, arg1_data, arg2_data_size, arg3_data_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg1_data, arg2_data_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_generate_key */
psa_status_t mbedtls_test_wrap_psa_generate_key(
    const psa_key_attributes_t *arg0_attributes,
    mbedtls_svc_key_id_t *arg1_key)
{
    psa_status_t status = (psa_generate_key)(arg0_attributes, arg1_key);
    return status;
}

/* Wrapper for psa_generate_random */
psa_status_t mbedtls_test_wrap_psa_generate_random(
    uint8_t *arg0_output,
    size_t arg1_output_size)
{
    psa_status_t status = (psa_generate_random)(arg0_output, arg1_output_size);
    return status;
}

/* Wrapper for psa_get_key_attributes */
psa_status_t mbedtls_test_wrap_psa_get_key_attributes(
    mbedtls_svc_key_id_t arg0_key,
    psa_key_attributes_t *arg1_attributes)
{
    psa_status_t status = (psa_get_key_attributes)(arg0_key, arg1_attributes);
    return status;
}

/* Wrapper for psa_hash_abort */
psa_status_t mbedtls_test_wrap_psa_hash_abort(
    psa_hash_operation_t *arg0_operation)
{
    psa_status_t status = (psa_hash_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_hash_clone */
psa_status_t mbedtls_test_wrap_psa_hash_clone(
    const psa_hash_operation_t *arg0_source_operation,
    psa_hash_operation_t *arg1_target_operation)
{
    psa_status_t status = (psa_hash_clone)(arg0_source_operation, arg1_target_operation);
    return status;
}

/* Wrapper for psa_hash_compare */
psa_status_t mbedtls_test_wrap_psa_hash_compare(
    psa_algorithm_t arg0_alg,
    const uint8_t *arg1_input,
    size_t arg2_input_length,
    const uint8_t *arg3_hash,
    size_t arg4_hash_length)
{
    psa_status_t status = (psa_hash_compare)(arg0_alg, arg1_input, arg2_input_length, arg3_hash, arg4_hash_length);
    return status;
}

/* Wrapper for psa_hash_compute */
psa_status_t mbedtls_test_wrap_psa_hash_compute(
    psa_algorithm_t arg0_alg,
    const uint8_t *arg1_input,
    size_t arg2_input_length,
    uint8_t *arg3_hash,
    size_t arg4_hash_size,
    size_t *arg5_hash_length)
{
    psa_status_t status = (psa_hash_compute)(arg0_alg, arg1_input, arg2_input_length, arg3_hash, arg4_hash_size, arg5_hash_length);
    return status;
}

/* Wrapper for psa_hash_finish */
psa_status_t mbedtls_test_wrap_psa_hash_finish(
    psa_hash_operation_t *arg0_operation,
    uint8_t *arg1_hash,
    size_t arg2_hash_size,
    size_t *arg3_hash_length)
{
    psa_status_t status = (psa_hash_finish)(arg0_operation, arg1_hash, arg2_hash_size, arg3_hash_length);
    return status;
}

/* Wrapper for psa_hash_setup */
psa_status_t mbedtls_test_wrap_psa_hash_setup(
    psa_hash_operation_t *arg0_operation,
    psa_algorithm_t arg1_alg)
{
    psa_status_t status = (psa_hash_setup)(arg0_operation, arg1_alg);
    return status;
}

/* Wrapper for psa_hash_update */
psa_status_t mbedtls_test_wrap_psa_hash_update(
    psa_hash_operation_t *arg0_operation,
    const uint8_t *arg1_input,
    size_t arg2_input_length)
{
    psa_status_t status = (psa_hash_update)(arg0_operation, arg1_input, arg2_input_length);
    return status;
}

/* Wrapper for psa_hash_verify */
psa_status_t mbedtls_test_wrap_psa_hash_verify(
    psa_hash_operation_t *arg0_operation,
    const uint8_t *arg1_hash,
    size_t arg2_hash_length)
{
    psa_status_t status = (psa_hash_verify)(arg0_operation, arg1_hash, arg2_hash_length);
    return status;
}

/* Wrapper for psa_import_key */
psa_status_t mbedtls_test_wrap_psa_import_key(
    const psa_key_attributes_t *arg0_attributes,
    const uint8_t *arg1_data,
    size_t arg2_data_length,
    mbedtls_svc_key_id_t *arg3_key)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg1_data, arg2_data_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_import_key)(arg0_attributes, arg1_data, arg2_data_length, arg3_key);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg1_data, arg2_data_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_key_derivation_abort */
psa_status_t mbedtls_test_wrap_psa_key_derivation_abort(
    psa_key_derivation_operation_t *arg0_operation)
{
    psa_status_t status = (psa_key_derivation_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_key_derivation_get_capacity */
psa_status_t mbedtls_test_wrap_psa_key_derivation_get_capacity(
    const psa_key_derivation_operation_t *arg0_operation,
    size_t *arg1_capacity)
{
    psa_status_t status = (psa_key_derivation_get_capacity)(arg0_operation, arg1_capacity);
    return status;
}

/* Wrapper for psa_key_derivation_input_bytes */
psa_status_t mbedtls_test_wrap_psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *arg0_operation,
    psa_key_derivation_step_t arg1_step,
    const uint8_t *arg2_data,
    size_t arg3_data_length)
{
    psa_status_t status = (psa_key_derivation_input_bytes)(arg0_operation, arg1_step, arg2_data, arg3_data_length);
    return status;
}

/* Wrapper for psa_key_derivation_input_integer */
psa_status_t mbedtls_test_wrap_psa_key_derivation_input_integer(
    psa_key_derivation_operation_t *arg0_operation,
    psa_key_derivation_step_t arg1_step,
    uint64_t arg2_value)
{
    psa_status_t status = (psa_key_derivation_input_integer)(arg0_operation, arg1_step, arg2_value);
    return status;
}

/* Wrapper for psa_key_derivation_input_key */
psa_status_t mbedtls_test_wrap_psa_key_derivation_input_key(
    psa_key_derivation_operation_t *arg0_operation,
    psa_key_derivation_step_t arg1_step,
    mbedtls_svc_key_id_t arg2_key)
{
    psa_status_t status = (psa_key_derivation_input_key)(arg0_operation, arg1_step, arg2_key);
    return status;
}

/* Wrapper for psa_key_derivation_key_agreement */
psa_status_t mbedtls_test_wrap_psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t *arg0_operation,
    psa_key_derivation_step_t arg1_step,
    mbedtls_svc_key_id_t arg2_private_key,
    const uint8_t *arg3_peer_key,
    size_t arg4_peer_key_length)
{
    psa_status_t status = (psa_key_derivation_key_agreement)(arg0_operation, arg1_step, arg2_private_key, arg3_peer_key, arg4_peer_key_length);
    return status;
}

/* Wrapper for psa_key_derivation_output_bytes */
psa_status_t mbedtls_test_wrap_psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *arg0_operation,
    uint8_t *arg1_output,
    size_t arg2_output_length)
{
    psa_status_t status = (psa_key_derivation_output_bytes)(arg0_operation, arg1_output, arg2_output_length);
    return status;
}

/* Wrapper for psa_key_derivation_output_key */
psa_status_t mbedtls_test_wrap_psa_key_derivation_output_key(
    const psa_key_attributes_t *arg0_attributes,
    psa_key_derivation_operation_t *arg1_operation,
    mbedtls_svc_key_id_t *arg2_key)
{
    psa_status_t status = (psa_key_derivation_output_key)(arg0_attributes, arg1_operation, arg2_key);
    return status;
}

/* Wrapper for psa_key_derivation_set_capacity */
psa_status_t mbedtls_test_wrap_psa_key_derivation_set_capacity(
    psa_key_derivation_operation_t *arg0_operation,
    size_t arg1_capacity)
{
    psa_status_t status = (psa_key_derivation_set_capacity)(arg0_operation, arg1_capacity);
    return status;
}

/* Wrapper for psa_key_derivation_setup */
psa_status_t mbedtls_test_wrap_psa_key_derivation_setup(
    psa_key_derivation_operation_t *arg0_operation,
    psa_algorithm_t arg1_alg)
{
    psa_status_t status = (psa_key_derivation_setup)(arg0_operation, arg1_alg);
    return status;
}

/* Wrapper for psa_mac_abort */
psa_status_t mbedtls_test_wrap_psa_mac_abort(
    psa_mac_operation_t *arg0_operation)
{
    psa_status_t status = (psa_mac_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_mac_compute */
psa_status_t mbedtls_test_wrap_psa_mac_compute(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    uint8_t *arg4_mac,
    size_t arg5_mac_size,
    size_t *arg6_mac_length)
{
    psa_status_t status = (psa_mac_compute)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_mac, arg5_mac_size, arg6_mac_length);
    return status;
}

/* Wrapper for psa_mac_sign_finish */
psa_status_t mbedtls_test_wrap_psa_mac_sign_finish(
    psa_mac_operation_t *arg0_operation,
    uint8_t *arg1_mac,
    size_t arg2_mac_size,
    size_t *arg3_mac_length)
{
    psa_status_t status = (psa_mac_sign_finish)(arg0_operation, arg1_mac, arg2_mac_size, arg3_mac_length);
    return status;
}

/* Wrapper for psa_mac_sign_setup */
psa_status_t mbedtls_test_wrap_psa_mac_sign_setup(
    psa_mac_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_mac_sign_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_mac_update */
psa_status_t mbedtls_test_wrap_psa_mac_update(
    psa_mac_operation_t *arg0_operation,
    const uint8_t *arg1_input,
    size_t arg2_input_length)
{
    psa_status_t status = (psa_mac_update)(arg0_operation, arg1_input, arg2_input_length);
    return status;
}

/* Wrapper for psa_mac_verify */
psa_status_t mbedtls_test_wrap_psa_mac_verify(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    const uint8_t *arg4_mac,
    size_t arg5_mac_length)
{
    psa_status_t status = (psa_mac_verify)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_mac, arg5_mac_length);
    return status;
}

/* Wrapper for psa_mac_verify_finish */
psa_status_t mbedtls_test_wrap_psa_mac_verify_finish(
    psa_mac_operation_t *arg0_operation,
    const uint8_t *arg1_mac,
    size_t arg2_mac_length)
{
    psa_status_t status = (psa_mac_verify_finish)(arg0_operation, arg1_mac, arg2_mac_length);
    return status;
}

/* Wrapper for psa_mac_verify_setup */
psa_status_t mbedtls_test_wrap_psa_mac_verify_setup(
    psa_mac_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg)
{
    psa_status_t status = (psa_mac_verify_setup)(arg0_operation, arg1_key, arg2_alg);
    return status;
}

/* Wrapper for psa_pake_abort */
psa_status_t mbedtls_test_wrap_psa_pake_abort(
    psa_pake_operation_t *arg0_operation)
{
    psa_status_t status = (psa_pake_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_pake_get_implicit_key */
psa_status_t mbedtls_test_wrap_psa_pake_get_implicit_key(
    psa_pake_operation_t *arg0_operation,
    psa_key_derivation_operation_t *arg1_output)
{
    psa_status_t status = (psa_pake_get_implicit_key)(arg0_operation, arg1_output);
    return status;
}

/* Wrapper for psa_pake_input */
psa_status_t mbedtls_test_wrap_psa_pake_input(
    psa_pake_operation_t *arg0_operation,
    psa_pake_step_t arg1_step,
    const uint8_t *arg2_input,
    size_t arg3_input_length)
{
    psa_status_t status = (psa_pake_input)(arg0_operation, arg1_step, arg2_input, arg3_input_length);
    return status;
}

/* Wrapper for psa_pake_output */
psa_status_t mbedtls_test_wrap_psa_pake_output(
    psa_pake_operation_t *arg0_operation,
    psa_pake_step_t arg1_step,
    uint8_t *arg2_output,
    size_t arg3_output_size,
    size_t *arg4_output_length)
{
    psa_status_t status = (psa_pake_output)(arg0_operation, arg1_step, arg2_output, arg3_output_size, arg4_output_length);
    return status;
}

/* Wrapper for psa_pake_set_password_key */
psa_status_t mbedtls_test_wrap_psa_pake_set_password_key(
    psa_pake_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_password)
{
    psa_status_t status = (psa_pake_set_password_key)(arg0_operation, arg1_password);
    return status;
}

/* Wrapper for psa_pake_set_peer */
psa_status_t mbedtls_test_wrap_psa_pake_set_peer(
    psa_pake_operation_t *arg0_operation,
    const uint8_t *arg1_peer_id,
    size_t arg2_peer_id_len)
{
    psa_status_t status = (psa_pake_set_peer)(arg0_operation, arg1_peer_id, arg2_peer_id_len);
    return status;
}

/* Wrapper for psa_pake_set_role */
psa_status_t mbedtls_test_wrap_psa_pake_set_role(
    psa_pake_operation_t *arg0_operation,
    psa_pake_role_t arg1_role)
{
    psa_status_t status = (psa_pake_set_role)(arg0_operation, arg1_role);
    return status;
}

/* Wrapper for psa_pake_set_user */
psa_status_t mbedtls_test_wrap_psa_pake_set_user(
    psa_pake_operation_t *arg0_operation,
    const uint8_t *arg1_user_id,
    size_t arg2_user_id_len)
{
    psa_status_t status = (psa_pake_set_user)(arg0_operation, arg1_user_id, arg2_user_id_len);
    return status;
}

/* Wrapper for psa_pake_setup */
psa_status_t mbedtls_test_wrap_psa_pake_setup(
    psa_pake_operation_t *arg0_operation,
    const psa_pake_cipher_suite_t *arg1_cipher_suite)
{
    psa_status_t status = (psa_pake_setup)(arg0_operation, arg1_cipher_suite);
    return status;
}

/* Wrapper for psa_purge_key */
psa_status_t mbedtls_test_wrap_psa_purge_key(
    mbedtls_svc_key_id_t arg0_key)
{
    psa_status_t status = (psa_purge_key)(arg0_key);
    return status;
}

/* Wrapper for psa_raw_key_agreement */
psa_status_t mbedtls_test_wrap_psa_raw_key_agreement(
    psa_algorithm_t arg0_alg,
    mbedtls_svc_key_id_t arg1_private_key,
    const uint8_t *arg2_peer_key,
    size_t arg3_peer_key_length,
    uint8_t *arg4_output,
    size_t arg5_output_size,
    size_t *arg6_output_length)
{
    psa_status_t status = (psa_raw_key_agreement)(arg0_alg, arg1_private_key, arg2_peer_key, arg3_peer_key_length, arg4_output, arg5_output_size, arg6_output_length);
    return status;
}

/* Wrapper for psa_sign_hash */
psa_status_t mbedtls_test_wrap_psa_sign_hash(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_hash,
    size_t arg3_hash_length,
    uint8_t *arg4_signature,
    size_t arg5_signature_size,
    size_t *arg6_signature_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_hash, arg3_hash_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_signature, arg5_signature_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_sign_hash)(arg0_key, arg1_alg, arg2_hash, arg3_hash_length, arg4_signature, arg5_signature_size, arg6_signature_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_hash, arg3_hash_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_signature, arg5_signature_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_sign_hash_abort */
psa_status_t mbedtls_test_wrap_psa_sign_hash_abort(
    psa_sign_hash_interruptible_operation_t *arg0_operation)
{
    psa_status_t status = (psa_sign_hash_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_sign_hash_complete */
psa_status_t mbedtls_test_wrap_psa_sign_hash_complete(
    psa_sign_hash_interruptible_operation_t *arg0_operation,
    uint8_t *arg1_signature,
    size_t arg2_signature_size,
    size_t *arg3_signature_length)
{
    psa_status_t status = (psa_sign_hash_complete)(arg0_operation, arg1_signature, arg2_signature_size, arg3_signature_length);
    return status;
}

/* Wrapper for psa_sign_hash_start */
psa_status_t mbedtls_test_wrap_psa_sign_hash_start(
    psa_sign_hash_interruptible_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg,
    const uint8_t *arg3_hash,
    size_t arg4_hash_length)
{
    psa_status_t status = (psa_sign_hash_start)(arg0_operation, arg1_key, arg2_alg, arg3_hash, arg4_hash_length);
    return status;
}

/* Wrapper for psa_sign_message */
psa_status_t mbedtls_test_wrap_psa_sign_message(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    uint8_t *arg4_signature,
    size_t arg5_signature_size,
    size_t *arg6_signature_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_signature, arg5_signature_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_sign_message)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_signature, arg5_signature_size, arg6_signature_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_signature, arg5_signature_size);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_verify_hash */
psa_status_t mbedtls_test_wrap_psa_verify_hash(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_hash,
    size_t arg3_hash_length,
    const uint8_t *arg4_signature,
    size_t arg5_signature_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_hash, arg3_hash_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_signature, arg5_signature_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_verify_hash)(arg0_key, arg1_alg, arg2_hash, arg3_hash_length, arg4_signature, arg5_signature_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_hash, arg3_hash_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_signature, arg5_signature_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

/* Wrapper for psa_verify_hash_abort */
psa_status_t mbedtls_test_wrap_psa_verify_hash_abort(
    psa_verify_hash_interruptible_operation_t *arg0_operation)
{
    psa_status_t status = (psa_verify_hash_abort)(arg0_operation);
    return status;
}

/* Wrapper for psa_verify_hash_complete */
psa_status_t mbedtls_test_wrap_psa_verify_hash_complete(
    psa_verify_hash_interruptible_operation_t *arg0_operation)
{
    psa_status_t status = (psa_verify_hash_complete)(arg0_operation);
    return status;
}

/* Wrapper for psa_verify_hash_start */
psa_status_t mbedtls_test_wrap_psa_verify_hash_start(
    psa_verify_hash_interruptible_operation_t *arg0_operation,
    mbedtls_svc_key_id_t arg1_key,
    psa_algorithm_t arg2_alg,
    const uint8_t *arg3_hash,
    size_t arg4_hash_length,
    const uint8_t *arg5_signature,
    size_t arg6_signature_length)
{
    psa_status_t status = (psa_verify_hash_start)(arg0_operation, arg1_key, arg2_alg, arg3_hash, arg4_hash_length, arg5_signature, arg6_signature_length);
    return status;
}

/* Wrapper for psa_verify_message */
psa_status_t mbedtls_test_wrap_psa_verify_message(
    mbedtls_svc_key_id_t arg0_key,
    psa_algorithm_t arg1_alg,
    const uint8_t *arg2_input,
    size_t arg3_input_length,
    const uint8_t *arg4_signature,
    size_t arg5_signature_length)
{
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_POISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_POISON(arg4_signature, arg5_signature_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    psa_status_t status = (psa_verify_message)(arg0_key, arg1_alg, arg2_input, arg3_input_length, arg4_signature, arg5_signature_length);
#if defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS)
    MBEDTLS_TEST_MEMORY_UNPOISON(arg2_input, arg3_input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(arg4_signature, arg5_signature_length);
#endif /* defined(MBEDTLS_PSA_COPY_CALLER_BUFFERS) */
    return status;
}

#endif /* defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_TEST_HOOKS) && \
    !defined(RECORD_PSA_STATUS_COVERAGE_LOG) */

/* End of automatically generated file. */
