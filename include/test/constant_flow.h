/**
 * \file constant_flow.h
 *
 * \brief   This file contains tools to ensure tested code has constant flow.
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef TEST_CONSTANT_FLOW_H
#define TEST_CONSTANT_FLOW_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN)
#include <sanitizer/msan_interface.h>

/* Use macros to avoid messing up with origin tracking */
#define TEST_CF_SECRET  __msan_allocated_memory
// void __msan_allocated_memory(const volatile void* data, size_t size);
#define TEST_CF_PUBLIC  __msan_unpoison
// void __msan_unpoison(const volatile void *a, size_t size);

#else /* MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN */

#define TEST_CF_SECRET(ptr, size)
#define TEST_CF_PUBLIC(ptr, size)

#endif /* MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN */

#endif /* TEST_CONSTANT_FLOW_H */
