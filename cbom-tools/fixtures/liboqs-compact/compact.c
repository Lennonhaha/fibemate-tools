/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 FIBEMATE Contributors */
/*
 * Fixture for test/legacy-recall.test.cjs: the compact identifiers liboqs and
 * PQClean actually contain, copied from their source layout.
 *
 * These spellings have no separator between the family and its parameter set
 * (`frodokem_640`, `mceliece348864`), so a word-boundary rule matches none of
 * them even though the family name is in the dictionary. It is never compiled;
 * it is read as source text by the scanner.
 */
#include <oqs/kem_frodokem.h>
#include <oqs/kem_classic_mceliece.h>
#include <oqs/kem_ntruprime.h>

#if defined(OQS_ENABLE_KEM_frodokem_640_aes)
OQS_KEM *OQS_KEM_frodokem_640_aes_new(void);
#endif

#if defined(OQS_ENABLE_KEM_classic_mceliece_348864)
OQS_KEM *OQS_KEM_classic_mceliece_348864_new(void);
#endif

#if defined(OQS_ENABLE_KEM_ntruprime_sntrup761)
OQS_KEM *OQS_KEM_ntruprime_sntrup761_new(void);
#endif

/* PQClean directory naming, as quoted by its per-scheme build files. */
const char *pqclean_mceliece348864_clean = "pqclean_mceliece348864_clean";
const char *pqclean_ntrulpr653_clean = "pqclean_ntrulpr653_clean";

/* Reference parameter sets, as named by the upstream implementation. */
const char *ntruhps2048509 = "crypto_kem_ntruhps2048509_keypair";
const char *ntruhrss701 = "crypto_kem_ntruhrss701_keypair";
