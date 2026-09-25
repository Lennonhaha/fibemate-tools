// SPDX-License-Identifier: Apache-2.0
// oqsbridge — liboqs CLI bridge for xdiff (cross-implementation differential sentinel)
//
// 与旧版 scripts/oqs_gen.c 的区别：
//   1. 用 OQS_KEM_new() 动态取长度，不再依赖 OQS_KEM_ml_kem_768_length_* 这类
//      版本相关的静态符号（liboqs 0.16 已移除，旧脚本因此编译失败）。
//   2. 批协议：一次进程吃多行命令，避免每次操作 spawn 一次进程。
//
// Build:
//   gcc -O2 -o oqsbridge.exe oqsbridge.c -I <liboqs>/include -L <liboqs>/lib -loqs
//
// Protocol (stdin 一行一条，stdout 一行一条结果):
//   keygen                    -> OK <pkHex> <skHex>
//   encaps <pkHex>            -> OK <ctHex> <ssHex>
//   decaps <skHex> <ctHex>    -> OK <ssHex>
//   失败一律 -> ERR <reason>

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALG "ML-KEM-768"

static void hexenc(const uint8_t *d, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[(d[i] >> 4) & 0xf];
        out[2 * i + 1] = H[d[i] & 0xf];
    }
    out[2 * n] = '\0';
}

static int hexdec(const char *hex, uint8_t *out, size_t out_len) {
    size_t len = strlen(hex);
    if (len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

int main(void) {
    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(ALG);
    if (!kem) {
        fprintf(stdout, "ERR kem_unavailable\n");
        fflush(stdout);
        return 1;
    }

    char *pk_hex  = (char *)malloc(kem->length_public_key  * 2 + 1);
    char *sk_hex  = (char *)malloc(kem->length_secret_key  * 2 + 1);
    char *ct_hex  = (char *)malloc(kem->length_ciphertext  * 2 + 1);
    char *ss_hex  = (char *)malloc(kem->length_shared_secret * 2 + 1);
    uint8_t *pk = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(kem->length_secret_key);
    uint8_t *ct = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *ss = (uint8_t *)malloc(kem->length_shared_secret);

    char line[65536];
    while (fgets(line, sizeof(line), stdin)) {
        // 去尾部换行/回车
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = '\0';
        if (!L) continue;

        char *cmd = strtok(line, " \t");

        if (!cmd) continue;

        if (strcmp(cmd, "keygen") == 0) {
            if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { printf("ERR keygen\n"); }
            else {
                hexenc(pk, kem->length_public_key, pk_hex);
                hexenc(sk, kem->length_secret_key, sk_hex);
                printf("OK %s %s\n", pk_hex, sk_hex);
            }
        } else if (strcmp(cmd, "encaps") == 0) {
            char *a = strtok(NULL, " \t");
            if (!a || hexdec(a, pk, kem->length_public_key) != 0) { printf("ERR bad_pk\n"); }
            else if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) { printf("ERR encaps\n"); }
            else {
                hexenc(ct, kem->length_ciphertext, ct_hex);
                hexenc(ss, kem->length_shared_secret, ss_hex);
                printf("OK %s %s\n", ct_hex, ss_hex);
            }
        } else if (strcmp(cmd, "decaps") == 0) {
            char *a = strtok(NULL, " \t");
            char *b = strtok(NULL, " \t");
            if (!a || !b || hexdec(a, sk, kem->length_secret_key) != 0 ||
                hexdec(b, ct, kem->length_ciphertext) != 0) { printf("ERR bad_args\n"); }
            else if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) { printf("ERR decaps\n"); }
            else {
                hexenc(ss, kem->length_shared_secret, ss_hex);
                printf("OK %s\n", ss_hex);
            }
        } else if (strcmp(cmd, "sizes") == 0) {
            printf("OK %zu %zu %zu %zu\n",
                   kem->length_public_key, kem->length_secret_key,
                   kem->length_ciphertext, kem->length_shared_secret);
        } else {
            printf("ERR unknown_cmd\n");
        }
        fflush(stdout);
    }

    free(pk_hex); free(sk_hex); free(ct_hex); free(ss_hex);
    free(pk); free(sk); free(ct); free(ss);
    OQS_KEM_free(kem);
    OQS_destroy();
    return 0;
}
