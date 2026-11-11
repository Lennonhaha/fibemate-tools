/* Negative control 9: a macro renames the hash function. */
#define HASH_FN mbedtls_sha256

int digest(const unsigned char *in, unsigned long len, unsigned char out[32])
{
    return HASH_FN(in, len, out, 0);
}
