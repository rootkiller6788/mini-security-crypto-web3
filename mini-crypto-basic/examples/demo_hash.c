#include "hash_func.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const char *msg = "Hello, crypto world!";
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t md5_digest[MD5_DIGEST_SIZE];

    printf("=== mini-crypto-basic Hash Demo ===\n\n");

    /* SHA256 */
    sha256_hash((const uint8_t *)msg, strlen(msg), digest);
    printf("SHA256(\"%s\") = ", msg);
    print_hex(digest, SHA256_DIGEST_SIZE);

    /* MD5 */
    md5_hash((const uint8_t *)msg, strlen(msg), md5_digest);
    printf("MD5(\"%s\")   = ", msg);
    print_hex(md5_digest, MD5_DIGEST_SIZE);

    /* SHA256 streaming */
    Sha256Context ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"Hello, ", 7);
    sha256_update(&ctx, (const uint8_t *)"crypto world!", 13);
    sha256_final(&ctx, digest);
    printf("SHA256(streaming) = ");
    print_hex(digest, SHA256_DIGEST_SIZE);

    /* HMAC-SHA256 */
    const char *key = "secret-key";
    const char *data = "authenticate this message";
    hmac_sha256((const uint8_t *)key, strlen(key),
                (const uint8_t *)data, strlen(data), digest);
    printf("\nHMAC-SHA256(key=\"%s\", data=\"%s\") = ", key, data);
    print_hex(digest, SHA256_DIGEST_SIZE);

    /* HMAC streaming */
    HmacContext hmac_ctx;
    hmac_sha256_init(&hmac_ctx, (const uint8_t *)key, strlen(key));
    hmac_sha256_update(&hmac_ctx, (const uint8_t *)"authenticate ", 13);
    hmac_sha256_update(&hmac_ctx, (const uint8_t *)"this message", 12);
    hmac_sha256_final(&hmac_ctx, digest);
    printf("HMAC-SHA256(streaming) = ");
    print_hex(digest, SHA256_DIGEST_SIZE);

    /* Merkle-Damgard demo */
    printf("\n--- Merkle-Damgard Structure ---\n");
    printf("  |---[pad + len]---|\n");
    printf("  IV --> f --> f --> ... --> H(M)\n");
    printf("  Block size: %d bytes\n", SHA256_BLOCK_SIZE);
    printf("  Digest size: %d bytes\n\n", SHA256_DIGEST_SIZE);

    return 0;
}
