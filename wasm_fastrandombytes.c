#include "fastrandombytes.h"
#include "aes.h"

static struct AES_ctx ctx;

/* r <-- aes256_ctr(round_key, iv, rlen) */
void fastrandombytes(unsigned char *r, unsigned long long rlen) {
    AES_CTR_xcrypt_buffer(&ctx, r, rlen);
}

/* round_key <-- aes256_key_expansion(randomness), iv <-- 0 */
void fastrandombytes_setseed(const unsigned char *randomness) {
    unsigned char iv[AES_BLOCKLEN];
    for (int i = 0; i < AES_BLOCKLEN; i++) {
        iv[i] = 0;
    }
    AES_init_ctx_iv(&ctx, randomness, iv);
}