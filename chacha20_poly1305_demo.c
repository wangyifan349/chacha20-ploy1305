// chacha20_poly1305_demo.c
// Educational, self-contained ChaCha20-Poly1305 AEAD (in-memory).
// NOT FOR PRODUCTION USE.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---------- utilities ---------- */

static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

static void xor_buf(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i) dst[i] = a[i] ^ b[i];
}

/* ---------- ChaCha20 (RFC 7539) ---------- */

static void chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint8_t out[64]) {
    const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    uint32_t state[16];
    memcpy(state + 0, constants, 4 * sizeof(uint32_t));
    memcpy(state + 4, key, 8 * sizeof(uint32_t));
    state[12] = counter;
    memcpy(state + 13, nonce, 3 * sizeof(uint32_t));

    uint32_t working[16];
    memcpy(working, state, sizeof(state));

    auto quarter_round = [](uint32_t s[16], int a, int b, int c, int d) {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
    };

    for (int i = 0; i < 10; ++i) {
        // column round
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);
        // diagonal round
        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t res = working[i] + state[i];
        out[4*i + 0] = res & 0xff;
        out[4*i + 1] = (res >> 8) & 0xff;
        out[4*i + 2] = (res >> 16) & 0xff;
        out[4*i + 3] = (res >> 24) & 0xff;
    }
}

static void chacha20_xor_stream(const uint8_t key32[32], uint32_t counter, const uint8_t nonce12[12],
                                const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t key_words[8];
    uint32_t nonce_words[3];
    for (int i = 0; i < 8; ++i)
        key_words[i] = ((uint32_t)key32[4*i]) | ((uint32_t)key32[4*i+1] << 8) | ((uint32_t)key32[4*i+2] << 16) | ((uint32_t)key32[4*i+3] << 24);
    for (int i = 0; i < 3; ++i)
        nonce_words[i] = ((uint32_t)nonce12[4*i]) | ((uint32_t)nonce12[4*i+1] << 8) | ((uint32_t)nonce12[4*i+2] << 16) | ((uint32_t)nonce12[4*i+3] << 24);

    size_t off = 0;
    uint8_t block[64];
    while (off < len) {
        chacha20_block(key_words, counter, nonce_words, block);
        size_t chunk = (len - off) < 64 ? (len - off) : 64;
        for (size_t i = 0; i < chunk; ++i) out[off + i] = in[off + i] ^ block[i];
        off += chunk;
        counter++;
    }
}

/* ---------- Poly1305 (RFC 7539) ---------- */

/* Reference-style implementation using 128/256-bit arithmetic split into 32/26-bit limbs.
   This implementation focuses on correctness for typical inputs and clarity. It follows
   the algorithm: clamp r, process 16-byte blocks, handle final partial block, carry reduction,
   add pad (s) and output 16-byte tag. Not constant-time in all places (educational). */

typedef struct {
    uint64_t r0, r1, r2, r3, r4; // r limbs (<= 2^26-ish)
    uint64_t h0, h1, h2, h3, h4; // accumulator limbs
    uint8_t s[16];               // pad (little-endian)
} poly1305_t;

static void poly1305_keygen(poly1305_t *st, const uint8_t key32[32]) {
    // load r (16 bytes little-endian) then clamp
    uint64_t t0 = (uint64_t)key32[0]  | ((uint64_t)key32[1] << 8) | ((uint64_t)key32[2] << 16) | ((uint64_t)key32[3] << 24)
                | ((uint64_t)key32[4] << 32) | ((uint64_t)key32[5] << 40) | ((uint64_t)key32[6] << 48) | ((uint64_t)key32[7] << 56);
    uint64_t t1 = (uint64_t)key32[8]  | ((uint64_t)key32[9] << 8) | ((uint64_t)key32[10] << 16) | ((uint64_t)key32[11] << 24)
                | ((uint64_t)key32[12] << 32) | ((uint64_t)key32[13] << 40) | ((uint64_t)key32[14] << 48) | ((uint64_t)key32[15] << 56);

    // clamp bits according to RFC: r &= 0xffffffc0ffffffc0ffffffc0fffffff
    t0 &= 0x0ffffffc0fffffffULL;
    t1 &= 0x0ffffffc0ffffffcULL;

    // split into 26-bit limbs (little-endian)
    st->r0 =  t0 & 0x3ffffffULL;
    st->r1 = (t0 >> 26) & 0x3ffffffULL;
    st->r2 = ((t0 >> 52) | (t1 << 12)) & 0x3ffffffULL;
    st->r3 = (t1 >> 14) & 0x3ffffffULL;
    st->r4 = (t1 >> 40) & 0x3fffffULL; // top limb 22 bits

    st->h0 = st->h1 = st->h2 = st->h3 = st->h4 = 0;
    memcpy(st->s, key32 + 16, 16);
}

static void poly1305_process_block(poly1305_t *st, const uint8_t block[16]) {
    // parse block into 130-bit number (with appended 1)
    uint64_t t0 = (uint64_t)block[0]  | ((uint64_t)block[1] << 8) | ((uint64_t)block[2] << 16) | ((uint64_t)block[3] << 24)
                | ((uint64_t)block[4] << 32) | ((uint64_t)block[5] << 40) | ((uint64_t)block[6] << 48) | ((uint64_t)block[7] << 56);
    uint64_t t1 = (uint64_t)block[8]  | ((uint64_t)block[9] << 8) | ((uint64_t)block[10] << 16) | ((uint64_t)block[11] << 24)
                | ((uint64_t)block[12] << 32) | ((uint64_t)block[13] << 40) | ((uint64_t)block[14] << 48) | ((uint64_t)block[15] << 56);

    uint64_t m0 =  t0 & 0x3ffffffULL;
    uint64_t m1 = (t0 >> 26) & 0x3ffffffULL;
    uint64_t m2 = ((t0 >> 52) | (t1 << 12)) & 0x3ffffffULL;
    uint64_t m3 = (t1 >> 14) & 0x3ffffffULL;
    uint64_t m4 = (t1 >> 40) & 0x3fffffULL; // 22 bits

    // add to h with the "1" bit (2^24) on top limb
    st->h0 += m0;
    st->h1 += m1;
    st->h2 += m2;
    st->h3 += m3;
    st->h4 += (m4 | (1ULL << 24));

    // multiply (h * r) mod (2^130 - 5) using 64-bit intermediates
    uint128_t s0 = (uint128_t)st->h0 * st->r0
                 + (uint128_t)st->h1 * (5 * st->r4)
                 + (uint128_t)st->h2 * (5 * st->r3)
                 + (uint128_t)st->h3 * (5 * st->r2)
                 + (uint128_t)st->h4 * (5 * st->r1);

    uint128_t s1 = (uint128_t)st->h0 * st->r1
                 + (uint128_t)st->h1 * st->r0
                 + (uint128_t)st->h2 * (5 * st->r4)
                 + (uint128_t)st->h3 * (5 * st->r3)
                 + (uint128_t)st->h4 * (5 * st->r2);

    uint128_t s2 = (uint128_t)st->h0 * st->r2
                 + (uint128_t)st->h1 * st->r1
                 + (uint128_t)st->h2 * st->r0
                 + (uint128_t)st->h3 * (5 * st->r4)
                 + (uint128_t)st->h4 * (5 * st->r3);

    uint128_t s3 = (uint128_t)st->h0 * st->r3
                 + (uint128_t)st->h1 * st->r2
                 + (uint128_t)st->h2 * st->r1
                 + (uint128_t)st->h3 * st->r0
                 + (uint128_t)st->h4 * (5 * st->r4);

    uint128_t s4 = (uint128_t)st->h0 * st->r4
                 + (uint128_t)st->h1 * st->r3
                 + (uint128_t)st->h2 * st->r2
                 + (uint128_t)st->h3 * st->r1
                 + (uint128_t)st->h4 * st->r0;

    // reduce carries (each limb 26 bits except top 22)
    uint64_t carry0 = (uint64_t)(s0 >> 26); s1 += carry0; s0 &= 0x3ffffff;
    uint64_t carry1 = (uint64_t)(s1 >> 26); s2 += carry1; s1 &= 0x3ffffff;
    uint64_t carry2 = (uint64_t)(s2 >> 26); s3 += carry2; s2 &= 0x3ffffff;
    uint64_t carry3 = (uint64_t)(s3 >> 26); s4 += carry3; s3 &= 0x3ffffff;
    uint64_t carry4 = (uint64_t)(s4 >> 26); s0 += carry4 * 5; s4 &= 0x3ffffff;
    uint64_t carry0b = (uint64_t)(s0 >> 26); s1 += carry0b; s0 &= 0x3ffffff;

    st->h0 = (uint64_t)s0;
    st->h1 = (uint64_t)s1;
    st->h2 = (uint64_t)s2;
    st->h3 = (uint64_t)s3;
    st->h4 = (uint64_t)s4;
}

static void poly1305_update(poly1305_t *st, const uint8_t *m, size_t mlen) {
    while (mlen >= 16) {
        poly1305_process_block(st, m);
        m += 16;
        mlen -= 16;
    }
    if (mlen > 0) {
        uint8_t block[16] = {0};
        memcpy(block, m, mlen);
        block[mlen] = 1;
        poly1305_process_block(st, block);
    }
}

static void poly1305_finish(poly1305_t *st, uint8_t tag[16]) {
    // fully carry and compute h + s (pad)
    // recombine limbs to 128-bit little-endian integer then add s
    uint64_t h0 = st->h0 + (st->h1 << 26);
    uint64_t h1 = (st->h1 >> 6) + (st->h2 << 20) + (st->h3 << 46);
    // For simplicity assemble 16 bytes via shifts from limbs:
    uint8_t hbytes[16] = {0};
    uint64_t acc0 = st->h0 | (st->h1 << 26) | (st->h2 << 52);
    hbytes[0] = acc0 & 0xff; hbytes[1] = (acc0 >> 8) & 0xff; hbytes[2] = (acc0 >> 16) & 0xff; hbytes[3] = (acc0 >> 24) & 0xff;
    hbytes[4] = (acc0 >> 32) & 0xff; hbytes[5] = (acc0 >> 40) & 0xff; hbytes[6] = (acc0 >> 48) & 0xff; hbytes[7] = (acc0 >> 56) & 0xff;
    uint64_t acc1 = (st->h2 >> 12) | (st->h3 << 14) | (st->h4 << 40);
    hbytes[8]  = acc1 & 0xff; hbytes[9]  = (acc1 >> 8) & 0xff; hbytes[10] = (acc1 >> 16) & 0xff; hbytes[11] = (acc1 >> 24) & 0xff;
    hbytes[12] = (acc1 >> 32) & 0xff; hbytes[13] = (acc1 >> 40) & 0xff; hbytes[14] = (acc1 >> 48) & 0xff; hbytes[15] = (acc1 >> 56) & 0xff;

    uint16_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        uint16_t sum = (uint16_t)hbytes[i] + (uint16_t)st->s[i] + carry;
        tag[i] = sum & 0xff;
        carry = sum >> 8;
    }
}

/* ---------- AEAD construction ---------- */

static void aead_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                           const uint8_t *aad, size_t aadlen,
                                           const uint8_t *pt, size_t ptlen,
                                           uint8_t *ct, uint8_t tag[16]) {
    // 1) one-time Poly1305 key: ChaCha20 block with counter=0 -> first 32 bytes
    uint32_t kwords[8];
    for (int i = 0; i < 8; ++i)
        kwords[i] = ((uint32_t)key[4*i]) | ((uint32_t)key[4*i+1] << 8) | ((uint32_t)key[4*i+2] << 16) | ((uint32_t)key[4*i+3] << 24);
    uint32_t nwords[3];
    for (int i = 0; i < 3; ++i)
        nwords[i] = ((uint32_t)nonce[4*i]) | ((uint32_t)nonce[4*i+1] << 8) | ((uint32_t)nonce[4*i+2] << 16) | ((uint32_t)nonce[4*i+3] << 24);

    uint8_t block0[64];
    chacha20_block(kwords, 0, nwords, block0);

    uint8_t poly_key[32];
    memcpy(poly_key, block0, 32);

    // 2) encrypt plaintext with ChaCha20 starting at counter=1
    chacha20_xor_stream(key, 1, nonce, pt, ct, ptlen);

    // 3) compute Poly1305 over: AAD || pad || ciphertext || pad || aadlen(8) || ctlen(8)
    poly1305_t st;
    poly1305_keygen(&st, poly_key);

    if (aadlen) poly1305_update(&st, aad, aadlen);
    if (aadlen % 16) {
        uint8_t zeros[16] = {0};
        poly1305_update(&st, zeros, 16 - (aadlen % 16));
    }

    if (ptlen) poly1305_update(&st, ct, ptlen);
    if (ptlen % 16) {
        uint8_t zeros[16] = {0};
        poly1305_update(&st, zeros, 16 - (ptlen % 16));
    }

    uint8_t lenbuf[16] = {0};
    uint64_t aadlen_le = (uint64_t)aadlen;
    uint64_t ctlen_le  = (uint64_t)ptlen;
    for (int i = 0; i < 8; ++i) lenbuf[i] = (aadlen_le >> (8*i)) & 0xff;
    for (int i = 0; i < 8; ++i) lenbuf[8+i] = (ctlen_le >> (8*i)) & 0xff;
    poly1305_update(&st, lenbuf, 16);

    poly1305_finish(&st, tag);
}

static int ct_memcmp_const(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t x = 0;
    for (size_t i = 0; i < n; ++i) x |= a[i] ^ b[i];
    return x; // 0 if equal
}

static int aead_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                          const uint8_t *aad, size_t aadlen,
                                          const uint8_t *ct, size_t ctlen,
                                          const uint8_t tag[16], uint8_t *pt_out) {
    // compute tag over aad||ct
    uint8_t computed_tag[16];
    aead_chacha20_poly1305_encrypt(key, nonce, aad, aadlen, ct, ctlen, (uint8_t*)ct, computed_tag);
    if (ct_memcmp_const(computed_tag, tag, 16)) return -1;
    // decrypt ciphertext
    chacha20_xor_stream(key, 1, nonce, ct, pt_out, ctlen);
    return 0;
}

/* ---------- Demo main (in-memory) ---------- */

int main(void) {
    // fixed key/nonce for demo (replace with CSPRNG in real use)
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 1);
    uint8_t nonce[12] = {0,0,0,0,0,0,0,0,0,0,0,1};

    const uint8_t aad[] = "demo-aad";
    const uint8_t pt[]  = "This is example plaintext for ChaCha20-Poly1305 demo.";
    size_t aadlen = sizeof(aad) - 1;
    size_t ptlen  = sizeof(pt) - 1;

    uint8_t *ct = malloc(ptlen);
    uint8_t tag[16];
    aead_chacha20_poly1305_encrypt(key, nonce, aad, aadlen, pt, ptlen, ct, tag);

    printf("Ciphertext (%zu bytes):\n", ptlen);
    for (size_t i = 0; i < ptlen; ++i) printf("%02x", ct[i]);
    printf("\nTag: ");
    for (int i = 0; i < 16; ++i) printf("%02x", tag[i]);
    printf("\n");

    uint8_t *decoded = malloc(ptlen);
    int ok = aead_chacha20_poly1305_decrypt(key, nonce, aad, aadlen, ct, ptlen, tag, decoded);
    if (ok == 0) {
        printf("Decrypted: %.*s\n", (int)ptlen, decoded);
    } else {
        printf("Auth failed\n");
    }

    free(ct);
    free(decoded);
    return 0;
}
