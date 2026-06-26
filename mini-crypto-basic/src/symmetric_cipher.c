#include "symmetric_cipher.h"
#include <string.h>

/* ─── AES S-Box ─────────────────────────────────────────────── */

const uint8_t AES_SBOX[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

const uint8_t AES_INV_SBOX[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static const uint8_t AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static inline uint8_t aes_gf_mul2(uint8_t val) {
    return (val << 1) ^ ((val & 0x80) ? 0x1B : 0x00);
}

static inline uint8_t aes_gf_mul3(uint8_t val) {
    return aes_gf_mul2(val) ^ val;
}

static inline uint8_t aes_gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = aes_gf_mul2(a);
        b >>= 1;
    }
    return result;
}

void aes_sub_bytes(uint8_t state[16]) { int i; for (i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]]; }
void aes_inv_sub_bytes(uint8_t state[16]) { int i; for (i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]]; }

void aes_shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = tmp;
}

void aes_inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = state[3]; state[3] = tmp;
}

void aes_mix_columns(uint8_t state[16]) {
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
        state[i*4]   = aes_gf_mul2(s0) ^ aes_gf_mul3(s1) ^ s2 ^ s3;
        state[i*4+1] = s0 ^ aes_gf_mul2(s1) ^ aes_gf_mul3(s2) ^ s3;
        state[i*4+2] = s0 ^ s1 ^ aes_gf_mul2(s2) ^ aes_gf_mul3(s3);
        state[i*4+3] = aes_gf_mul3(s0) ^ s1 ^ s2 ^ aes_gf_mul2(s3);
    }
}

void aes_inv_mix_columns(uint8_t state[16]) {
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
        state[i*4]   = aes_gf_mul(0x0E,s0) ^ aes_gf_mul(0x0B,s1) ^ aes_gf_mul(0x0D,s2) ^ aes_gf_mul(0x09,s3);
        state[i*4+1] = aes_gf_mul(0x09,s0) ^ aes_gf_mul(0x0E,s1) ^ aes_gf_mul(0x0B,s2) ^ aes_gf_mul(0x0D,s3);
        state[i*4+2] = aes_gf_mul(0x0D,s0) ^ aes_gf_mul(0x09,s1) ^ aes_gf_mul(0x0E,s2) ^ aes_gf_mul(0x0B,s3);
        state[i*4+3] = aes_gf_mul(0x0B,s0) ^ aes_gf_mul(0x0D,s1) ^ aes_gf_mul(0x09,s2) ^ aes_gf_mul(0x0E,s3);
    }
}

void aes_add_round_key(uint8_t state[16], const uint8_t *rkey) {
    int i;
    for (i = 0; i < 16; i++) state[i] ^= rkey[i];
}

static void aes_key_expansion(const uint8_t key[16], uint8_t expanded[176]) {
    memcpy(expanded, key, 16);
    int i;
    for (i = 1; i <= AES_NUM_ROUNDS; i++) {
        uint8_t temp[4];
        int base = i * 16;
        memcpy(temp, expanded + base - 4, 4);
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = AES_SBOX[temp[1]]; temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]]; temp[3] = AES_SBOX[t];
        }
        temp[0] ^= AES_RCON[i / 4];
        int j;
        for (j = 0; j < 4; j++) expanded[base + j] = expanded[base - 16 + j] ^ temp[j];
        for (j = 4; j < 16; j++) expanded[base + j] = expanded[base - 16 + j] ^ expanded[base + j - 4];
    }
}

void aes128_key_schedule(AesContext *ctx, const uint8_t key[AES_KEY_SIZE]) {
    uint8_t expanded[176];
    aes_key_expansion(key, expanded);
    int i;
    for (i = 0; i <= AES_NUM_ROUNDS; i++)
        memcpy(ctx->round_keys + i * AES_BLOCK_SIZE, expanded + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

void aes128_encrypt_block(const AesContext *ctx, const uint8_t plain[AES_BLOCK_SIZE],
                          uint8_t cipher[AES_BLOCK_SIZE]) {
    memcpy(cipher, plain, AES_BLOCK_SIZE);
    aes_add_round_key(cipher, ctx->round_keys);
    int round;
    for (round = 1; round < AES_NUM_ROUNDS; round++) {
        aes_sub_bytes(cipher);
        aes_shift_rows(cipher);
        aes_mix_columns(cipher);
        aes_add_round_key(cipher, ctx->round_keys + round * AES_BLOCK_SIZE);
    }
    aes_sub_bytes(cipher);
    aes_shift_rows(cipher);
    aes_add_round_key(cipher, ctx->round_keys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);
}

void aes128_decrypt_block(const AesContext *ctx, const uint8_t cipher[AES_BLOCK_SIZE],
                          uint8_t plain[AES_BLOCK_SIZE]) {
    memcpy(plain, cipher, AES_BLOCK_SIZE);
    aes_add_round_key(plain, ctx->round_keys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);
    aes_inv_shift_rows(plain);
    aes_inv_sub_bytes(plain);
    int round;
    for (round = AES_NUM_ROUNDS - 1; round >= 1; round--) {
        aes_add_round_key(plain, ctx->round_keys + round * AES_BLOCK_SIZE);
        aes_inv_mix_columns(plain);
        aes_inv_shift_rows(plain);
        aes_inv_sub_bytes(plain);
    }
    aes_add_round_key(plain, ctx->round_keys);
}

/* ─── DES ───────────────────────────────────────────────────── */

const int DES_IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};
const int DES_IP_INV[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};
const int DES_E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
    12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
};
const int DES_P[32] = {
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
};
const int DES_PC1[56] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};
const int DES_PC2[48] = {
    14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8,
    16,7,27,20,13,2, 41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};

static const int DES_SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

static const uint8_t DES_SBOX[8][4][16] = {
    {/*S1*/{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}}},
    {/*S2*/{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}}},
    {/*S3*/{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}}},
    {/*S4*/{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}}},
    {/*S5*/{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}}},
    {/*S6*/{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}}},
    {/*S7*/{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}}},
    {/*S8*/{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}}
};

static uint64_t des_permute(uint64_t in, const int *table, int n) {
    uint64_t out = 0; int i;
    for (i = 0; i < n; i++) {
        out <<= 1;
        out |= (in >> (64 - table[i])) & 1;
    }
    return out;
}

static uint32_t des_feistel(uint32_t r, uint64_t subkey) {
    uint64_t expanded = des_permute(r, DES_E, 48);
    expanded ^= subkey;
    uint32_t out = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint8_t chunk = (uint8_t)((expanded >> (42 - i * 6)) & 0x3F);
        int row = ((chunk >> 5) << 1) | (chunk & 1);
        int col = (chunk >> 1) & 0x0F;
        out = (out << 4) | DES_SBOX[i][row][col];
    }
    return (uint32_t)des_permute(out, DES_P, 32);
}

void des_key_schedule(DesContext *ctx, const uint8_t key[DES_KEY_SIZE]) {
    uint64_t k = 0; int i;
    for (i = 0; i < 8; i++) k = (k << 8) | key[i];
    k = des_permute(k, DES_PC1, 56);
    uint32_t c = (uint32_t)(k >> 28), d = (uint32_t)(k & 0x0FFFFFFF);
    for (i = 0; i < DES_NUM_ROUNDS; i++) {
        c = ((c << DES_SHIFTS[i]) | (c >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        d = ((d << DES_SHIFTS[i]) | (d >> (28 - DES_SHIFTS[i]))) & 0x0FFFFFFF;
        uint64_t cd = ((uint64_t)c << 28) | d;
        ctx->round_keys[i] = des_permute(cd, DES_PC2, 48);
    }
}

void des_encrypt_block(const DesContext *ctx, const uint8_t plain[DES_BLOCK_SIZE],
                       uint8_t cipher[DES_BLOCK_SIZE]) {
    uint64_t block = 0; int i;
    for (i = 0; i < 8; i++) block = (block << 8) | plain[i];
    block = des_permute(block, DES_IP, 64);
    uint32_t l = (uint32_t)(block >> 32), r = (uint32_t)(block & 0xFFFFFFFF);
    for (i = 0; i < DES_NUM_ROUNDS; i++) {
        uint32_t tmp = r;
        r = l ^ des_feistel(r, ctx->round_keys[i]);
        l = tmp;
    }
    block = ((uint64_t)r << 32) | l;
    block = des_permute(block, DES_IP_INV, 64);
    for (i = 7; i >= 0; i--, block >>= 8) cipher[i] = (uint8_t)(block & 0xFF);
}

void des_decrypt_block(const DesContext *ctx, const uint8_t cipher[DES_BLOCK_SIZE],
                       uint8_t plain[DES_BLOCK_SIZE]) {
    uint64_t block = 0; int i;
    for (i = 0; i < 8; i++) block = (block << 8) | cipher[i];
    block = des_permute(block, DES_IP, 64);
    uint32_t l = (uint32_t)(block >> 32), r = (uint32_t)(block & 0xFFFFFFFF);
    for (i = DES_NUM_ROUNDS - 1; i >= 0; i--) {
        uint32_t tmp = r;
        r = l ^ des_feistel(r, ctx->round_keys[i]);
        l = tmp;
    }
    block = ((uint64_t)r << 32) | l;
    block = des_permute(block, DES_IP_INV, 64);
    for (i = 7; i >= 0; i--, block >>= 8) plain[i] = (uint8_t)(block & 0xFF);
}

/* ─── CBC Mode ──────────────────────────────────────────────── */

static size_t cipher_block_size(CipherAlgo algo) {
    return (algo == CIPHER_ALGO_AES128) ? AES_BLOCK_SIZE : DES_BLOCK_SIZE;
}

static void cipher_encrypt_block(void *ctx, CipherAlgo algo,
                                  const uint8_t *in, uint8_t *out) {
    if (algo == CIPHER_ALGO_AES128)
        aes128_encrypt_block((AesContext*)ctx, in, out);
    else
        des_encrypt_block((DesContext*)ctx, in, out);
}

static void cipher_decrypt_block(void *ctx, CipherAlgo algo,
                                  const uint8_t *in, uint8_t *out) {
    if (algo == CIPHER_ALGO_AES128)
        aes128_decrypt_block((AesContext*)ctx, in, out);
    else
        des_decrypt_block((DesContext*)ctx, in, out);
}

void cbc_encrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]) {
    cbc->cipher_ctx = cipher_ctx;
    cbc->algo = algo;
    size_t bs = cipher_block_size(algo);
    memcpy(cbc->iv, iv, bs);
    cbc->buf_len = 0;
    memset(cbc->buffer, 0, AES_BLOCK_SIZE);
}

void cbc_encrypt_update(CbcContext *cbc, const uint8_t *plain, size_t len,
                        uint8_t *cipher, size_t *out_len) {
    size_t bs = cipher_block_size(cbc->algo);
    size_t total = 0;
    while (len > 0) {
        cbc->buffer[cbc->buf_len++] = *plain++;
        len--;
        if (cbc->buf_len == bs) {
            int i;
            for (i = 0; i < (int)bs; i++) cbc->buffer[i] ^= cbc->iv[i];
            cipher_encrypt_block(cbc->cipher_ctx, cbc->algo, cbc->buffer, cipher + total);
            memcpy(cbc->iv, cipher + total, bs);
            total += bs;
            cbc->buf_len = 0;
        }
    }
    *out_len = total;
}

void cbc_encrypt_final(CbcContext *cbc, uint8_t *cipher, size_t *out_len) {
    *out_len = 0;
}

void cbc_decrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]) {
    cbc->cipher_ctx = cipher_ctx;
    cbc->algo = algo;
    size_t bs = cipher_block_size(algo);
    memcpy(cbc->iv, iv, bs);
    cbc->buf_len = 0;
    memset(cbc->buffer, 0, AES_BLOCK_SIZE);
}

void cbc_decrypt_update(CbcContext *cbc, const uint8_t *cipher, size_t len,
                        uint8_t *plain, size_t *out_len) {
    size_t bs = cipher_block_size(cbc->algo);
    size_t total = 0;
    uint8_t prev_iv[AES_BLOCK_SIZE];
    memcpy(prev_iv, cbc->iv, bs);
    while (len >= bs) {
        memcpy(cbc->iv, cipher, bs);
        cipher_decrypt_block(cbc->cipher_ctx, cbc->algo, cipher, plain + total);
        int i;
        for (i = 0; i < (int)bs; i++) plain[total + i] ^= prev_iv[i];
        memcpy(prev_iv, cbc->iv, bs);
        cipher += bs;
        total += bs;
        len -= bs;
    }
    *out_len = total;
}

void cbc_decrypt_final(CbcContext *cbc, uint8_t *plain, size_t *out_len) {
    *out_len = 0;
}

/* ─── CTR Mode ──────────────────────────────────────────────── */

void ctr_crypt_init(CtrContext *ctr, void *cipher_ctx, CipherAlgo algo,
                    const uint8_t nonce_counter[AES_BLOCK_SIZE]) {
    ctr->cipher_ctx = cipher_ctx;
    ctr->algo = algo;
    size_t bs = cipher_block_size(algo);
    memcpy(ctr->counter, nonce_counter, bs);
    ctr->stream_pos = bs;
}

static void ctr_next_keystream(CtrContext *ctr) {
    size_t bs = cipher_block_size(ctr->algo);
    cipher_encrypt_block(ctr->cipher_ctx, ctr->algo, ctr->counter, ctr->keystream);
    int i;
    for (i = (int)bs - 1; i >= 0; i--) {
        ctr->counter[i]++;
        if (ctr->counter[i] != 0) break;
    }
    ctr->stream_pos = 0;
}

void ctr_crypt_update(CtrContext *ctr, const uint8_t *in, size_t len,
                      uint8_t *out, size_t *out_len) {
    size_t bs = cipher_block_size(ctr->algo);
    size_t i;
    for (i = 0; i < len; i++) {
        if (ctr->stream_pos >= bs) ctr_next_keystream(ctr);
        out[i] = in[i] ^ ctr->keystream[ctr->stream_pos++];
    }
    *out_len = len;
}

/* ─── PKCS#7 Padding ────────────────────────────────────────── */

size_t pkcs7_pad(const uint8_t *data, size_t data_len, size_t block_size,
                 uint8_t *padded) {
    size_t pad_val = block_size - (data_len % block_size);
    memcpy(padded, data, data_len);
    size_t i;
    for (i = 0; i < pad_val; i++)
        padded[data_len + i] = (uint8_t)pad_val;
    return data_len + pad_val;
}

size_t pkcs7_unpad(const uint8_t *padded, size_t padded_len,
                   uint8_t *data) {
    if (padded_len == 0) return 0;
    size_t pad_val = padded[padded_len - 1];
    if (pad_val == 0 || pad_val > PKCS7_MAX_PAD) return padded_len;
    if (pad_val > padded_len) return padded_len;
    size_t i;
    for (i = padded_len - pad_val; i < padded_len; i++) {
        if (padded[i] != pad_val) return padded_len;
    }
    memcpy(data, padded, padded_len - pad_val);
    return padded_len - pad_val;
}
