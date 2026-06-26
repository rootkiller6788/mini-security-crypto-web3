#ifndef SYMMETRIC_CIPHER_H
#define SYMMETRIC_CIPHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ─── AES-128 ────────────────────────────────────────────────── */

#define AES_BLOCK_SIZE   16
#define AES_KEY_SIZE     16
#define AES_NUM_ROUNDS   10
#define AES_STATE_COLS    4
#define AES_STATE_ROWS    4
#define AES_KEY_WORDS    44
#define AES_SBOX_SIZE   256

typedef struct AesContext {
    uint8_t round_keys[AES_KEY_WORDS * 4];
} AesContext;

extern const uint8_t AES_SBOX[AES_SBOX_SIZE];
extern const uint8_t AES_INV_SBOX[AES_SBOX_SIZE];

void aes128_key_schedule(AesContext *ctx, const uint8_t key[AES_KEY_SIZE]);
void aes128_encrypt_block(const AesContext *ctx, const uint8_t plain[AES_BLOCK_SIZE],
                          uint8_t cipher[AES_BLOCK_SIZE]);
void aes128_decrypt_block(const AesContext *ctx, const uint8_t cipher[AES_BLOCK_SIZE],
                          uint8_t plain[AES_BLOCK_SIZE]);

/* SubBytes / ShiftRows / MixColumns / AddRoundKey (internal helpers) */
void aes_sub_bytes(uint8_t state[AES_BLOCK_SIZE]);
void aes_inv_sub_bytes(uint8_t state[AES_BLOCK_SIZE]);
void aes_shift_rows(uint8_t state[AES_BLOCK_SIZE]);
void aes_inv_shift_rows(uint8_t state[AES_BLOCK_SIZE]);
void aes_mix_columns(uint8_t state[AES_BLOCK_SIZE]);
void aes_inv_mix_columns(uint8_t state[AES_BLOCK_SIZE]);
void aes_add_round_key(uint8_t state[AES_BLOCK_SIZE], const uint8_t *rkey);

/* ─── DES ────────────────────────────────────────────────────── */

#define DES_BLOCK_SIZE   8
#define DES_KEY_SIZE     8
#define DES_NUM_ROUNDS  16

typedef struct DesContext {
    uint64_t round_keys[DES_NUM_ROUNDS];
} DesContext;

extern const int DES_IP[64];
extern const int DES_IP_INV[64];
extern const int DES_E[48];
extern const int DES_P[32];
extern const int DES_PC1[56];
extern const int DES_PC2[48];

void des_key_schedule(DesContext *ctx, const uint8_t key[DES_KEY_SIZE]);
void des_encrypt_block(const DesContext *ctx, const uint8_t plain[DES_BLOCK_SIZE],
                       uint8_t cipher[DES_BLOCK_SIZE]);
void des_decrypt_block(const DesContext *ctx, const uint8_t cipher[DES_BLOCK_SIZE],
                       uint8_t plain[DES_BLOCK_SIZE]);

/* ─── Block Cipher Modes ─────────────────────────────────────── */

typedef enum CipherMode {
    CIPHER_MODE_CBC,
    CIPHER_MODE_CTR
} CipherMode;

typedef enum CipherAlgo {
    CIPHER_ALGO_AES128,
    CIPHER_ALGO_DES
} CipherAlgo;

typedef struct CbcContext {
    void  *cipher_ctx;
    CipherAlgo algo;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t buffer[AES_BLOCK_SIZE];
    size_t  buf_len;
} CbcContext;

typedef struct CtrContext {
    void  *cipher_ctx;
    CipherAlgo algo;
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t  stream_pos;
} CtrContext;

void cbc_encrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]);
void cbc_encrypt_update(CbcContext *cbc, const uint8_t *plain, size_t len,
                        uint8_t *cipher, size_t *out_len);
void cbc_encrypt_final(CbcContext *cbc, uint8_t *cipher, size_t *out_len);

void cbc_decrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]);
void cbc_decrypt_update(CbcContext *cbc, const uint8_t *cipher, size_t len,
                        uint8_t *plain, size_t *out_len);
void cbc_decrypt_final(CbcContext *cbc, uint8_t *plain, size_t *out_len);

void ctr_crypt_init(CtrContext *ctr, void *cipher_ctx, CipherAlgo algo,
                    const uint8_t nonce_counter[AES_BLOCK_SIZE]);
void ctr_crypt_update(CtrContext *ctr, const uint8_t *in, size_t len,
                      uint8_t *out, size_t *out_len);

/* ─── PKCS#7 Padding ─────────────────────────────────────────── */

#define PKCS7_MAX_PAD 16

size_t pkcs7_pad(const uint8_t *data, size_t data_len, size_t block_size,
                 uint8_t *padded);
size_t pkcs7_unpad(const uint8_t *padded, size_t padded_len,
                   uint8_t *data);

#endif /* SYMMETRIC_CIPHER_H */
