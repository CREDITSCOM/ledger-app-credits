#ifndef CREDITS_CREDITS_H
#define CREDITS_CREDITS_H

// exception codes
#define CS_DEVELOPER_ERR 0x6B00
#define CS_INVALID_PARAM 0x6B01
#define CS_IMPROPER_INIT 0x6B02
#define CS_USER_REJECTED 0x6985
#define CS_OK            0x9000

// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(uint8_t *dst, uint64_t n);

// extractPubkeyBytes converts a Ledger-style public key to a Credits-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *dst, cx_ecfp_public_key_t *publicKey);

// deriveKeypair derives an Ed25519 key pair from an index and the Ledger
// seed. Either privateKey or publicKey may be NULL.
void deriveKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey);

// deriveAndSign derives an Ed25519 private key from an index and the
// Ledger seed, and uses it to produce a 64-byte signature of the provided
// 32-byte hash. The key is cleared from memory after signing.
void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash);

#endif // CREDITS_CREDITS_H
