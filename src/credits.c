#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "credits.h"

void deriveKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey) {
	uint8_t keySeed[32];
	cx_ecfp_private_key_t pk;

	// bip32 path for 44'/498'/n'/0'/0'
	uint32_t bip32Path[] = {44 | 0x80000000, 498 | 0x80000000, index | 0x80000000, 0x80000000, 0x80000000};
	os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, bip32Path, 5, keySeed, NULL, NULL, 0);

	cx_ecfp_init_private_key(CX_CURVE_Ed25519, keySeed, sizeof(keySeed), &pk);
	if (publicKey) {
		cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, publicKey);
		cx_ecfp_generate_pair(CX_CURVE_Ed25519, publicKey, &pk, 1);
	}
	if (privateKey) {
		*privateKey = pk;
	}
	os_memset(keySeed, 0, sizeof(keySeed));
	os_memset(&pk, 0, sizeof(pk));
}

void extractPubkeyBytes(unsigned char *dst, cx_ecfp_public_key_t *publicKey) {
	for (int i = 0; i < 32; i++) {
		dst[i] = publicKey->W[64 - i];
	}
	if (publicKey->W[32] & 1) {
		dst[31] |= 0x80;
	}
}

void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash) {
	cx_ecfp_private_key_t privateKey;
	deriveKeypair(index, &privateKey, NULL);
	cx_eddsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA512, hash, 32, NULL, 0, dst, 64, NULL);
	os_memset(&privateKey, 0, sizeof(privateKey));
}

void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen) {
	static uint8_t const hex[] = "0123456789abcdef";
	for (uint64_t i = 0; i < inlen; i++) {
		dst[2*i+0] = hex[(data[i]>>4) & 0x0F];
		dst[2*i+1] = hex[(data[i]>>0) & 0x0F];
	}
	dst[2*inlen] = '\0';
}

int bin2dec(uint8_t *dst, uint64_t n) {
	if (n == 0) {
		dst[0] = '0';
		dst[1] = '\0';
		return 1;
	}
	// determine final length
	int len = 0;
	for (uint64_t nn = n; nn != 0; nn /= 10) {
		len++;
	}
	// write digits in big-endian order
	for (int i = len-1; i >= 0; i--) {
		dst[i] = (n % 10) + '0';
		n /= 10;
	}
	dst[len] = '\0';
	return len;
}
