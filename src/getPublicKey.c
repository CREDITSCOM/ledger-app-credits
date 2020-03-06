#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "credits.h"
#include "ux.h"

static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

static const bagl_element_t ui_getPublicKey_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, "Compare:"),
	// The visible portion of the public key or address.
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.partialStr),
};

static const bagl_element_t* ui_prepro_getPublicKey_compare(const bagl_element_t *element) {
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ctx->displayIndex == (64-12))) {
		return NULL;
	}
	return element;
}

static unsigned int ui_getPublicKey_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < (64-12)) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		ui_idle();
		break;
	}
	return 0;
}

static const bagl_element_t ui_getPublicKey_approve[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 12, 128, "Generate public"),
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.keyStr),
};

static unsigned int ui_getPublicKey_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {
	uint16_t tx = 0;
	cx_ecfp_public_key_t publicKey;

	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, 0);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		deriveKeypair(ctx->keyIndex, NULL, &publicKey);
		extractPubkeyBytes(G_io_apdu_buffer + tx, &publicKey);
		tx += 32;
		io_exchange_with_code(SW_OK, tx);

		// The APDU buffer contains the raw bytes of the public key, so
		// first we need to convert to a human-readable form.
		bin2hex(ctx->fullStr, G_io_apdu_buffer, 32);

		os_memmove(ctx->partialStr, ctx->fullStr, 12);
		ctx->partialStr[12] = '\0';
		ctx->displayIndex = 0;

		// Display the comparison screen.
		UX_DISPLAY(ui_getPublicKey_compare, ui_prepro_getPublicKey_compare);
		break;
	}
	return 0;
}

void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	ctx->keyIndex = U4LE(dataBuffer, 0);

	os_memmove(ctx->keyStr, "Key #", 5);
	int n = bin2dec(ctx->keyStr+5, ctx->keyIndex);
	os_memmove(ctx->keyStr+5+n, "?", 2);

	UX_DISPLAY(ui_getPublicKey_approve, NULL);
	
	*flags |= IO_ASYNCH_REPLY;
}
