#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "credits.h"
#include "ux.h"

static signHashContext_t *ctx = &global.signHashContext;

static const bagl_element_t ui_signHash_approve[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 12, 128, "Sign this Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.indexStr),
};

static unsigned int ui_signHash_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, 0);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		deriveAndSign(G_io_apdu_buffer, ctx->keyIndex, ctx->hash);
		io_exchange_with_code(SW_OK, 64);
		ui_idle();
		break;
	}
	return 0;
}

static const bagl_element_t ui_signHash_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, "Compare Hashes:"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.partialHashStr),
};

static const bagl_element_t* ui_prepro_signHash_compare(const bagl_element_t *element) {
	switch (element->component.userid) {
	case 1:
		// 0x01 is the left icon (see screen definition above), so return NULL
		// if we're displaying the beginning of the text.
		return (ctx->displayIndex == 0) ? NULL : element;
	case 2:
		// 0x02 is the right, so return NULL if we're displaying the end of the text.
		return (ctx->displayIndex == sizeof(ctx->hexHash)-12) ? NULL : element;
	default:
		// Always display all other elements.
		return element;
	}
}

static unsigned int ui_signHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < sizeof(ctx->hexHash)-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		os_memmove(ctx->indexStr, "with Key #", 10);
		int n = bin2dec(ctx->indexStr+10, ctx->keyIndex);
		os_memmove(ctx->indexStr+10+n, "?", 2);
		UX_DISPLAY(ui_signHash_approve, NULL);
		break;
	}
	return 0;
}

void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	ctx->keyIndex = U4LE(dataBuffer, 0);
	os_memmove(ctx->hash, dataBuffer+4, sizeof(ctx->hash));

	bin2hex(ctx->hexHash, ctx->hash, sizeof(ctx->hash));
	os_memmove(ctx->partialHashStr, ctx->hexHash, 12);
	ctx->partialHashStr[12] = '\0';
	ctx->displayIndex = 0;

	UX_DISPLAY(ui_signHash_compare, ui_prepro_signHash_compare);

	*flags |= IO_ASYNCH_REPLY;
}
