/*
 * This header enables or disables certain features of the translation
 * client.  More specifically, it can be used to eliminate
 * #TranslateRequest and #TranslateResponse attributes.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#pragma once

#define TRANSLATION_ENABLE_CACHE 0
#define TRANSLATION_ENABLE_WANT 0
#define TRANSLATION_ENABLE_EXPAND 0
#define TRANSLATION_ENABLE_SESSION 0
#define TRANSLATION_ENABLE_HTTP 0
#define TRANSLATION_ENABLE_WIDGET 0
#define TRANSLATION_ENABLE_RADDRESS 0
#define TRANSLATION_ENABLE_TRANSFORMATION 0
#define TRANSLATION_ENABLE_EXECUTE 1
#define TRANSLATION_ENABLE_SPAWN 1
#define TRANSLATION_ENABLE_LOGIN 1
