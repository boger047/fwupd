/*
 * Copyright (C) 2018 Evan Lojewski
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: GPL-2+
 */

#include "config.h"

#include "fwupd-error.h"

#include "fu-common.h"

#include "fu-bcm57xx-common.h"

#define CRC32_POLYNOMIAL 0xEDB88320

guint32
fu_bcm57xx_nvram_crc (const guint8 *buf, guint32 bufsz, guint32 crc)
{
	for (guint32 idx = 0; idx < bufsz; idx++) {
		guint8 data = *buf++;
		for (guint32 bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc >> 1) ^ (((crc ^ data) & 1) ? CRC32_POLYNOMIAL : 0);
		}
	}
	return GUINT32_FROM_BE(~crc);
}

gboolean
fu_bcm57xx_verify_crc (GBytes *fw, GError **error)
{
	guint32 crc_actual;
	guint32 crc_file = 0;
	gsize bufsz = 0x0;
	const guint8 *buf = g_bytes_get_data (fw, &bufsz);

	/* expected */
	if (!fu_common_read_uint32_safe (buf, bufsz, bufsz - sizeof(guint32),
					 &crc_file, G_BIG_ENDIAN, error))
		return FALSE;

	/* reality */
	crc_actual = fu_bcm57xx_nvram_crc (buf, bufsz - sizeof(guint32), 0xffffffff);
	if (crc_actual != crc_file) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "invalid CRC, expected 0x%08x got: 0x%08x",
			     (guint) crc_file, (guint) crc_actual);
		return FALSE;
	}

	/* success */
	return TRUE;
}

gboolean
fu_bcm57xx_verify_magic (GBytes *fw, gsize offset, GError **error)
{
	guint32 magic = 0;
	gsize bufsz = 0x0;
	const guint8 *buf = g_bytes_get_data (fw, &bufsz);

	/* hardcoded value */
	if (!fu_common_read_uint32_safe (buf, bufsz, offset, &magic, G_BIG_ENDIAN, error))
		return FALSE;
	if (magic != BCM_NVRAM_MAGIC) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "invalid magic, got: 0x%x",
			     (guint) magic);
		return FALSE;
	}

	/* success */
	return TRUE;
}
