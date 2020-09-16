/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib.h>

#define BCM_FIRMWARE_SIZE			0x80000
#define BCM_NVRAM_MAGIC				0x669955AA

guint32		 fu_bcm57xx_nvram_crc		(const guint8	*buf,
						 guint32	 bufsz,
						 guint32	 crc);
gboolean	 fu_bcm57xx_verify_crc		(GBytes		*fw,
						 GError		**error);
gboolean	 fu_bcm57xx_verify_magic	(GBytes		*fw,
						 gsize		 offset,
						 GError		**error);
