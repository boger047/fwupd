/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib.h>

#define BCM_FIRMWARE_SIZE			0x80000
#define BCM_NVRAM_MAGIC				0x669955AA

/* offsets into BAR */
#define REG_DEVICE_PCI_VENDOR_DEVICE_ID		0x6434
#define REG_NVM_SOFTWARE_ARBITRATION		0x7020
#define REG_NVM_ACCESS				0x7024
#define REG_NVM_COMMAND				0x7000
#define REG_NVM_ADDR				0x700c
#define REG_NVM_READ				0x7010
#define REG_NVM_WRITE				0x7008

typedef union {
	guint32 r32;
	struct {
		guint32 reserved_0_0		: 1;
		guint32 Reset			: 1;
		guint32 reserved_2_2		: 1;
		guint32 Done			: 1;
		guint32 Doit			: 1;
		guint32 Wr			: 1;
		guint32 Erase			: 1;
		guint32 First			: 1;
		guint32 Last			: 1;
		guint32 reserved_15_9		: 7;
		guint32 WriteEnableCommand	: 1;
		guint32 WriteDisableCommand	: 1;
		guint32 reserved_31_18		: 14;
	} __attribute__((packed)) bits;
} RegNVMCommand_t;

typedef union {
	guint32 r32;
	struct {
		guint32 ReqSet0			: 1;
		guint32 ReqSet1			: 1;
		guint32 ReqSet2			: 1;
		guint32 ReqSet3			: 1;
		guint32 ReqClr0			: 1;
		guint32 ReqClr1			: 1;
		guint32 ReqClr2			: 1;
		guint32 ReqClr3			: 1;
		guint32 ArbWon0			: 1;
		guint32 ArbWon1			: 1;
		guint32 ArbWon2			: 1;
		guint32 ArbWon3			: 1;
		guint32 Req0			: 1;
		guint32 Req1			: 1;
		guint32 Req2			: 1;
		guint32 Req3			: 1;
		guint32 reserved_31_16		: 16;
	} __attribute__((packed)) bits;
} RegNVMSoftwareArbitration_t;

typedef union {
	guint32 r32;
	struct {
		guint32 Enable			: 1;
		guint32 WriteEnable		: 1;
		guint32 reserved_31_2		: 30;
	} __attribute__((packed)) bits;
} RegNVMAccess_t;

guint32		 fu_bcm57xx_nvram_crc		(const guint8	*buf,
						 guint32	 bufsz,
						 guint32	 crc);
gboolean	 fu_bcm57xx_verify_crc		(GBytes		*fw,
						 GError		**error);
gboolean	 fu_bcm57xx_verify_magic	(GBytes		*fw,
						 gsize		 offset,
						 GError		**error);
