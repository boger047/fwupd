/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: GPL-2+
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "fu-chunk.h"
#include "fu-bcm57xx-common.h"
#include "fu-bcm57xx-device.h"
#include "fu-bcm57xx-firmware.h"

typedef struct {
	guint8	*buf;
	gsize	 bufsz;
} FuBcm57xxMmap;

#define FU_BCM57XX_MMAP_MAX	3

struct _FuBcm57xxDevice {
	FuUdevDevice		 parent_instance;
	FuBcm57xxMmap		 bar[FU_BCM57XX_MMAP_MAX];
};

G_DEFINE_TYPE (FuBcm57xxDevice, fu_bcm57xx_device, FU_TYPE_UDEV_DEVICE)

static void
fu_bcm57xx_device_to_string (FuUdevDevice *device, guint idt, GString *str)
{
//	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
//	fu_common_string_append_ku (str, idt, "SectorSize", self->sect_size);
}

static gboolean
fu_bcm57xx_device_probe (FuUdevDevice *device, GError **error)
{
	if (fu_udev_device_get_number (device) != 1) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "only device 1 supported on multi-device card");
		return FALSE;
	}
	return fu_udev_device_set_physical_id (device, "pci", error);
}

static gboolean
fu_bcm57xx_device_setup (FuDevice *device, GError **error)
{
	return TRUE;
}

static gboolean
fu_bcm57xx_device_open (FuDevice *device, GError **error)
{
	return TRUE;
}

static gboolean
fu_bcm57xx_device_close (FuDevice *device, GError **error)
{
	return TRUE;
}

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


#ifdef __ppc64__
//#define BARRIER()	asm volatile ("sync 0\neieio\n" : : : "memory")
#else
//#define BARRIER()	asm volatile ("" : : : "memory")
#define BARRIER()	;
#endif

#if 0
static guint32
read_from_ram (guint32 val, guint32 offset, void *args)
{
	uint8_t *base = (uint8_t *) args;
	base += offset;
	BARRIER();
	return *(guint32 *)base;
}

static guint32
write_to_ram (guint32 val, guint32 offset, void *args)
{
	uint8_t *base = (uint8_t *) args;
	base += offset;
	BARRIER();
	*(guint32 *)base = val;
	BARRIER();
	return val;
}
#endif

static guint32
fu_bcm57xx_device_bar_read (FuBcm57xxDevice *self, guint bar, gsize offset)
{
	guint8 *base = self->bar[bar].buf + offset;
	BARRIER();
	return *(guint32 *)base;
}

static void
fu_bcm57xx_device_bar_write (FuBcm57xxDevice *self, guint bar, gsize offset, guint32 val)
{
	guint8 *base = self->bar[bar].buf + offset;
	BARRIER();
	*(guint32 *)base = val;
	BARRIER();
}

#define REG_DEVICE_PCI_VENDOR_DEVICE_ID		0x6434
#define REG_NVM_SOFTWARE_ARBITRATION		0x7020
#define REG_NVM_ACCESS				0x7024
#define REG_NVM_COMMAND				0x7000
#define REG_NVM_ADDR				0x700c
#define REG_NVM_READ				0x7010
#define REG_NVM_WRITE				0x7008

typedef enum {
	FU_BCM57XX_DEVICE_MODE_DISABLED,
	FU_BCM57XX_DEVICE_MODE_ENABLED,
	FU_BCM57XX_DEVICE_MODE_ENABLED_WRITE,
} FuBcm57xxDeviceMode;

static gboolean
fu_bcm57xx_device_set_mode (FuBcm57xxDevice *self, FuBcm57xxDeviceMode mode, GError **error)
{
	RegNVMAccess_t tmp;
	tmp.r32 = fu_bcm57xx_device_bar_read (self, 0x0, REG_NVM_ACCESS);
	tmp.bits.Enable = mode == FU_BCM57XX_DEVICE_MODE_ENABLED ||
			  mode == FU_BCM57XX_DEVICE_MODE_ENABLED_WRITE;
	tmp.bits.WriteEnable = mode == FU_BCM57XX_DEVICE_MODE_ENABLED_WRITE;
	fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_ACCESS, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_acquire_lock (FuBcm57xxDevice *self, GError **error)
{
	RegNVMSoftwareArbitration_t tmp = { 0 };
	GTimer *timer = g_timer_new ();

	tmp.bits.ReqSet1 = 1;
	fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_SOFTWARE_ARBITRATION, tmp.r32);
	do {
		tmp.r32 = fu_bcm57xx_device_bar_read (self, 0x0, REG_NVM_SOFTWARE_ARBITRATION);
		if (tmp.bits.ArbWon1)
			return TRUE;
		if (g_timer_elapsed (timer, NULL) > 0.2)
			break;
	} while (TRUE);

	/* timed out */
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_TIMED_OUT,
			     "timed out trying to aquire lock #1");
	return FALSE;
}

static gboolean
fu_bcm57xx_device_release_lock (FuBcm57xxDevice *self, GError **error)
{
	RegNVMSoftwareArbitration_t tmp = { 0 };
	tmp.r32 = 0;
	tmp.bits.ReqClr1 = 1;
	fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_SOFTWARE_ARBITRATION, tmp.r32);
	return TRUE;
}

static gboolean
fu_bcm57xx_device_wait_done (FuBcm57xxDevice *self, GError **error)
{
	RegNVMCommand_t tmp = { 0 };
	GTimer *timer = g_timer_new ();
	do {
		tmp.r32 = fu_bcm57xx_device_bar_read (self, 0x0, REG_NVM_COMMAND);
		if (tmp.bits.Done)
			return TRUE;
		if (g_timer_elapsed (timer, NULL) > 0.2)
			break;
	} while (TRUE);

	/* timed out */
	g_set_error_literal (error,
			     G_IO_ERROR,
			     G_IO_ERROR_TIMED_OUT,
			     "timed out");
	return FALSE;
}

static void
fu_bcm57xx_device_clear_done (FuBcm57xxDevice *self)
{
	RegNVMCommand_t tmp = { 0 };
	tmp.bits.Done = 1;
	fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_COMMAND, tmp.r32);
}

static gboolean
fu_bcm57xx_device_read (FuBcm57xxDevice *self,
			guint32 address, guint32 *buf, gsize bufsz,
			GError **error)
{
	for (guint i = 0; i < bufsz; i++) {
		RegNVMCommand_t tmp = { 0 };
		fu_bcm57xx_device_clear_done (self);
		fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_ADDR, address);
		tmp.bits.Doit = 1;
		tmp.bits.First = (i == 0);
		tmp.bits.Last = (i == bufsz - 1);
		fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_COMMAND, tmp.r32);
		if (!fu_bcm57xx_device_wait_done (self, error)) {
			g_prefix_error (error, "failed to read @0x%x: ", address);
			return FALSE;
		}
		buf[i] = GUINT32_FROM_BE(fu_bcm57xx_device_bar_read (self, 0x0, REG_NVM_READ));
		address += sizeof(guint32);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_write (FuBcm57xxDevice *self,
			 guint32 address, const guint32 *buf, gsize bufsz,
			 GError **error)
{
	for (guint i = 0; i < bufsz; i++) {
		RegNVMCommand_t tmp = { 0 };
		fu_bcm57xx_device_clear_done (self);
		fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_WRITE, GUINT32_TO_BE(buf[i]));
		fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_ADDR, address);
		tmp.bits.Wr = 1;
		tmp.bits.Doit = 1;
		tmp.bits.First = (i == 0);
		tmp.bits.Last = (i == bufsz - 1);
		fu_bcm57xx_device_bar_write (self, 0x0, REG_NVM_COMMAND, tmp.r32);
		if (!fu_bcm57xx_device_wait_done (self, error)) {
			g_prefix_error (error, "failed to read @0x%x: ", address);
			return FALSE;
		}
		address += sizeof(guint32);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_detach (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
	FuUdevDevice *udev_device = FU_UDEV_DEVICE (device);
	const gchar *sysfs_path = fu_udev_device_get_sysfs_path (udev_device);
	guint32 vendev;

	/* unbind tg3 */
	if (!fu_device_unbind_driver (device, error))
		return FALSE;

#if 0
	/* this can't work */
	if (RUNNING_ON_VALGRIND) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "running on valgrind is not supported");
		return FALSE;
	}
#endif

	/* map BARs */
	for (guint i = 0; i < FU_BCM57XX_MMAP_MAX; i++) {
		int memfd;
		struct stat st;
		g_autofree gchar *fn = NULL;
		g_autofree gchar *resfn = NULL;

		/* open 64 bit resource */
		resfn = g_strdup_printf ("resource%u", i * 2);
		fn = g_build_filename (sysfs_path, resfn, NULL);
		memfd = open (fn, O_RDWR | O_SYNC);
		if (memfd < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_FOUND,
				     "error opening %s", fn);
			return FALSE;
		}
		if (fstat (memfd, &st) < 0) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "could not stat %s", fn);
			close (memfd);
			return FALSE;
		}

		/* mmap */
		g_debug ("mapping %s for 0x%x bytes", fn, (guint) st.st_size);
		self->bar[i].buf = (guint8 *) mmap (0, st.st_size,
						    PROT_READ | PROT_WRITE,
						    MAP_SHARED, memfd, 0);
		self->bar[i].bufsz = st.st_size;
		close (memfd);
		if (self->bar[i].buf == MAP_FAILED) {
			g_set_error (error,
				     G_IO_ERROR,
				     G_IO_ERROR_NOT_SUPPORTED,
				     "cound not mmap %s: %s",
				     fn, strerror(errno));
			return FALSE;
		}
	}

	/* verify we can read something simple */
	vendev = fu_bcm57xx_device_bar_read (self, 0x0, REG_DEVICE_PCI_VENDOR_DEVICE_ID);
	g_debug ("REG_DEVICE_PCI_VENDOR_DEVICE_ID=%x", vendev);
	if ((vendev & 0xffff0000) >> 4 != 0x14e4) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_NOT_SUPPORTED,
			     "invalid bar[0] VID, got %08x, expected %04xXXXX",
			     vendev, (guint) 0x14e4);
		return FALSE;
	}

	if (!fu_bcm57xx_device_acquire_lock (self, error))
		return FALSE;
	if (!fu_bcm57xx_device_set_mode (self, FU_BCM57XX_DEVICE_MODE_ENABLED, error))
		return FALSE;

	{
		guint32 buf[4] = { 0x0 };
		if (!fu_bcm57xx_device_read (self, 0x0, buf, 4, error))
			return FALSE;
		for (guint i = 0; i < 4; i++)
			g_warning ("%02x", buf[i]);
	}

	if (!fu_bcm57xx_device_release_lock (self, error))
		return FALSE;

	if (0) {
		if (!fu_bcm57xx_device_write (self, 0x0, NULL, 0, error))
			return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_attach (FuDevice *device, GError **error)
{
	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);

	/* unmap BARs */
	for (guint i = 0; i < FU_BCM57XX_MMAP_MAX; i++) {
		if (self->bar[i].buf == NULL)
			continue;
		munmap (self->bar[i].buf, self->bar[i].bufsz);
		self->bar[i].buf = NULL;
		self->bar[i].bufsz = 0;
	}

	/* bind tg3 */
	if (!fu_device_bind_driver (device, "pci", "tg3", error))
		return FALSE;

	/* success */
	return TRUE;
}

static FuFirmware *
fu_bcm57xx_device_read_firmware (FuDevice *device, GError **error)
{
//	FuBcm57xxDevice *self = FU_BCM57XX_DEVICE (device);
	g_autoptr(GBytes) fw = NULL;

	fu_device_set_status (device, FWUPD_STATUS_DEVICE_READ);
	fw = g_bytes_new (NULL, 0);
	return fu_firmware_new_from_bytes (fw);
}

static FuFirmware *
fu_bcm57xx_device_prepare_firmware (FuDevice *device,
				    GBytes *fw,
				    FwupdInstallFlags flags,
				    GError **error)
{
	g_autoptr(FuFirmware) firmware = NULL;
	g_autoptr(FuFirmware) firmware_tmp = fu_bcm57xx_firmware_new ();
	g_autoptr(FuFirmwareImage) img_ape = NULL;
	g_autoptr(FuFirmwareImage) img_stage1 = NULL;
	g_autoptr(FuFirmwareImage) img_stage2 = NULL;

	/* try to parse NVRAM, stage1 or APE */
	if (!fu_firmware_parse (firmware_tmp, fw, flags, error))
		return NULL;

	/* for full NVRAM image, verify if correct device */
	if ((flags & FWUPD_INSTALL_FLAG_FORCE) == 0) {
		guint16 vid = fu_bcm57xx_firmware_get_vendor (FU_BCM57XX_FIRMWARE (firmware_tmp));
		guint16 did = fu_bcm57xx_firmware_get_model (FU_BCM57XX_FIRMWARE (firmware_tmp));
		if (vid != 0x0 && did != 0x0 &&
		    (fu_udev_device_get_vendor (FU_UDEV_DEVICE (device)) != vid ||
		     fu_udev_device_get_model (FU_UDEV_DEVICE (device)) != did)) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "PCI vendor or model incorrect, got: %04X:%04X",
				     vid, did);
			return NULL;
		}
	}

	/* get the existing firmware from the device */
	firmware = fu_bcm57xx_device_read_firmware (device, error);
	if (firmware == NULL)
		return NULL;

	/* merge in all the provided images into the existing firmware */
	img_stage1 = fu_firmware_get_image_by_id (firmware_tmp, "stage1", NULL);
	if (img_stage1 != NULL)
		fu_firmware_add_image (firmware, img_stage1);
	img_stage2 = fu_firmware_get_image_by_id (firmware_tmp, "stage2", NULL);
	if (img_stage2 != NULL)
		fu_firmware_add_image (firmware, img_stage2);
	img_ape = fu_firmware_get_image_by_id (firmware_tmp, "ape", NULL);
	if (img_ape != NULL)
		fu_firmware_add_image (firmware, img_ape);

	/* success */
	return g_steal_pointer (&firmware);
}

static gboolean
fu_bcm57xx_device_write_firmware (FuDevice *device,
				  FuFirmware *firmware,
				  FwupdInstallFlags flags,
				  GError **error)
{
//	FuBcm57xxDevice *self= FU_BCM57XX_DEVICE (device);
	g_autoptr(GBytes) blob = NULL;

	/* build the images into one linear blob of the correct size */
	blob = fu_firmware_write (firmware, error);
	if (blob == NULL)
		return FALSE;

	/* success */
	return TRUE;
}

static void
fu_bcm57xx_device_init (FuBcm57xxDevice *self)
{
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_CAN_VERIFY_IMAGE);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_NO_GUID_MATCHING);
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_set_protocol (FU_DEVICE (self), "com.broadcom.bcm57xx");
	fu_device_add_icon (FU_DEVICE (self), "network-wired");
	fu_device_set_firmware_size (FU_DEVICE (self), BCM_FIRMWARE_SIZE);

	/* no BARs mapped */
	for (guint i = 0; i < FU_BCM57XX_MMAP_MAX; i++) {
		self->bar[i].buf = NULL;
		self->bar[i].bufsz = 0;
	}
}

static void
fu_bcm57xx_device_finalize (GObject *object)
{
	G_OBJECT_CLASS (fu_bcm57xx_device_parent_class)->finalize (object);
}

static void
fu_bcm57xx_device_class_init (FuBcm57xxDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	FuUdevDeviceClass *klass_udev_device = FU_UDEV_DEVICE_CLASS (klass);
	object_class->finalize = fu_bcm57xx_device_finalize;
	klass_device->prepare_firmware = fu_bcm57xx_device_prepare_firmware;
	klass_device->setup = fu_bcm57xx_device_setup;
	klass_device->open = fu_bcm57xx_device_open;
	klass_device->close = fu_bcm57xx_device_close;
	klass_device->write_firmware = fu_bcm57xx_device_write_firmware;
	klass_device->read_firmware = fu_bcm57xx_device_read_firmware;
	klass_device->attach = fu_bcm57xx_device_attach;
	klass_device->detach = fu_bcm57xx_device_detach;
	klass_udev_device->probe = fu_bcm57xx_device_probe;
	klass_udev_device->to_string = fu_bcm57xx_device_to_string;
}
