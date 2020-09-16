/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: GPL-2+
 */

#include "config.h"

#include "fu-chunk.h"
#include "fu-bcm57xx-common.h"
#include "fu-bcm57xx-device.h"
#include "fu-bcm57xx-firmware.h"

struct _FuBcm57xxDevice {
	FuUdevDevice		 parent_instance;
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

static gboolean
fu_bcm57xx_device_detach (FuDevice *device, GError **error)
{
	/* unbind tg3 */
	if (!fu_device_unbind_driver (device, error))
		return FALSE;

	/* success */
	return TRUE;
}

static gboolean
fu_bcm57xx_device_attach (FuDevice *device, GError **error)
{
	/* bind tg3 */
	if (!fu_device_bind_driver (device, "pci", "tg3", error))
		return FALSE;

	/* success */
	return TRUE;
}

static FuFirmware *
fu_bcm57xx_device_read_firmware (FuDevice *device, GError **error)
{
//	FuSuperioDevice *self = FU_SUPERIO_DEVICE (device);
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
