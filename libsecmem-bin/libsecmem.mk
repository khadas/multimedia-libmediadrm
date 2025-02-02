################################################################################
#
# libsecmem prebuilt
#
################################################################################


LIBSECMEM_BIN_VERSION = 1.0
LIBSECMEM_BIN_SITE = $(TOPDIR)/../multimedia/libmediadrm/libsecmem-bin/prebuilt
LIBSECMEM_BIN_SITE_METHOD = local
LIBSECMEM_BIN_INSTALL_TARGET := YES
LIBSECMEM_BIN_INSTALL_STAGING := YES
LIBSECMEM_BIN_DEPENDENCIES = tdk

CC_TARGET_ABI_:= $(call qstrip,$(BR2_GCC_TARGET_ABI))
CC_TARGET_FLOAT_ABI_ := $(call qstrip,$(BR2_GCC_TARGET_FLOAT_ABI))

define LIBSECMEM_BIN_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(STAGING_DIR)/usr/lib/
	$(INSTALL) -D -m 0644 $(@D)/noarch/include/* $(STAGING_DIR)/usr/include/
endef

define LIBSECMEM_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/noarch/ta/v$(BR2_PACKAGE_TDK_VERSION)/*.ta $(TARGET_DIR)/lib/teetz/
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(TARGET_DIR)/usr/lib/
        $(INSTALL) -D -m 0755 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/secmem_test $(TARGET_DIR)/usr/bin/
endef

$(eval $(generic-package))
