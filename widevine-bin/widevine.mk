################################################################################
#
# widevine prebuilt
#
################################################################################


WIDEVINE_BIN_VERSION = $(call qstrip,$(BR2_PACKAGE_WIDEVINE_BIN_VERSION))
WIDEVINE_BIN_SITE = $(TOPDIR)/../multimedia/libmediadrm/widevine-bin/prebuilt-v$(WIDEVINE_BIN_VERSION)
WIDEVINE_BIN_SITE_METHOD = local
WIDEVINE_BIN_INSTALL_TARGET := YES
WIDEVINE_BIN_INSTALL_STAGING := YES
WIDEVINE_BIN_DEPENDENCIES = tdk


define WIDEVINE_BIN_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/lib/$(BR2_ARCH)/*.so $(STAGING_DIR)/usr/lib/
endef

define WIDEVINE_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/ta/*.ta $(TARGET_DIR)/lib/teetz/
	$(INSTALL) -D -m 0644 $(@D)/lib/$(BR2_ARCH)/*.so $(TARGET_DIR)/usr/lib/
endef

$(eval $(generic-package))
