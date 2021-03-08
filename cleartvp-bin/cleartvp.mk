################################################################################
#
# cleartvp prebuilt
#
################################################################################


CLEARTVP_BIN_VERSION = 1.0
CLEARTVP_BIN_SITE = $(TOPDIR)/../multimedia/libmediadrm/cleartvp-bin/prebuilt
CLEARTVP_BIN_SITE_METHOD = local
CLEARTVP_BIN_INSTALL_TARGET := YES
CLEARTVP_BIN_INSTALL_STAGING := YES
CLEARTVP_BIN_DEPENDENCIES = tdk


define CLEARTVP_BIN_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(STAGING_DIR)/usr/lib/
	$(INSTALL) -D -m 0644 $(@D)/noarch/include/* $(STAGING_DIR)/usr/include
endef

define CLEARTVP_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/noarch/ta/*.ta $(TARGET_DIR)/lib/teetz/
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(TARGET_DIR)/usr/lib/
endef

$(eval $(generic-package))
