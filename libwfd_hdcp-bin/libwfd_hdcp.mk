################################################################################
#
# libwfd_hdcp prebuilt
#
################################################################################


LIBWFD_HDCP_BIN_VERSION = 1.0
LIBWFD_HDCP_BIN_SITE = $(TOPDIR)/../multimedia/libmediadrm/libwfd_hdcp-bin/prebuilt
LIBWFD_HDCP_BIN_SITE_METHOD = local
LIBWFD_HDCP_BIN_INSTALL_TARGET := YES
LIBWFD_HDCP_BIN_INSTALL_STAGING := YES
LIBWFD_HDCP_BIN_DEPENDENCIES = tdk


define LIBWFD_HDCP_BIN_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(STAGING_DIR)/usr/lib/
	$(INSTALL) -D -m 0644 $(@D)/noarch/include/*.h $(STAGING_DIR)/usr/include
endef

define LIBWFD_HDCP_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/noarch/ta/v$(BR2_PACKAGE_TDK_VERSION)/*.ta $(TARGET_DIR)/lib/teetz/
	$(INSTALL) -D -m 0644 $(@D)/$(BR2_ARCH).$(CC_TARGET_ABI_).$(CC_TARGET_FLOAT_ABI_)/*.so $(TARGET_DIR)/usr/lib/
endef

$(eval $(generic-package))
