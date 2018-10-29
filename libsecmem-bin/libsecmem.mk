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


define LIBSECMEM_BIN_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/lib/$(BR2_ARCH)/*.so $(STAGING_DIR)/usr/lib/
endef

define LIBSECMEM_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/ta/*.ta $(TARGET_DIR)/lib/teetz/
	$(INSTALL) -D -m 0644 $(@D)/lib/$(BR2_ARCH)/*.so $(TARGET_DIR)/usr/lib/
        $(INSTALL) -D -m 0755 $(@D)/test/$(BR2_ARCH)/* $(TARGET_DIR)/usr/bin/
endef

$(eval $(generic-package))
