#
# Copyright (C) 2015-2015 NightCoffee
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=udpdst
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/udpdst
  SUBMENU:=Other modules
  DEPENDS:=+kmod-nf-conntrack
  TITLE:=UDP Original Dest
  FILES:=$(PKG_BUILD_DIR)/udpdst.ko
  AUTOLOAD:=$(call AutoLoad,30,udpdst,1)
  KCONFIG:=
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,udpdst))
