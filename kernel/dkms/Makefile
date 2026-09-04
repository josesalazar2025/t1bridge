KDIR ?= /lib/modules/$(shell uname -r)/build
KERNEL_ROOT := $(abspath $(CURDIR)/..)

.PHONY: all clean

all:
	$(MAKE) -C $(KERNEL_ROOT)/t1-cfgsel KDIR=$(KDIR)
	$(MAKE) -C $(KERNEL_ROOT)/appletbdrm-t1 KDIR=$(KDIR)
	$(MAKE) -C $(KERNEL_ROOT)/apple-t1-ncm KDIR=$(KDIR)
	$(MAKE) -C $(KERNEL_ROOT)/uvcvideo-t1 KDIR=$(KDIR)

clean:
	$(MAKE) -C $(KERNEL_ROOT)/t1-cfgsel KDIR=$(KDIR) clean
	$(MAKE) -C $(KERNEL_ROOT)/appletbdrm-t1 KDIR=$(KDIR) clean
	$(MAKE) -C $(KERNEL_ROOT)/apple-t1-ncm KDIR=$(KDIR) clean
	$(MAKE) -C $(KERNEL_ROOT)/uvcvideo-t1 KDIR=$(KDIR) clean
