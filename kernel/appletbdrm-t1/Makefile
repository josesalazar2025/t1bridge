KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean

obj-m += appletbdrm.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
