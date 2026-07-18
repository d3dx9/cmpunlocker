# Makefile for cmpunlocker_mod kernel module
#
# Build with: make
# Install with: sudo make install

obj-m += cmpunlocker_mod.o

# Kernel build directory
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install: cmpunlocker.ko
	mkdir -p /lib/modules/$(shell uname -r)/extra
	cp cmpunlocker.ko /lib/modules/$(shell uname -r)/extra/
	depmod -a
	echo cmpunlocker > /etc/modules-load.d/cmpunlocker.conf

.PHONY: all clean install