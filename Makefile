# Comment/uncomment the following line to enable/disable debugging
DEBUG = n

ifeq ($(DEBUG),y)
    #DEBUGFLAGS = -O -Wall -g # "-O" is needed to expand inlines
    DEBUGFLAGS = -Wall -g # "-O" is needed to expand inlines
else
    DEBUGFLAGS = -Wall -O2
endif

EXTRA_CFLAGS += $(DEBUGFLAGS)
EXTRA_CFLAGS += -I$(M)/../includes
#EXTRA_CFLAGS += -DLOCALFS

TARGET = fslog

ifneq ($(KERNELRELEASE),)

obj-m := fslog.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)


modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif


install:
	install -d $(INSTALLDIR)
	install -c $(TARGET).o $(INSTALLDIR)

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers *.unsigned modules.order

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif

