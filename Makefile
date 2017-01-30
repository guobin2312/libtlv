ARCH?=$(shell arch)

#CFLAGS=-g -Wall -Wa,-ahdlcs=$@.lst $(EXTRA_CFLAGS)
CFLAGS=-g -Wall -Werror $(EXTRA_CFLAGS)
LDFLAGS=$(EXTRA_LDFLAGS)

ifeq ($(ARCH),x86)
EXTRA_CFLAGS=-m32
EXTRA_LDFLAGS=-m32
endif

ifeq ($(ARCH),x86_64)
EXTRA_CFLAGS=-m64
EXTRA_LDFLAGS=-m64
endif

ifeq ($(ARCH),mips)
CC             = 
LD             = 
EXTRA_CPPFLAGS =
EXTRA_CFLAGS   = 
EXTRA_LDFLAGS  = 
LDLIBS         = 
endif

ifeq ($(ARCH),arm)
CC             = 
LD             = 
EXTRA_CPPFLAGS =
EXTRA_CFLAGS   = 
EXTRA_LDFLAGS  =
LDLIBS         = 
endif

all: tlvtest

test: tlvtest
	$(PWD)/tlvtest

tlvtest: tlvtest.o libtlv.o

tlvtest.o: tlvtest.c libtlv.h Makefile

libtlv.o: libtlv.c libtlv.h Makefile

clean:
	-rm -f *.o *.lst *~ $(NAME)

.PHONEY: all test clean
