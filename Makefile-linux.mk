# Copyright (c) 2017 Thales e-Security Ltd.
# All rights reserved. Company confidential.

NFAST_PATH=/opt/nfast

# Where the source/output lives
SRCPATH=.
OUTPATH=./host
THALES_OUTPUT = $(OUTPATH)/thales

# Affects how some methods are called when on the host
MODULE=1

# Header file locations
INC_SWORLD= $(NFAST_PATH)/c/csd/gcc/include/sworld
INC_HILIBS= $(NFAST_PATH)/c/csd/gcc/include/hilibs
INC_CUTILS= $(NFAST_PATH)/c/csd/gcc/include/cutils
INC_SWORLD= $(NFAST_PATH)/c/csd/gcc/include/sworld
INCEX_HILIBS= $(NFAST_PATH)/c/csd/examples/hilibs
INCEX_CUTILS= $(NFAST_PATH)/c/csd/examples/cutils

LIBPATH_GENERAL=$(NFAST_PATH)/c/csd/gcc/lib

# C compiler variables
CC= 		/usr/bin/cc
CPPFLAGS=	-I$(INC_HILIBS) -I$(INC_CUTILS) -I$(INC_SWORLD) \
	  		-I$(INCEX_CUTILS) -I$(INCEX_HILIBS)

CFLAGS=		-Wall -g3 -D RUNNING_ON_HOST=1 -D MODULE=$(MODULE)

LINK=		/usr/bin/ld

LDLIBS=		$(LIBPATH_GENERAL)/libnfkm.a \
				$(LIBPATH_GENERAL)/libnfstub.a \
				$(LIBPATH_GENERAL)/libnflog.a \
				$(LIBPATH_GENERAL)/libcutils.a


BINARY := $(OUTPATH)/main

all : $(BINARY)

SOURCES := $(shell find $(SRCPATH) -name '*.c')

# Get list of object files, with paths
OBJECTS := $(addprefix $(OUTPATH)/,$(SOURCES:%.c=%.o))

THALES_OBJECTS = $(THALES_OUTPUT)/nfutil.o $(THALES_OUTPUT)/simplebignum.o

# Thales source code provided with CodeSafe developer kit
$(THALES_OUTPUT)/nfutil.o: $(INCEX_HILIBS)/nfutil.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(INCEX_HILIBS) -c $< -o $@

$(THALES_OUTPUT)/simplebignum.o: $(INCEX_HILIBS)/simplebignum.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(INCEX_HILIBS) -c $< -o $@
	


$(BINARY): $(THALES_OBJECTS) $(OBJECTS)
	$(CC) $(CFLAGS) $(THALES_OBJECTS) $(OBJECTS) $(LDLIBS) -lm -o $(BINARY)

$(OUTPATH)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(dir $<) -c $< -o $@


clean:
	rm -f $(OUTPATH)/ed25519/*.o
	rm -f $(OUTPATH)/*.o
	rm -f $(OUTPATH)/main
	rm -f $(THALES_OUTPUT)/*.o