# Copyright (c) 2017 Thales e-Security Ltd.
# All rights reserved. Company confidential.

NFAST_PATH=	$(NFAST_HOME)

# Path to GCC for PowerPC cross-compiler installation
TOOLS_PATH=$(NFAST_PATH)/gcc/bin

# Path to CodeSafe/C tools
NCTOOLS_PATH=	$(NFAST_PATH)/bin


#######################################################
# EDIT THIS SECTION BEFORE COMPILING

#Which module number to use (to sign and pack)
MODULE= 			1

#Name of SEE machine signing key
MACHINE_KEY=see-signing-key

#Name of user data signing key
UD_KEY=see-ud-signing-key
#######################################################


# Where the source lives
SRCPATH=.
OUTPATH=./see
THALES_OUTPUT = $(OUTPATH)/thales

INC_SWORLD= $(NFAST_PATH)/c/csd/include-see/sworld
INC_BSDLIB= $(NFAST_PATH)/c/csd/include-see/bsdlib
INC_BSDSEE= $(NFAST_PATH)/c/csd/include-see/bsdsee
INC_HILIBS= $(NFAST_PATH)/c/csd/include-see/hilibs
INC_CUTILS= $(NFAST_PATH)/c/csd/include-see/cutils
INC_SWORLD= $(NFAST_PATH)/c/csd/include-see/sworld
INCEX_BSDLIB= $(NFAST_PATH)/c/csd/examples/bsdlib
INCEX_BSDSEE= $(NFAST_PATH)/c/csd/examples/bsdsee
INCEX_HILIBS= $(NFAST_PATH)/c/csd/examples/hilibs
INCEX_CUTILS= $(NFAST_PATH)/c/csd/examples/cutils

LIBPATH_GENERAL=$(NFAST_PATH)/c/csd/lib-ppc-gcc

# C compiler variables
CC=		$(TOOLS_PATH)/powerpc-codesafe-linux-gnu-gcc


CPPFLAGS=	-DNF_CROSSCC_BSDUSR=1 -D_THREAD_SAFE -DNF_CROSSCC_PPC_GCC=1 \
				-I$(SRCPATH) $(XCPPFLAGS) -DMODULE=$(MODULE)

CFLAGS=		-O2 -Wall -Wpointer-arith -Wno-strict-prototypes -Wwrite-strings \
				-Wmissing-prototypes -mpowerpc -mcpu=603e -mno-toc -mbig-endian \
				-mhard-float -mno-multiple -mno-string -meabi -mprototype \
				-mstrict-align -memb -fno-builtin -Werror     $(XCFLAGS)


LINK=		$(TOOLS_PATH)/powerpc-codesafe-linux-gnu-ld

LDFLAGS= 	-nostdlib -Ttext 0xa00000 -Tdata 0xd00000 $(XLDFLAGS)
LDLIBS=		$(XLDLIBS) \
				$(LIBPATH_GENERAL)/libnfkm.a \
				$(LIBPATH_GENERAL)/libnfstub.a \
				$(LIBPATH_GENERAL)/libnflog.a \
				$(LIBPATH_GENERAL)/libcutils.a \
				$(LIBPATH_GENERAL)/hostinetsocks.o \
				$(LIBPATH_GENERAL)/libvfsextras.a \
				$(LIBPATH_GENERAL)/libc.a



XLDLIBS=
XCPPFLAGS=-I$(INC_BSDLIB) -I$(INC_CUTILS) -I$(INC_BSDSEE) \
	  -I$(INC_HILIBS) -I$(INCEX_CUTILS) -I$(INCEX_HILIBS) -I$(INC_SWORLD)

ELF2AIF=	$(NCTOOLS_PATH)/elf2aif
ELFTOOL=	$(NCTOOLS_PATH)/elftool
PACKTOOL=	$(NCTOOLS_PATH)/tct2
CPIOTOOL=	$(NCTOOLS_PATH)/cpioc

# Targets
all:	 seemachine.sar userdata.sar

SOURCES := $(shell find $(SRCPATH) -name '*.c')

       
# Get list of object files, with paths
OBJECTS := $(addprefix $(OUTPATH)/,$(SOURCES:%.c=%.o))


THALES_OBJECTS = $(THALES_OUTPUT)/nfutil.o $(THALES_OUTPUT)/simplebignum.o

# Thales source code provided with CodeSafe developer kit
$(THALES_OUTPUT)/nfutil.o: $(INCEX_HILIBS)/nfutil.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(INCEX_HILIBS) -c $< -o $@

$(THALES_OUTPUT)/simplebignum.o: $(INCEX_HILIBS)/simplebignum.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(INCEX_HILIBS) -c $< -o $@
               

# Build instructions for all other files
$(OUTPATH)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -I$(dir $<) -I$(INCEX_HILIBS) -c $< -o $@

seemachine.sxf: $(THALES_OBJECTS) $(OBJECTS) 
	$(LINK) $(LDFLAGS) -o $(OUTPATH)/seemachine.elf $(THALES_OBJECTS) $(OBJECTS) $(LDLIBS)
	$(ELFTOOL) --sxf $(OUTPATH)/seemachine.elf $(OUTPATH)/seemachine.sxf

seemachine.sar: seemachine.sxf
	$(PACKTOOL) --sign-and-pack --key=$(MACHINE_KEY) --is-machine --module=$(MODULE) -o $(OUTPATH)/seemachine.sar $(OUTPATH)/seemachine.sxf

userdata.sar: userdata.cpio
	$(PACKTOOL) --sign-and-pack --key=$(UD_KEY) --machine-key-ident=$(MACHINE_KEY) --module=$(MODULE) -o $(OUTPATH)/userdata.sar $(OUTPATH)/userdata.cpio

userdata.cpio:
	$(CPIOTOOL) $(OUTPATH)/userdata.cpio opt

clean:
	rm -f $(OUTPATH)/*.o
	rm -f $(OUTPATH)/ed25519/*.o	
	rm -f $(OUTPATH)/*.sxf
	rm -f $(OUTPATH)/*.elf
	rm -f $(OUTPATH)/*.sar
	rm -f $(OUTPATH)/*.cpio
	rm -f $(THALES_OUTPUT)/*.o
