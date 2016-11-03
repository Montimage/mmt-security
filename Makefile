CC     = gcc
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
VERSION = 1.0.0

#name of executable file to generate
OUTPUT   = security
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/security

#get git version abbrev
GIT_VERSION := $(shell git describe --abbrev=7 --always)

#set of library
LIBS     = -ldl -lpthread -lxml2

CFLAGS   = -O0 -Wall -DGIT_VERSION=\"$(GIT_VERSION)\" -Wno-unused-variable -I/usr/include/libxml2/
CLDFLAGS = 

#for debuging
ifdef DEBUG
	CFLAGS   += -g -DDEBUG_MODE
	CLDFLAGS += -g -DDEBUG_MODE
endif

#folders containing source files
SRCDIR = src

#objects to generate
LIB_OBJS  :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/lib/*.c))
TEST_OBJS :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/../test/*.c))

#filter out 2 files: src/main.c and src/test_probe.c
MAIN_SRCS := $(wildcard   $(SRCDIR)/*.c)
MAIN_SRCS := $(filter-out $(SRCDIR)/tips.c, $(MAIN_SRCS))

MAIN_SRCS := $(filter-out $(SRCDIR)/main_dpi.c, $(MAIN_SRCS))
MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS))

MMT_DPI_HEADER = $(SRCDIR)/dpi/mmt_dpi.h

ifndef VERBOSE
	QUIET := @
endif

MAIN_DPI = gen_dpi_header

MAIN_GEN_PLUGIN = gen_plugin

MAIN_PLUGIN_INFO = plugin_info

MAIN_STAND_ALONE = mmt_sec_standalone

all: $(MMT_DPI_HEADER) $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] $(OUTPUT)"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)

gen_plugin: src/dpi/mmt_dpi.h $(MMT_DPI_HEADER) $(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o
	@echo "[COMPILE] $(MAIN_GEN_PLUGIN)"
	$(QUIET) $(CC) -o $(MAIN_GEN_PLUGIN) $(CLDFLAGS) $^ $(LIBS)
	
standalone: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -o $(MAIN_STAND_ALONE) $(SRCDIR)/main_sec_standalone.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -lmmt_core -ldl

plugin_info: src/dpi/mmt_dpi.h $(LIB_OBJS) $(SRCDIR)/main_plugin_info.o
	@echo "[COMPILE] $(MAIN_PLUGIN_INFO)"
	$(QUIET) $(CC) -o $(MAIN_PLUGIN_INFO) $(CLDFLAGS) $^ $(LIBS)

gen_dpi src/dpi/mmt_dpi.h:
	$(QUIET) $(CC) -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -o $(MAIN_DPI) $(SRCDIR)/main_gen_dpi.c -lmmt_core -ldl
	@echo "Generate list of protocols and their attributes"	
	$(QUIET) ./$(MAIN_DPI) > $(MMT_DPI_HEADER)
	
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* $(MMT_DPI_HEADER) $(MAIN_DPI) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO) $(MAIN_STAND_ALONE)