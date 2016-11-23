CC     = gcc-4.9
AR     = ar rcs
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
MV     = mv
LN     = ln -s

#name of executable file to generate
OUTPUT   = security
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/security

#get git version abbrev
GIT_VERSION := $(shell git describe --abbrev=7 --always)
VERSION     := 1.0

#set of library
LIBS     = -ldl -lpthread -lxml2

CFLAGS   = -fPIC -Wall -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -Wno-unused-variable -I/usr/include/libxml2/
CLDFLAGS = 

#for debuging
ifdef DEBUG
	CFLAGS   += -g -DDEBUG_MODE -O0 -fstack-protector-all -Wmaybe-uninitialized -Wuninitialized
	CLDFLAGS += -g -DDEBUG_MODE -O0 -fstack-protector-all
else
	CFLAGS   += -O3
	CLDFLAGS += -O3
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

MAIN_GEN_PLUGIN = compile_rule

MAIN_PLUGIN_INFO = rule_info

MAIN_STAND_ALONE = mmt_sec_standalone

MAIN_SEC_SERVER = mmt_sec_server

MAIN_SEC_SERVER_33 = mmt_sec_server_33

MAIN_SEC_SERVER_03 = mmt_sec_server_03

MAIN_SEC_SERVER_V = mmt_sec_server_v

LIB_NAME = libmmt_security

all: standalone compile_rule rule_info sec_server

%.o: %.c src/dpi/mmt_dpi.h
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)

compile_rule: src/dpi/mmt_dpi.h $(MMT_DPI_HEADER) $(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o
	@echo "[COMPILE] $(MAIN_GEN_PLUGIN)"
	$(QUIET) $(CC) -o $(MAIN_GEN_PLUGIN) $(CLDFLAGS) $^ $(LIBS)
	
sec_server: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER) $(SRCDIR)/main_sec_server.c  $(CLDFLAGS) $^ $(LIBS) -ldl
	
sec_server_33: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER_33) $(SRCDIR)/main_sec_server_33.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -ldl

sec_server_v: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER_V) $(SRCDIR)/main_sec_server_v.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -ldl

standalone: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -o $(MAIN_STAND_ALONE) $(SRCDIR)/main_sec_standalone.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -lmmt_core -ldl

sec_server_03: src/dpi/mmt_dpi.h $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER_03) $(SRCDIR)/main_sec_server_03.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -ldl

rule_info: src/dpi/mmt_dpi.h $(LIB_OBJS) $(SRCDIR)/main_plugin_info.o
	@echo "[COMPILE] $(MAIN_PLUGIN_INFO)"
	$(QUIET) $(CC) -o $(MAIN_PLUGIN_INFO) $(CLDFLAGS) $^ $(LIBS)

gen_dpi src/dpi/mmt_dpi.h:
	$(QUIET) $(CC) -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -o $(MAIN_DPI) $(SRCDIR)/main_gen_dpi.c -lmmt_core -ldl
	$(QUIET) echo "Generate list of protocols and their attributes"	
	$(QUIET) ./$(MAIN_DPI) > $(MMT_DPI_HEADER)

$(LIB_NAME).a: $(LIB_OBJS)
	$(QUIET) echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $(LIB_NAME).a  $(LIB_OBJS)


$(LIB_NAME).so: $(LIB_OBJS)
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC)  -fPIC -shared -O3 -o $(LIB_NAME).so $(LIB_OBJS)
	
lib: $(LIB_NAME).a $(LIB_NAME).so
	
INSTALL_DIR=/opt/mmt/security
$(INSTALL_DIR):
	$(QUIET) $(MKDIR) $(INSTALL_DIR)/rules
uninstall:
	$(QUIET) $(RM) $(INSTALL_DIR)
install: uninstall $(INSTALL_DIR) clean standalone rule_info compile_rule lib
	
	$(QUIET) $(MKDIR) $(INSTALL_DIR)/include
	$(QUIET) $(CP) $(SRCDIR)/dpi/* $(SRCDIR)/lib/*.h $(INSTALL_DIR)/include/
	
	$(QUIET) $(MKDIR) $(INSTALL_DIR)/bin
	$(QUIET) $(MV) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO)  $(INSTALL_DIR)/bin
	$(QUIET) $(MV)  $(MAIN_STAND_ALONE) $(INSTALL_DIR)/bin/mmt_security
	
	$(QUIET) $(MKDIR) $(INSTALL_DIR)/lib
	$(QUIET) $(MV)  $(LIB_NAME).so $(INSTALL_DIR)/lib/$(LIB_NAME).so.$(VERSION)
	$(QUIET) $(MV)  $(LIB_NAME).a $(INSTALL_DIR)/lib/$(LIB_NAME).a.$(VERSION)
	
	$(QUIET) $(RM)  $(INSTALL_DIR)/lib/$(LIB_NAME).so $(INSTALL_DIR)/lib/$(LIB_NAME).a
	
	$(QUIET) $(LN)  $(INSTALL_DIR)/lib/$(LIB_NAME).so.$(VERSION) $(INSTALL_DIR)/lib/$(LIB_NAME).so 
	$(QUIET) $(LN)  $(INSTALL_DIR)/lib/$(LIB_NAME).a.$(VERSION) $(INSTALL_DIR)/lib/$(LIB_NAME).a
	$(QUIET) chmod -x $(INSTALL_DIR)/lib/$(LIB_NAME).*
	
	@echo "Installed mmt-security in $(INSTALL_DIR)"
	
dist-clean: uninstall
	@echo "Removed mmt-security from $(INSTALL_DIR)"
	
clean:
	$(QUIET) $(RM) $(LIB_NAME).* $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* $(MMT_DPI_HEADER) $(MAIN_DPI) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO) $(MAIN_STAND_ALONE) $(MAIN_SEC_SERVER) $(MAIN_SEC_SERVER_33) $(MAIN_SEC_SERVER_V) $(MAIN_SEC_SERVER_03)