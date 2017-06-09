CC     = gcc-4.9
AR     = ar rcs
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
MV     = mv
LN     = ln -s

######color
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

#name of executable file to generate
OUTPUT   = security
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/security

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)

# if you update the version number here, 
# ==> you must also update VERSION_NUMBER in src/lib/version.c 
VERSION     := 1.1.5
#set of library
LIBS     = -ldl -lpthread -lxml2 -lhiredis -lmmt_core

CFLAGS   = -fPIC -Wall -DGIT_VERSION=\"$(GIT_VERSION)\" -DLEVEL1_DCACHE_LINESIZE=`getconf LEVEL1_DCACHE_LINESIZE` -Wno-unused-variable -I/usr/include/libxml2/  -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib 
CLDFLAGS = -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib

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

LIB_NAME = libmmt_security

all: standalone compile_rule rule_info sec_server

%.o: %.c $(MMT_DPI_HEADER)
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $@ $(CLDFLAGS)  $^ $(LIBS)

compile_rule: $(MMT_DPI_HEADER) $(MMT_DPI_HEADER) $(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o
	@echo "[COMPILE] $(MAIN_GEN_PLUGIN)"
	$(QUIET) $(CC) -o $(MAIN_GEN_PLUGIN) $(CLDFLAGS) $^ $(LIBS)
	
sec_server: $(MMT_DPI_HEADER) $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER) $(SRCDIR)/main_sec_server.c  $(CLDFLAGS) $^ $(LIBS) -ldl
	
standalone: $(MMT_DPI_HEADER) $(LIB_OBJS) 
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_STAND_ALONE) $(SRCDIR)/main_sec_standalone.c  $(CLDFLAGS) $^ $(LIBS) -lpcap -lmmt_core -ldl

rule_info: $(MMT_DPI_HEADER) $(LIB_OBJS) $(SRCDIR)/main_plugin_info.o
	@echo "[COMPILE] $(MAIN_PLUGIN_INFO)"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_PLUGIN_INFO) $(CLDFLAGS) $^ $(LIBS)

gen_dpi:
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

uninstall:
	$(QUIET) $(RM) $(INSTALL_DIR)
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt-security.conf

rules/%.so: compile_rule
	$(QUIET) ./$(MAIN_GEN_PLUGIN) rules/$*.so rules/$*.xml
	
sample_rules: $(sort $(patsubst %.xml,%.so, $(wildcard rules/*.xml)))
	
copy_files:
	$(QUIET) $(MKDIR) /tmp/mmt/rules
	$(QUIET) $(MV) rules/*.so /tmp/mmt/rules/
	
	$(QUIET) $(MKDIR) /tmp/mmt/include
	$(QUIET) $(CP) $(SRCDIR)/dpi/* $(SRCDIR)/lib/*.h /tmp/mmt/include/
	
	$(QUIET) $(MKDIR) /tmp/mmt/bin
	$(QUIET) $(CP)  $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO)  /tmp/mmt/bin
	$(QUIET) $(CP)  $(MAIN_STAND_ALONE) /tmp/mmt/bin/mmt_security
	$(QUIET) $(CP)  $(MAIN_SEC_SERVER) /tmp/mmt/bin/
	
	$(QUIET) $(MKDIR) /tmp/mmt/lib
	$(QUIET) $(MV)  $(LIB_NAME).so /tmp/mmt/lib/$(LIB_NAME).so.$(VERSION)
	$(QUIET) $(MV)  $(LIB_NAME).a /tmp/mmt/lib/$(LIB_NAME).a.$(VERSION)
	
	$(QUIET) $(RM)  /tmp/mmt/lib/$(LIB_NAME).so /tmp/mmt/lib/$(LIB_NAME).a
	
	$(QUIET) $(LN)  $(INSTALL_DIR)/lib/$(LIB_NAME).so.$(VERSION) /tmp/mmt/lib/$(LIB_NAME)2.so 
	$(QUIET) $(LN)  $(INSTALL_DIR)/lib/$(LIB_NAME).a.$(VERSION)  /tmp/mmt/lib/$(LIB_NAME)2.a
	$(QUIET) chmod -x /tmp/mmt/lib/$(LIB_NAME).*
	
install: all lib sample_rules uninstall copy_files
	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(MV) /tmp/mmt/* $(INSTALL_DIR)
	$(QUIET) $(RM) /tmp/mmt
	
	@echo "/opt/mmt/security/lib" >> /etc/ld.so.conf.d/mmt-security.conf
	@ldconfig
	
	@echo ""
	@echo "Installed mmt-security in $(INSTALL_DIR)"
	
	
DEB_NAME = mmt-security_$(VERSION)_$(GIT_VERSION)_`uname -s`_`uname -m`
	
deb: all lib sample_rules copy_files
	$(QUIET) $(MKDIR) $(DEB_NAME)/DEBIAN $(DEB_NAME)/$(INSTALL_DIR)
	$(QUIET) $(MV) /tmp/mmt/* $(DEB_NAME)/$(INSTALL_DIR)
	$(QUIET) $(RM) /tmp/mmt
	
	$(QUIET) echo "Package: mmt-security \
        \nVersion: $(VERSION) \
        \nSection: base \
        \nPriority: standard \
        \nArchitecture: all \
        \nMaintainer: Montimage <contact@montimage.com> \
        \nDescription: MMT-Security: An intrusion detection system \
        \n  Version id: $(GIT_VERSION). Build time: `date +"%Y-%m-%d %H:%M:%S"` \
        \nHomepage: http://www.montimage.com" \
		> $(DEB_NAME)/DEBIAN/control
		
	$(QUIET) $(MKDIR) $(DEB_NAME)/etc/ld.so.conf.d/
	@echo "/opt/mmt/security/lib" >> $(DEB_NAME)/etc/ld.so.conf.d/mmt-security.conf
	
	$(QUIET) dpkg-deb -b $(DEB_NAME)
	$(QUIET) $(RM) $(DEB_NAME)
	
dist-clean: uninstall
	@echo "Removed mmt-security from $(INSTALL_DIR)"
	
clean:
	$(QUIET) $(RM) $(LIB_NAME).* $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* \
			$(MAIN_DPI) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO) $(MAIN_STAND_ALONE) $(MAIN_SEC_SERVER)
	
################################################################################
#auto test 
################################################################################
NAMES := $(sort $(patsubst check/pcap/%.pcap,%, $(wildcard check/pcap/*.pcap)))

ifdef VAL
	VALGRIND = valgrind --leak-check=yes
else
	VALGRIND =
endif

TEST_INDEX=1
_prepare: compile_rule standalone sample_rules
	@echo "==============================="
check/expect/%.csv :
	@echo "  => not found expected result: $@"
	@exit 1
check/pcap/%.pcap :
	@echo "  => not found sample pcap file: $@"
	@exit 1
_print.%:
	@echo
	@echo "$(TEST_INDEX). Testing $*"
	$(eval TEST_INDEX=$(shell echo $$(($(TEST_INDEX)+1))))
#one test
_check.%: _print.% check/expect/%.csv check/pcap/%.pcap
	$(QUIET) $(RM) /tmp/mmt-security*.csv
	$(QUIET) bash -c "$(VALGRIND) ./$(MAIN_STAND_ALONE) -t check/pcap/$*.pcap -f /tmp/"
	$(QUIET) bash -c "diff --ignore-all-space <(cut -c 20- check/expect/$*.csv) <(cut -c 20- /tmp/mmt-security*.csv) || (echo \"====================execution log:\" && cat /tmp/$*.log)"
	@echo '  => OK'
	
check: _prepare $(patsubst %,_check.%,$(NAMES))
	@echo "All test passed!"
	
_csv.%: _prepare
	$(QUIET) $(RM) /tmp/mmt-security*.csv
	$(QUIET) ./$(MAIN_STAND_ALONE) -v -t check/pcap/$*.pcap -f /tmp/ || exit 1
	$(QUIET) find /tmp/mmt-security*.csv -exec mv {} check/expect/$*.csv \;
	
csv: $(patsubst %,_csv.%,$(NAMES))
################################################################################