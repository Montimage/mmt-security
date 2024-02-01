CC     = gcc
AR     = ar rcs
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
MV     = mv
LN     = ln -s

#name of executable file to generate
OUTPUT   = security

#directory where probe will be installed on
ifndef MMT_BASE
  MMT_BASE             := /opt/mmt
  NEED_ROOT_PERMISSION := 1
else
  $(info INFO: Set default folder of MMT to $(MMT_BASE))
endif

INSTALL_DIR := $(MMT_BASE)/security
MMT_DPI_DIR := $(MMT_BASE)/dpi

# directory where MMT-DPI was installed


#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.2.19

CACHE_LINESIZE := 64 #$(shell getconf LEVEL1_DCACHE_LINESIZE)

#set of library
LIBS     += -ldl -lpthread -lxml2  -l:libmmt_tcpip.so   # -l:libmmt_http2.so

CFLAGS   += -fPIC -Wall -DINSTALL_DIR=\"$(INSTALL_DIR)\" -DVERSION_NUMBER=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DLEVEL1_DCACHE_LINESIZE=$(CACHE_LINESIZE) -Wno-unused-variable -Wno-unused-function -Wuninitialized -I/usr/include/libxml2/  -I$(MMT_DPI_DIR)/include    #-I/usr/include/nghttp2 -lnghttp2
CLDFLAGS += -I$(MMT_DPI_DIR)/include -L$(MMT_DPI_DIR)/lib -L/usr/local/lib #-I/usr/include/nghttp2 -lnghttp2

#a specific flag for each .o file
CFLAGS += $(CFLAGS-$@)

#for debuging
ifdef DEBUG
  CFLAGS   += -g -DDEBUG_MODE -O0 -fstack-protector-all
else
  CFLAGS   += -O3
endif

ifdef VALGRIND
  CFLAGS += -DVALGRIND_MODE
endif

ifdef REDIS
  CFLAGS += -DMODULE_REDIS_OUTPUT
  LIBS   += -lhiredis
  $(info => Enable: Output to redis)	
endif

#Enable update_rules if this parameter is different 0 
ifndef UPDATE_RULES 
else
  ifneq "$(UPDATE_RULES)" "0"
  		CFLAGS += -DMODULE_ADD_OR_RM_RULES_RUNTIME
  endif
endif

#folders containing source files
SRCDIR := $(abspath ./src )

#objects to generate
LIB_OBJS  :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/lib/*.c))
TEST_OBJS :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/../test/*.c))

#filter out 2 files: src/main.c and src/test_probe.c
MAIN_SRCS := $(wildcard   $(SRCDIR)/*.c)
MAIN_SRCS := $(filter-out $(SRCDIR)/tips.c, $(MAIN_SRCS))

MAIN_SRCS := $(filter-out $(SRCDIR)/main_dpi.c, $(MAIN_SRCS))
MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS))

MMT_DPI_HEADER := $(SRCDIR)/dpi/mmt_dpi.h

ifndef VERBOSE
  QUIET := @
endif

MAIN_DPI = gen_dpi_header

MAIN_GEN_PLUGIN = compile_rule

MAIN_PLUGIN_INFO = rule_info

MAIN_STAND_ALONE = mmt_sec_standalone

MAIN_SEC_SERVER = mmt_sec_server

LIB_NAME = libmmt_security2


all: $(MMT_DPI_HEADER) compile_rule rule_info sec_server lib standalone

#this is useful when running the tools, such as, gen_dpi, compile_rule
# but libmmt_core, ... are not found by ldd
export LD_LIBRARY_PATH=$(MMT_DPI_DIR)/lib

# check if there exists the folder of MMT-DPI 
$(MMT_DPI_DIR):
	@echo "ERROR: Not found MMT-DPI at folder $(MMT_DPI_DIR).\n"
	@exit 1
	
#Generate a DPI header, so mmt-security does not depend on mmt-dpi after having the header
gen_dpi $(MMT_DPI_HEADER): $(MMT_DPI_DIR)
	$(QUIET) $(CC) -I$(MMT_DPI_DIR)/include -L$(MMT_DPI_DIR)/lib -o $(MAIN_DPI) $(SRCDIR)/main_gen_dpi.c -l:libmmt_core.so -ldl
	$(QUIET) echo ">>> Generate list of protocols and their attributes to $(MMT_DPI_HEADER)"
	$(QUIET) ./$(MAIN_DPI) $(MMT_DPI_HEADER)

%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $@ $(CLDFLAGS)  $^ $(LIBS)

perf.%: $(LIB_OBJS) test/perf/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $@ $(CLDFLAGS)  $^ $(LIBS)

compile_rule: $(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o
	@echo "[COMPILE] $(MAIN_GEN_PLUGIN)"
	$(QUIET) $(CC) -o $(MAIN_GEN_PLUGIN) $(CLDFLAGS) $^ $(LIBS) 
	
sec_server: $(LIB_OBJS)  $(SRCDIR)/main_sec_server.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER)  $(CFLAGS)  $(CLDFLAGS) $^ $(LIBS)
	
standalone:  $(MMT_DPI_DIR) $(LIB_OBJS)  $(SRCDIR)/main_sec_standalone.o $(RULE_OBJS) --refresh-plugin-engine
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_STAND_ALONE) $(CLDFLAGS) $(LIB_OBJS)  $(RULE_OBJS)  $(SRCDIR)/main_sec_standalone.o $(LIBS) -lpcap  -l:libmmt_core.so 

rule_info: $(LIB_OBJS) $(SRCDIR)/main_plugin_info.o
	@echo "[COMPILE] $(MAIN_PLUGIN_INFO)"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_PLUGIN_INFO) $(CLDFLAGS) $^ $(LIBS)


RULE_XML := $(sort $(wildcard rules/*.xml))

ifdef STATIC_LINK
#this block is for statically linking rules into libmmt_security.a

#here we got a list of rule files
RULE_OBJS := $(patsubst %.xml,%.o, $(RULE_XML))

#Generate code C of a rule
rules/%.c: compile_rule
	$(QUIET) echo [COMPILE] rules/$*.xml
	$(QUIET) ./$(MAIN_GEN_PLUGIN) $@ rules/$*.xml -c > /dev/null 2>&1

#Compile code C of a rule and add a RULE_SUFFIX is the name of the rule
# (we replace the non-alphanumeric characters by underscores)
rules/%.o: rules/%.c
	@#replace non-alphanumeric characters in the file name of rule(s) by underscores
	$(eval RULE_SUFFIX=$(shell echo $* | sed "s/[^[:alnum:]]/_/g"))
	
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -I./src/lib -I./src/dpi -c -o $@ $< -DRULE_SUFFIX=_$(RULE_SUFFIX)
	@#we do not need its C code any more, delete it
	$(QUIET) $(RM) $<
	@#remember the list of suffix of compiled rules
	$(eval STATIC_RULES_SUFFIX_LIST += SUFFIX($(RULE_SUFFIX)))


#update the CFLAG for plugins_engine.so
CFLAG-PLUGINS-ENGINE +=  -DSTATIC_RULES_SUFFIX_LIST="$(STATIC_RULES_SUFFIX_LIST)"
  
SAMPLE_RULES :=
else
  SAMPLE_RULES := $(patsubst %.xml,%.so, $(RULE_XML))
  RULE_OBJS    :=
endif

# This target is to deal with the issue when user uses 
#   2 differrent values of INSTALL_DIR for "make" and "make install"
# Ex: make; sudo make install INSTALL_DIR=/tmp/mmt/security
#   - the first "make" will set in the codes MMT_SEC_PLUGINS_REPOSITORY_OPT to /opt/mmt/security/rules
#   - while the second "make install" will install to /tmp/mmt
# Thus we need to recompile the codes that use MMT_SEC_PLUGINS_REPOSITORY_OPT to update the new directory.
# The following target will remove the object files of the codes, thus it will trigger to recompile them.
# So, in the example above, the MMT_SEC_PLUGINS_REPOSITORY_OPT will be update to /tmp/mmt/security/rules.
	
--refresh-plugin-engine:
	$(QUIET) echo [RE-COMPILE] plugins_engine.o
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) $(CFLAG-PLUGINS-ENGINE) -c -o $(SRCDIR)/lib/plugins_engine.o $(SRCDIR)/lib/plugins_engine.c


# RULE_OBJS is a list of .o files of rules
#   This list is empty if we compile without STATIC_LINK option
$(LIB_NAME).a:
	$(QUIET) echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $(LIB_NAME).a  $(LIB_OBJS) $(RULE_OBJS)
	
	@#$(QUIET) $(RM) $(RULE_OBJS) #we do not need rules/*.o anymore

$(LIB_NAME).so:
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC)  -fPIC -shared -O3 -o $(LIB_NAME).so $(LIB_OBJS)  $(RULE_OBJS)
	
lib:  $(LIB_OBJS)  $(RULE_OBJS) --refresh-plugin-engine $(LIB_NAME).a $(LIB_NAME).so
	
uninstall:
	$(QUIET) $(RM) $(INSTALL_DIR)
	
ifdef NEED_ROOT_PERMISSION
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt-security.conf
endif


rules/%.so: compile_rule
	$(QUIET) ./$(MAIN_GEN_PLUGIN) rules/$*.so rules/$*.xml
	
sample_rules: $(SAMPLE_RULES)


# create a temporal folder
TMP_DIR := build_mmt_security

copy_files:
	$(QUIET) $(RM)    $(TMP_DIR) 2> /dev/null
	$(QUIET) $(MKDIR) $(TMP_DIR)/rules
	
ifndef STATIC_LINK
	$(QUIET) $(CP)    rules/*.so $(TMP_DIR)/rules/
endif

	$(QUIET) $(CP)    mmt-security.conf  $(TMP_DIR)/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/include
	$(QUIET) $(CP)    $(SRCDIR)/dpi/* $(SRCDIR)/lib/*.h $(TMP_DIR)/include/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/bin
	$(QUIET) $(CP)    $(MAIN_GEN_PLUGIN)  $(MAIN_PLUGIN_INFO)  $(TMP_DIR)/bin
	$(QUIET) $(CP)    $(MAIN_STAND_ALONE) $(TMP_DIR)/bin/mmt_security
	$(QUIET) $(CP)    $(MAIN_SEC_SERVER)  $(TMP_DIR)/bin/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/lib
	$(QUIET) $(MV)    $(LIB_NAME).so      $(TMP_DIR)/lib/$(LIB_NAME).so.$(VERSION)
	$(QUIET) $(MV)    $(LIB_NAME).a       $(TMP_DIR)/lib/$(LIB_NAME).a.$(VERSION)
	
	$(QUIET) $(RM)  $(TMP_DIR)/lib/$(LIB_NAME).so $(TMP_DIR)/lib/$(LIB_NAME).a
	
ifdef REDIS
	$(QUIET) $(CP) /usr/local/lib/libhiredis.so.0.13 $(TMP_DIR)/lib/
endif

#create symbolic links	
	$(QUIET) cd $(TMP_DIR)/lib/ && $(LN)  $(LIB_NAME).so.$(VERSION) $(LIB_NAME).so
	$(QUIET) cd $(TMP_DIR)/lib/ && $(LN)  $(LIB_NAME).a.$(VERSION)  $(LIB_NAME).a
	
	
install: all sample_rules uninstall copy_files
	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(MV)    $(TMP_DIR)/* $(INSTALL_DIR)
	$(QUIET) $(RM)    $(TMP_DIR)
	
ifdef NEED_ROOT_PERMISSION
	@echo "$(INSTALL_DIR)/lib" >> /etc/ld.so.conf.d/mmt-security.conf
	@ldconfig
endif

	@echo ""
	@echo "INFO: Installed successfully MMT-Security in $(INSTALL_DIR)"
	
	
DEB_NAME = mmt-security_$(VERSION)_$(GIT_VERSION)_$(shell uname -s)_$(shell uname -m)

deb: all lib sample_rules copy_files
	$(QUIET) $(MKDIR) $(DEB_NAME)/DEBIAN $(DEB_NAME)/$(INSTALL_DIR)
	$(QUIET) $(MV) $(TMP_DIR)/* $(DEB_NAME)/$(INSTALL_DIR)
	$(QUIET) $(RM) $(TMP_DIR)
	
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
	@echo "$(INSTALL_DIR)/lib" > $(DEB_NAME)/etc/ld.so.conf.d/mmt-security.conf
	
	$(QUIET) dpkg-deb -b $(DEB_NAME)
	$(QUIET) $(RM) $(DEB_NAME)
	
	
#create rpm file for RHEL
rpm: all lib sample_rules copy_files
	
#create rpm structure
	$(QUIET) $(MKDIR) ./rpmbuild/{RPMS,BUILD}
	
	$(QUIET) echo -e\
      "Summary:  MMT-Security:  An intrusion detection system\
      \nName: mmt-security\
      \nVersion: $(VERSION)\
      \nRelease: $(GIT_VERSION)\
      \nLicense: proprietary\
      \nGroup: Development/Libraries\
      \nURL: http://montimage.com/\
      \n\
      \nRequires:  mmt-dpi >= 1.6.9\
      \nBuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}\
      \n\
      \n%description\
      \nMMT-Security is a library using MMT-DPI to detect abnormalities in network.\
      \nBuild date: `date +"%Y-%m-%d %H:%M:%S"`\
      \n\
      \n%prep\
      \nrm -rf %{buildroot}\
      \nmkdir -p %{buildroot}/$(INSTALL_DIR)\
      \ncp -rL $(TMP_DIR)/* %{buildroot}/$(INSTALL_DIR)\
      \nmkdir -p %{buildroot}/etc/ld.so.conf.d/\
      \necho "$(INSTALL_DIR)/lib" >> %{buildroot}/etc/ld.so.conf.d/mmt-security.conf\
      \n\
      \n%clean\
      \nrm -rf %{buildroot}\
      \n\
      \n%files\
      \n%defattr(-,root,root,-)\
      \n$(INSTALL_DIR)/*\
      \n/etc/ld.so.conf.d/mmt-security.conf\
      \n%post\
      \nldconfig\
   " > ./mmt-security.spec
	
	$(QUIET) rpmbuild --quiet --rmspec --define "_topdir $(shell pwd)/rpmbuild" --define "_rpmfilename ../../$(DEB_NAME).rpm" -bb ./mmt-security.spec
	$(QUIET) $(RM) $(TMP_DIR) rpmbuild
	@echo "[PACKAGE] $(DEB_NAME).rpm"
		
dist-clean: uninstall
	@echo "INFO: Removed successfully MMT-Security from $(INSTALL_DIR)"

clean-rules:
	$(QUIET) $(RM) rules/*.so rules/*.o rules/*.c
clean: clean-rules
	$(QUIET) $(RM) $(LIB_NAME).* $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* \
			$(MAIN_DPI) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO) $(MAIN_STAND_ALONE) $(MAIN_SEC_SERVER)\
			$(RULE_OBJS) $(TMP_DIR)
	
clean-all: clean
	$(QUIET) $(RM) $(MMT_DPI_HEADER)
	
################################################################################
# Auto test 
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
#starting by rule id (rm timestamp, filename, probe-id)
	$(QUIET) bash -c "cut -d, -f5- /tmp/mmt-security*.csv  > /tmp/mmt-security-res.csv"
	$(QUIET) bash -c "cut -d, -f5- check/expect/$*.csv     > /tmp/mmt-security-expect.csv"
#get set of rules
	$(QUIET) bash -c "cut -d, -f1 /tmp/mmt-security-expect.csv | sort | uniq > /tmp/mmt-security-expect-rule-id.csv"
	$(QUIET) cat /tmp/mmt-security-expect-rule-id.csv
#get only verdicts of the rules
# the first -e "" is used to avoid hanging when mmt-security-res.csv is empty
	$(QUIET) bash -c 'grep -e "" $$(while read ruleId; do echo "-e ^$$ruleId"; done < /tmp/mmt-security-expect-rule-id.csv) /tmp/mmt-security-res.csv > /tmp/mmt-security-result.csv || echo "" '
	$(QUIET) wc -l /tmp/mmt-security-expect.csv
	$(QUIET) wc -l /tmp/mmt-security-result.csv
	$(QUIET) bash -c "diff --ignore-all-space /tmp/mmt-security-expect.csv /tmp/mmt-security-result.csv || (echo \"====================execution log:\" && cat /tmp/$*.log)"
	@echo '  => OK'
	
check: _prepare $(patsubst %,_check.%,$(NAMES))
	@echo "All test passed!"
	
_csv.%: _prepare
	$(QUIET) $(RM) /tmp/mmt-security*.csv
	$(QUIET) ./$(MAIN_STAND_ALONE) -v -t check/pcap/$*.pcap -f /tmp/ || exit 1
	$(QUIET) find /tmp/mmt-security*.csv -exec mv {} check/expect/$*.csv \;
	
csv: $(patsubst %,_csv.%,$(NAMES))
################################################################################
