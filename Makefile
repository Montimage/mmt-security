CC     = gcc
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
VERSION = 1.0.0

#name of executable file to generate
OUTPUT   = security
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/security

    
#set of library
LIBS     = -ldl -lpthread -lxml2

CFLAGS   = -g -O0 -Wall -DNDEBUG -Wno-unused-variable -I/usr/include/libxml2/
CLDFLAGS = -g -DNDEBUG

#for debuging
ifdef DEBUG
	CFLAGS   += -g -DNDEBUG
	CLDFLAGS += -g -DNDEBUG
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

MMT_DPI_HEADER = $(SRCDIR)/lib/mmt_dpi.h

ifndef VERBOSE
	QUIET := @
endif

MAIN_DPI = gen_dpi_header

MAIN_GEN_SEC_LIB = gen_rules_lib

all: $(MMT_DPI_HEADER) $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] $(OUTPUT)"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)

gen_lib: $(MMT_DPI_HEADER) $(LIB_OBJS) $(SRCDIR)/main_gen_rules_lib.o
	@echo "[COMPILE] $(MAIN_GEN_SEC_LIB)"
	$(QUIET) $(CC) -o $(MAIN_GEN_SEC_LIB) $(CLDFLAGS) $^ $(LIBS)
	
gen_dpi src/lib/mmt_dpi.h:
	$(QUIET) $(CC) -I/opt/mmt/dpi/include -L/opt/mmt/dpi/lib -o $(MAIN_DPI) $(SRCDIR)/main_dpi.c -lmmt_core -ldl
	@echo "Generate list of protocols and their attributes"	
	$(QUIET) ./$(MAIN_DPI) > $(MMT_DPI_HEADER)

clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* $(MMT_DPI_HEADER) $(MAIN_DPI) $(MAIN_GEN_SEC_LIB)