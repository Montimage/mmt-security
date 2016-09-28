CC     = gcc
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
VERSION = 1.0.0

#name of executable file to generate
OUTPUT   = security
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/probe

    
#set of library
LIBS     = -ldl -lpthread -lxml2

CFLAGS   = -g -O3 -Wall -DNDEBUG -Wno-unused-variable -I/usr/include/libxml2/
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
MAIN_SRCS := $(filter-out $(SRCDIR)/tip.c, $(MAIN_SRCS))
MAIN_SRCS := $(filter-out $(SRCDIR)/*_defs.h, $(MAIN_SRCS))

MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS))

ifndef VERBOSE
	QUIET := @
endif

all: $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] $(OUTPUT)"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.*