PLUGIN_NAME = matter-dissector

# Example for RasPi: CROSS_COMPILE=arm-linux-gnueabihf- make
CROSS_COMPILE ?=

ifeq ($(UNAME_S),Darwin)
CC  = $(CROSS_COMPILE)llvm-gcc
CPP = $(CROSS_COMPILE)llvm-g++
LD  = $(CROSS_COMPILE)ld
AR  = $(CROSS_COMPILE)ar
else
CC  = $(CROSS_COMPILE)gcc
CPP = $(CROSS_COMPILE)g++
LD  = $(CROSS_COMPILE)g++
AR  = $(CROSS_COMPILE)ar
endif

#CC  = $(CROSS_COMPILE)clang
#CPP = $(CROSS_COMPILE)clang++
#LD  = $(CROSS_COMPILE)ld
#AR  = $(CROSS_COMPILE)llvm-ar

WIRESHARK_SRC_DIR ?= ../wireshark
WIRESHARK_BUILD_DIR ?= $(WIRESHARK_SRC_DIR)/build

UNAME_S := $(shell uname -s)

WIRESHARK_CFLAGS = -I$(WIRESHARK_SRC_DIR) -I$(WIRESHARK_BUILD_DIR)
WIRESHARK_LDFLAGS =

MATTER_ROOT ?= MatterMinimal

MATTER_CFLAGS = -I$(MATTER_ROOT)/include -DHAVE_MALLOC -DHAVE_FREE

ifeq ($(MATTER_ROOT),MatterMinimal)
MATTER_SRCS =											\
	$(MATTER_ROOT)/src/lib/core/MatterTLVReader.cpp		\
	$(MATTER_ROOT)/src/lib/support/MatterNames.cpp		\
	$(MATTER_ROOT)/src/lib/support/ErrorStr.cpp			\
	$(MATTER_ROOT)/src/lib/support/StatusReportStr.cpp
else
MATTER_LDFLAGS = -L$(MATTER_ROOT)/x86_64-unknown-linux-gnu/lib -lMatter
endif

#PKG_CONFIG_FLAGS = \
#	PKG_CONFIG_SYSTEM_LIBRARY_PATH=/usr/lib/arm-linux-gnueabihf/lib \
#	PKG_CONFIG_SYSTEM_INCLUDE_PATH=/usr/lib/arm-linux-gnueabihf/include \
#	PKG_CONFIG_ALLOW_CROSS=1

GLIB_CFLAGS ?= $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS ?= $(shell pkg-config --libs  glib-2.0)

OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl)
OPENSSL_LDFLAGS ?= $(shell pkg-config --libs openssl)

OPT_FLAGS ?= -g3 -O0

WARN_FLAGS ?= -Wall

CFLAGS = -ffunction-sections -fdata-sections $(GLIB_CFLAGS) $(OPENSSL_CFLAGS) $(WIRESHARK_CFLAGS) $(MATTER_CFLAGS) $(WARN_FLAGS) $(OPT_FLAGS) -fPIC -DPIC
CPPFLAGS = $(CFLAGS)

LDFLAGS = $(GLIB_LDFLAGS) $(WIRESHARK_LDFLAGS) $(MATTER_LDFLAGS) $(OPENSSL_LDFLAGS) $(OPT_FLAGS) -lstdc++

ifeq ($(UNAME_S),Darwin)
PLUGIN_OUT = matter-dissector.dylib
LDFLAGS += -Wl,-install_name=$(PLUGIN_NAME).dylib
else
PLUGIN_OUT = matter-dissector.so
LDFLAGS += -Wl,-soname=$(PLUGIN_NAME).so -Wl,-Map -Wl,$(PLUGIN_NAME).map -Wl,--cref -Wl,--exclude-libs=ALL -Wl,--gc-sections
endif

DISSECTOR_SRCS := packet-matter.cpp packet-matter-decrypt.cpp packet-matter-echo.cpp packet-matter-common.cpp packet-matter-im.cpp packet-matter-security.cpp
SRCS := $(DISSECTOR_SRCS) $(MATTER_SRCS) TLVDissector.cpp MatterMessageTracker.cpp MessageEncryptionKey.cpp UserEncryptionKeyPrefs.cpp HKDF.c
HEADERS = moduleinfo.h  packet-matter.h packet-matter-decrypt.h TLVDissector.h MatterMessageTracker.h MessageEncryptionKey.h UserEncryptionKeyPrefs.h HKDF.h
OBJS := $(foreach src, $(SRCS), $(src:.c=.o))
OBJS := $(foreach src, $(OBJS), $(src:.cpp=.o))

TEST_INPUT ?= tests/chip_tool_test_TestCluster_22f09.pcapng
TEST_ECHO ?= tests/matter_echo.pcapng

TEST_SRCS := tests/test-packet-matter-decrypt.cpp
#TEST_SRCS  = $(shell find . -maxdepth 1 -name 'tests/*.c')
#TEST_SRCS += $(shell find . -maxdepth 1 -name 'tests/*.cpp')

TEST_OBJS := $(patsubst %.c, %.o,$(filter %.c,  $(TEST_SRCS)))
TEST_OBJS += $(patsubst %.cpp,%.o,$(filter %.cpp, $(TEST_SRCS)))

TEST_EXES := $(patsubst %.o, %.exe,$(filter %.o,  $(TEST_OBJS)))

.PHONY : all install clean test

all : $(PLUGIN_OUT)

$(PLUGIN_OUT) : $(OBJS) $(SRCS) $(HEADERS)
	$(CC) -shared $(OBJS) $(LDFLAGS) -o $@

#$(TEST_EXES) : $(TEST_OBJS)
#	$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

tests/test-packet-matter-decrypt.exe: tests/test-packet-matter-decrypt.o packet-matter-decrypt.o
	$(CC) -o $@ $^ $(LDFLAGS) -lpthread -ldl


install : $(PLUGIN_OUT)
	mkdir -p ~/.local/lib/wireshark/plugins/3.6/epan
	cp $(PLUGIN_OUT) ~/.local/lib/wireshark/plugins/3.6/epan

test : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 $(WIRESHARK_BUILD_DIR)/run/wireshark $(TEST_INPUT)

testecho : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 $(WIRESHARK_BUILD_DIR)/run/wireshark $(TEST_ECHO)

debug : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 libtool --mode=execute gdb $(WIRESHARK_BUILD_DIR)/run/wireshark -ex "set args $(TEST_INPUT)"

debugecho : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 libtool --mode=execute gdb $(WIRESHARK_BUILD_DIR)/run/wireshark -ex "set args $(TEST_ECHO)"

check: install $(TEST_EXES)
	tests/test-packet-matter-decrypt.exe

clean :
	rm -f $(OBJS) $(PLUGIN_NAME).so *.map tests/*.exe

### Generic rules based on extension
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.cc
	$(CPP) -c $(CFLAGS) $< -o $@

%.o: %.cpp
	$(CPP) -c $(CFLAGS) $< -o $@
