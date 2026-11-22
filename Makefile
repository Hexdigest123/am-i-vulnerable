CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libcurl libxml-2.0)
LDLIBS += $(shell $(PKG_CONFIG) --libs libcurl libxml-2.0)

DEV ?= 0
ifeq ($(DEV),1)
CPPFLAGS += -DDEV
endif

VERSION := $(shell cat VERSION)
GIT_REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
TARGET := am-i-vulnerable

SRC_DIR := src
BUILD_DIR := build/$(if $(filter 1,$(DEV)),dev,release)
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_UNIT_DIR ?= $(PREFIX)/lib/systemd/system
DESTDIR ?=

DIST_DIR := dist
DIST_NAME := $(TARGET)-$(VERSION)-$(GIT_REV)

.PHONY: all check install uninstall dist clean dev FORCE

all: $(TARGET)

$(TARGET): $(OBJS) FORCE
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

FORCE:

dev:
	$(MAKE) DEV=1
	exec ./$(TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c VERSION | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DVERSION=\"$(VERSION)\" -MMD -MP -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

check: $(TARGET)
	./$(TARGET) --help >/dev/null

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"
	install -d "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	install -m 0644 systemd/$(TARGET).service \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(TARGET).service"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(TARGET).service"

dist: $(TARGET)
	rm -rf "$(DIST_DIR)/$(DIST_NAME)"
	$(MAKE) install \
		DESTDIR="$(CURDIR)/$(DIST_DIR)/$(DIST_NAME)" \
		PREFIX=/usr/local
	tar -C "$(DIST_DIR)/$(DIST_NAME)" -czf \
		"$(DIST_DIR)/$(DIST_NAME).tar.gz" .
	@printf 'Created %s\n' "$(DIST_DIR)/$(DIST_NAME).tar.gz"

clean:
	rm -f $(TARGET)
	rm -rf build $(DIST_DIR)

-include $(DEPS)
