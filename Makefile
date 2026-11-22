CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

VERSION := $(shell cat VERSION)
GIT_REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
TARGET := am-i-vulnerable

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_UNIT_DIR ?= $(PREFIX)/lib/systemd/system
DESTDIR ?=

DIST_DIR := dist
DIST_NAME := $(TARGET)-$(VERSION)-$(GIT_REV)

.PHONY: all check install uninstall dist clean

all: $(TARGET)

$(TARGET): src/main.c VERSION
	$(CC) $(CPPFLAGS) $(CFLAGS) -DVERSION=\"$(VERSION)\" \
		-o $(TARGET) src/main.c $(LDFLAGS) $(LDLIBS)

check: $(TARGET)
	./$(TARGET) --version >/dev/null

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
	rm -rf $(DIST_DIR)
