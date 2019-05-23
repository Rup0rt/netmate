PREFIX = /usr
BINDIR = $(PREFIX)/bin
DOCDIR = $(PREFIX)/share/doc
MANDIR = $(PREFIX)/share/man
APPDIR = $(PREFIX)/share/applications
ICODIR = $(PREFIX)/share/pixmaps

OPTFLAGS = $(shell getconf LFS_CFLAGS) -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4
WARNFLAGS = -Wall -Wextra -Wformat -Werror=format-security
DEBUGFLAGS = -g
CFLAGS += $(OPTFLAGS) $(WARNFLAGS) $(DEBUGFLAGS)
LDFLAGS += -Wl,-z,relro
PKG_CONFIG ?= pkg-config
GTK_CFLAGS = $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GTK_LIBS = $(shell $(PKG_CONFIG) --libs gtk+-3.0)

all: netmate.c layer2.h layer3.h layer4.h
	$(CC) $(CPPFLAGS) $(GTK_CFLAGS) $(CFLAGS) -c netmate.c -o netmate.o
	$(CC) $(LDFLAGS) netmate.o $(GTK_LIBS)  -lpcap -o netmate

install:
	install -D -m 755 netmate $(DESTDIR)/$(BINDIR)/netmate
	install -D -m 644 netmate.1 $(DESTDIR)/$(MANDIR)/man1/netmate.1
	install -D -m 644 res/netmate.desktop $(DESTDIR)/$(APPDIR)/netmate.desktop
	install -D -m 644 res/netmate.xpm $(DESTDIR)/$(ICODIR)/netmate.xpm

uninstall:
	rm -f $(DESTDIR)/$(BINDIR)/netmate
	rm -f $(DESTDIR)/$(MANDIR)/man1/netmate.1
	rm -f $(DESTDIR)/$(APPDIR)/netmate.desktop
	rm -f $(DESTDIR)/$(ICODIR)/netmate.xpm

clean:
	rm -f *.o netmate
