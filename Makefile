UNAME := $(shell uname -s)
SRCDIR   = src
PRVDIR	 = priv

ifeq ($(UNAME),Linux)
CFLAGS = -fPIC -std=c99 -D_GNU_SOURCE -pedantic-errors -Wall -Wextra -I$(ERTS_INCLUDE_DIR)
LFLAGS = -shared -dynamiclib -undefined,dynamic_lookup
SOURCES = src/sniff_linux.c src/sniff_posix.c src/sniff.c
TARGET = $(PRVDIR)/sniff_linux.so
OBJDIR = obj/sniff_linux
endif

ifeq ($(UNAME),Darwin)
CFLAGS = -fPIC -std=c99 -D_GNU_SOURCE -pedantic-errors -Wall -Wextra -I$(ERTS_INCLUDE_DIR)
LFLAGS = -shared -dynamiclib -undefined dynamic_lookup
SOURCES = src/sniff_darwin.c src/sniff_posix.c src/sniff.c
TARGET = $(PRVDIR)/sniff_darwin.so
OBJDIR = obj/sniff_darwin
endif

HEADERS = $(SRCDIR)/sniff.h

OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean

all: $(TARGET)

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c $(HEADERS)
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -o $@ -c $<

$(TARGET): $(OBJECTS)
	mkdir -p $(PRVDIR)
	$(CC) $(LFLAGS) -o $@ $^

clean:
	rm -fr $(OBJDIR)
	rm -f $(TARGET)
