# Build shared libraries (32/64) with versioned symbols and applications (32/64).

RELF = readelf -W --dynamic --dyn-syms --version-info
COMP = $(CC) -m$* -Os -o $@ $^

all: prog32 prog64 lib32.so lib64.so

prog%: main.c lib%.so
	$(COMP) -Wl,-rpath=$(CURDIR) -ldl

# Symbol versioning does not work with LTO enabled.
# Just turn it off explicitly in case it's enabled by default.
lib%.so: lib.c
	$(COMP) -shared -fPIC -Wl,--version-script=lib.ver -fno-lto

elf: all
	$(RELF) prog32 lib32.so
	$(RELF) prog64 lib64.so

clean:
	$(RM) prog32 lib32.so
	$(RM) prog64 lib64.so
