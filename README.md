# libgoblin [![Build Status](https://travis-ci.org/m4b/goblin.svg?branch=master)](https://travis-ci.org/m4b/goblin)

![say the right words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)

### Features

* goblins (TBA)
* the best, most feature complete ELF64 implementation, ever.
* begrudging ELF32 support, with type punning!
* many cfg options - it will make your head spin, and make you angry when reading the source!
* slowly adding mach-o and PE binary support, mostly because it's boring and it's just a port of [rdr](http://github.com/m4b/rdr)
* tests
* awesome crate name

Libgoblin aims to be your one-stop shop for binary parsing, loading, and analysis.  Eventually, at some future date, once the holy trinity is finished (ELF, mach, PE), writers for the various binary formats are planned.

### Use-cases and Planned Features

Here are some things you could do with this crate (or help to implement so they could be done):

1. write a compiler and use it to generate binaries with the future writers defined here
2. write a binary analysis tool which parses all three formats
3. write a [non-functioning dynamic linker](http://github.com/m4b/dryad) because libc implementations define massive, persistent global state and are tightly coupled with their dynamic linker implementations, because *nix is broken by design ;)
4. write a kernel and load binaries using the forthcoming "pure" cfg. I.e., it is essentially just struct and const defs (like a C header) - no fd, no output, no std.
5. write a bin2json tool (http://github.com/m4b/bin2json), because why shouldn't binary formats be in JSON?

### Cfgs

libgoblin is designed to be massively configurable; by default however, all binary targets are default opted in.  Therefore, you must _opt out_, in contrast to rust guidelines.  This may change before the 1.0 release, in which case you will have to _opt in_ (the negation).

Currently the feature flags are:

* no_elf
* no_elf32
* no_mach
* no_mach32
* no_pe
* no_pe32
* no_endian_fd

Planned flags:

* pure

Note: the non-suffixed 32 binary formats are default 64 bit, because I'm trying to brainwash everyone into forgetting about 32-bit binary formats.  It's not working, and I may add 64 bit suffixes to make this clear.

The planned `pure` flag, as stated above, is essentially just struct and const defs (like a C header) - no fd, no output, no std - suitable for use in kernel development environments or other somesuch stuff.
