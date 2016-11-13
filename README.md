# libgoblin [![Build Status](https://travis-ci.org/m4b/goblin.svg?branch=master)](https://travis-ci.org/m4b/goblin)

![say the right words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)

### Features

* goblins (TBA)
* the best, most feature complete ELF64/32 implementation, ever - now with auto type punning!
* many cfg options - it will make your head spin, and make you angry when reading the source!
* slowly adding mach-o and PE binary support, mostly because it's boring and it's just a port of [rdr](http://github.com/m4b/rdr)
* tests
* awesome crate name

`libgoblin` aims to be your one-stop shop for binary parsing, loading,
and analysis.  Eventually, at some future date, once the holy trinity
is finished (ELF, mach, PE), writers for the various binary
formats are planned.

See the [documentation](https://docs.rs/goblin/0.0.5/goblin/) for more.

### Use-cases and Planned Features

Here are some things you could do with this crate (or help to implement so they could be done):

1. write a compiler and use it to generate binaries with the future writers defined here
2. write a binary analysis tool which parses all three formats
3. write a [non-functioning dynamic linker](http://github.com/m4b/dryad) because libc implementations define massive, persistent global state and are tightly coupled with their dynamic linker implementations, because *nix is broken by design ;)
4. write a kernel and load binaries using the forthcoming "pure" cfg. I.e., it is essentially just struct and const defs (like a C header) - no fd, no output, no std.
5. write a bin2json tool (http://github.com/m4b/bin2json), because why shouldn't binary formats be in JSON?

### Cfgs

`libgoblin` is designed to be massively configurable. The current flags are:

* elf64 - usable
* elf32 - usable
* mach64 - wip
* mach32 - wip
* pe64 - unimplemented
* pe32 - unimplemented
* endian_fd - parses according to the endianness in the binary
* std - to allow `no_std` environments
* archive - a Unix Archive parser