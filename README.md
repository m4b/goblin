# libgoblin [![Build Status](https://travis-ci.org/m4b/goblin.svg?branch=master)](https://travis-ci.org/m4b/goblin) [![Current Crates.io Version](https://img.shields.io/crates/v/goblin.svg)](https://crates.io/crates/goblin)

![say the right words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)

### Documentation

https://docs.rs/goblin/

[changelog](CHANGELOG.md)

### Usage

Goblin requires `rustc` 1.18.

Add to your `Cargo.toml`

```toml
[dependencies]
goblin = "0.0.13"
```

### Features

* awesome crate name
* zero-copy, cross-platform, endian-aware, ELF64/32 implementation - wow!
* zero-copy, cross-platform, endian-aware, 32/64 bit Mach-o parser - zoiks!
* PE 32/64-bit parser - bing!
* a Unix _and_ BSD style archive parser (latter courtesy of [@willglynn](https://github.com/willglynn)) - huzzah!
* many cfg options - it will make your head spin, and make you angry when reading the source!
* fuzzed - " I am happy to report that goblin withstood 100 million fuzzing runs, 1 million runs each for seed 1~100." - [@sanxiyn](https://github.com/sanxiyn)
* tests

`libgoblin` aims to be your one-stop shop for binary parsing, loading,
and analysis.

### Use-cases

Goblin primarily supports the following important use cases:

1. Core, std-free `#[repr(C)]` structs, tiny compile time, 32/64 (or both) at your leisure

2. Type punning. Define a function once on a type, but have it work on 32 or 64-bit variants - without really changing anything, and no macros! See `examples/automagic.rs` for a basic example.

3. `std` mode. This throws in read and write impls via `Pread` and `Pwrite`, reading from file, convenience allocations, extra methods, etc. This is for clients who can allocate and want to read binaries off disk.

4. `Endian_fd`. A truly terrible name :laughing: this is for binary analysis like in [panopticon](https://github.com/das-labor/panopticon) or [falcon](https://github.com/endeav0r/falcon) which needs to read binaries of foreign endianness, _or_ as a basis for constructing cross platform foreign architecture binutils, e.g. [cargo-sym](https://github.com/m4b/cargo-sym) and [bingrep](https://github.com/m4b/bingrep) are simple examples of this, but the sky is the limit.

Here are some things you could do with this crate (or help to implement so they could be done):

1. write a compiler and use it to [generate binaries](https://github.com/m4b/faerie) (all the raw C structs have [`Pwrite`](https://github.com/m4b/scroll) derived)
2. write a binary analysis tool which loads, parses, and analyzes various binary formats, e.g., [panopticon](https://github.com/das-labor/panopticon) or [falcon](https://github.com/endeav0r/falcon)
3. write a [semi-functioning dynamic linker](http://github.com/m4b/dryad)
4. write a [kernel](https://github.com/redox-os/redox) and load binaries using `no_std` cfg. I.e., it is essentially just struct and const defs (like a C header) - no fd, no output, no std.
5. write a bin2json tool (http://github.com/m4b/bin2json), because why shouldn't binary formats be in JSON?

### Cfgs

`libgoblin` is designed to be massively configurable. The current flags are:

* elf64 - 64-bit elf binaries, `repr(C)` struct defs
* elf32 - 32-bit elf binaries, `repr(C)` struct defs
* mach64 - 64-bit mach-o `repr(C)` struct defs
* mach32 - 32-bit mach-o `repr(C)` struct defs
* pe32 - 32-bit PE `repr(C)` struct defs
* pe64 - 64-bit PE `repr(C)` struct defs
* archive - a Unix Archive parser
* endian_fd - parses according to the endianness in the binary
* std - to allow `no_std` environments

# Contributors

Thank you all :heart: !

In alphabetic order:

- [@flanfly](https://github.com/flanfly)
- [@jdub](https://github.com/jdub)
- [@le-jzr](https://github.com/le-jzr)
- [@lion128](https://github.com/lion128)
- [@llogiq](https://github.com/llogiq)
- [@mitsuhiko](https://github.com/mitsuhiko)
- [@mre](https://github.com/mre)
- [@philipc](https://github.com/philipc)
- [@sanxiyn](https://github.com/sanxiyn)
- [@ticki](https://github.com/ticki)
- [@willglynn](https://github.com/willglynn)
