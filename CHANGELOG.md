# Changelog
All notable changes to this project will be documented in this file.

Before 1.0, this project does not adhere to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

I'm sorry, I will try my best to ease breaking changes.  We're almost to 1.0, don't worry!

## [Unreleased]
### Added
- proper cputype and cpusubtype constants to mach, along with mappings, courtesy of @mitsuhiko
- new osx and ios version constants
- all mach load commands now implement IOread and IOwrite from scroll
- add new elf::note module and associated structs + constants, and `iter_notes` method to Elf object
- remove all unused muts; this will make nightly and future stables no longer warn

### Changed
- mach header cpusubtype bug fixed, thanks @mitsuhiko !
- add proper std feature flag to log; this was an oversight in last version

## [0.0.11] - 2017-08-24
### Added
- goblin::Object::parse; add deprecation to goblin::parse
- MAJOR archive now parses bsd style archives AND is zero-copy by @willglynn
- MAJOR macho import parser bug fixed by @willglynn
- added writer impls for Section and Segment
- add get_unsafe to strtab for Option<&str> returns
- relocations method on mach
- more elf relocations
- mach relocations
- convenience functions for many elf structures that elf writer will appreciate
- mach relocation iteration
- update to scroll 0.7
- add cread/ioread impls for various structs

### Changed
- BREAKING: sections() and section iterator now return (Section, &[u8])
- Segment, Section, RelocationIterator are now in segment module
- removed lifetime from section, removed data and raw data, and embedded ctx
- all scroll::Error have been removed from public API ref #33
- better mach symbol iteration
- better mach section iteration
- remove wow_so_meta_doge due to linker issues
- Strtab.get now returns a Option<Result>, when index is bad
- elf.soname is &str
- elf.libraries is now Vec<&str>

## [0.0.10] - 2017-05-09
### Added
- New goblin::Object for enum containing the parsed binary container, or convenience goblin::parse(&[u8) for parsing bytes into respective container format
### Changed
- All binaries formats now have lifetimes
- Elf has a lifetime
- Strtab.new now requires a &'a[u8]
- Strtab.get now returns a scroll::Result<&'a str> (use strtab[index] if you want old behavior and don't care about panics); returning scroll::Error is a bug, fixed in next release

## [0.0.9] - 2017-04-05
### Changed
- Archive has a lifetime
- Mach has a lifetime
