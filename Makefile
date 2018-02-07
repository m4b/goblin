ELF32 = $(wildcard src/elf/_32/*.rs)
ELF = $(wildcard src/elf/*.rs)
ELF64 = $(wildcard src/elf/_64/*.rs)
MACH = $(wildcard src/mach/*.rs)
PE = $(wildcard src/pe/*.rs)
SRC = $(wildcard src/*.rs) $(ELF) $(ELF64) $(ELF32) $(MACH) $(PE)

ARTIFACTS = $(addprefix target/debug/, libgoblin.rlib libgoblin.so)

$(ARTIFACTS): $(SRC)
	cargo rustc -- -Z incremental=target/

doc:
	cargo doc

clean:
	cargo clean

test:
	RUST_BACKTRACE=1 cargo test

example:
	cargo run --example=rdr -- /bin/ls

api:
	cargo build --no-default-features
	cargo build --no-default-features --features="std"
	cargo build --no-default-features --features="endian_fd std"
	cargo build --no-default-features --features="elf32"
	cargo build --no-default-features --features="elf32 elf64"
	cargo build --no-default-features --features="elf32 elf64 std"
	cargo build --no-default-features --features="elf32 elf64 endian_fd std"
	cargo build --no-default-features --features="archive std"
	cargo build --no-default-features --features="mach64 std"
	cargo build --no-default-features --features="mach32 std"
	cargo build --no-default-features --features="mach64 mach32 std"
	cargo build --no-default-features --features="pe32 std"
	cargo build --no-default-features --features="pe32 pe64 std"
	cargo build

nightly_api:
	cargo build --no-default-features --features="alloc"
	cargo build --no-default-features --features="endian_fd"
	cargo build --no-default-features --features="elf32 elf64 endian_fd"
	cargo build --no-default-features --features="archive"
	cargo build --no-default-features --features="mach64"
	cargo build --no-default-features --features="mach32"
	cargo build --no-default-features --features="mach64 mach32"
	cargo build --no-default-features --features="pe32"
	cargo build --no-default-features --features="pe32 pe64"

.PHONY: clean test example doc
