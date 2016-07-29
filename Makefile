ELF32 = $(wildcard src/elf32/*.rs)
ELF = $(wildcard src/elf/*.rs)
MACH = $(wildcard src/mach/*.rs)
PE = $(wildcard src/pe/*.rs)
SRC = $(wildcard src/*.rs) $(ELF) $(ELF32) $(MACH) $(PE)

ARTIFACTS = $(addprefix target/debug/, libgoblin.rlib libgoblin.so)

$(ARTIFACTS): $(SRC)
	cargo build

clean:
	cargo clean

test:
	RUST_BACKTRACE=1 cargo test

example:
	cargo run --example=rdr -- /bin/ls

.PHONY: clean test
