ELF32 = $(wildcard src/elves/_32/*.rs)
ELF = $(wildcard src/elves/*.rs)
ELF64 = $(wildcard src/elves/_64/*.rs)
MACH = $(wildcard src/mach/*.rs)
PE = $(wildcard src/pe/*.rs)
SRC = $(wildcard src/*.rs) $(ELF) $(ELF64) $(ELF32) $(MACH) $(PE)

ARTIFACTS = $(addprefix target/debug/, libgoblin.rlib libgoblin.so)

$(ARTIFACTS): $(SRC)
#	cargo rustc -- -Z orbit=on -Z incremental=1 -C lto
	cargo build

clean:
	cargo clean

test:
	RUST_BACKTRACE=1 cargo test

example:
	cargo run --example=rdr -- /bin/ls

.PHONY: clean test
