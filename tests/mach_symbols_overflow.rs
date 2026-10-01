use goblin::Object;
/// Regression test for the 32-bit overflow in `SymbolIterator`.
///
/// Reported as part of #542: with the 89-byte PoC from that issue,
/// `LC_SYMTAB.stroff` is 0xFFFFFFFF and the first `n_strx` reads 0xFEEDFACE
/// straight out of the file header. Adding them gives 8571976397, which fits
/// in a 64-bit `usize` but overflows a 32-bit one, so `symbols()` panicked
/// with:
///
///     thread 'main' panicked at src/mach/symbols.rs:378:
///     attempt to add with overflow
///
/// That is why it is invisible on x86_64 and reproducible on
/// i686-pc-windows-msvc, which goblin builds in CI.
///
/// Valid input is covered by the existing `iter_symbols` test in
/// tests/macho.rs, which walks `symbols()` over a well-formed Mach-O; this
/// file only adds the malformed case.
///
/// `catch_unwind` turns the 32-bit panic into a test failure instead of
/// aborting the run, so the same test is meaningful on both architectures.
use goblin::mach::Mach;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Byte-for-byte the input from #542.
const POC_SYMBOLS_89: [u8; 89] = [
    0xfe, 0xed, 0xfa, 0xce, 0x64, 0xd0, 0x33, 0x02, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x80, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdb, 0x00, 0x08,
];

#[test]
fn symbol_string_offset_overflow_is_reported_not_panicked() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let parsed = Object::parse(&POC_SYMBOLS_89[..]);
        let mach = match parsed {
            Ok(Object::Mach(Mach::Binary(ref m))) => m,
            Ok(_) => panic!("PoC should parse as a single Mach-O"),
            Err(_) => panic!("PoC should parse at all"),
        };

        // The iterator must surface an error rather than panic. Only the first
        // few items matter: the point is that reaching them is safe.
        let mut saw_error = false;
        for item in mach.symbols() {
            if item.is_err() {
                saw_error = true;
                break;
            }
        }
        saw_error
    }));

    match outcome {
        Ok(true) => {}
        Ok(false) => panic!(
            "symbols() neither returned an error nor stopped: the malformed \
             string offset was accepted"
        ),
        Err(_) => panic!("symbols() panicked on crafted input (32-bit overflow)"),
    }
}
