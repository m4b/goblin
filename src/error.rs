use scroll;
use core::result;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: ::std::io::Error) {
            from()
        }
        #[cfg(feature = "endian_fd")]
        Scroll(err: scroll::Error) {
            from()
        }
        BadMagic(magic: u64) {
            description("Invalid magic number")
                display("Invalid magic number: 0x{:x}", magic)
        }
        Malformed(msg: String) {
            description("Entity is malformed in some way")
                display("Malformed entity: {}", msg)
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
