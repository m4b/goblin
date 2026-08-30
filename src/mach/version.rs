/*-
 * Copyright: see LICENSE file
 */

use crate::mach::MachO;
use crate::mach::load_command::CommandVariant;

if_std! {
    use crate::error;
    use crate::mach::{Mach, SingleArch};
    use crate::mach::cputype::CpuType;
    use std::cmp::Ordering;
    use std::collections::{VecDeque,HashMap};
    use std::str::FromStr;
    use std::fmt;
}

#[derive(Eq, Debug)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl From<u32> for Version {
    fn from(packed: u32) -> Self {
        // X.Y.Z is encoded in nibbles xxxx.yy.zz
        // 12.6 = 0b0000_0000_0000_1100_0000_0110_0000_0000
        Self {
            major: (packed & 0b1111_1111_1111_1111_0000_0000_0000_0000u32) >> 16,
            minor: (packed & 0b0000_0000_0000_0000_1111_1111_0000_0000u32) >> 8,
            patch: (packed & 0b0000_0000_0000_0000_0000_0000_1111_1111u32) >> 0,
        }
    }
}

impl MachO<'_> {
    pub fn version(&self) -> Option<Version> {
        self.load_commands
            .iter()
            .find_map(|c| match c.command {
                CommandVariant::VersionMinMacosx(v) => Some(v.version),
                CommandVariant::BuildVersion(v) => Some(v.minos),
                _ => None,
            })
            .map(Version::from)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major && self.minor == other.minor && self.patch == other.patch
    }
}

if_std! {
    impl fmt::Display for Version {
        // This trait requires `fmt` with this exact signature.
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // Write strictly the first element into the supplied output
            // stream: `f`. Returns `fmt::Result` which indicates whether the
            // operation succeeded or failed. Note that `write!` uses syntax which
            // is very similar to `println!`.
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }

    impl Ord for Version {
        fn cmp(&self, other: &Self) -> Ordering {
            let mao = self.major.cmp(&other.major);
            let mio = self.minor.cmp(&other.minor);
            let pao = self.patch.cmp(&other.patch);
            if mao == Ordering::Equal && mio == Ordering::Equal {
                pao
            } else if mao == Ordering::Equal {
                mio
            } else {
                mao
            }
        }
    }

    impl PartialOrd for Version {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl FromStr for Version {
        type Err = error::Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut parts = s
            .trim()
            .split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .take(3)
            .collect::<VecDeque<u32>>();

            if parts.front().is_some_and(|major| *major > 0) {
                Ok(Self {
                    major: parts.pop_front().unwrap(), // existance checked in conditional
                    minor: parts.pop_front().unwrap_or(0),
                    patch: parts.pop_front().unwrap_or(0),
                })
            } else {
                Err(error::Error::Malformed("Missing major version from target version, version string should look like: X.Y.Z".to_string()))
            }
        }
    }

    impl TryFrom<Mach<'_>> for Vec<Version> {
        type Error = error::Error;

        fn try_from(b: Mach) -> Result<Self, error::Error> {
            match b {
                Mach::Binary(b) => b.version().ok_or(error::Error::Malformed("Binary has no version".to_string())).map(|v|vec![v]),
                Mach::Fat(f) => f.into_iter().map(|r| r.map(|s| match s {
                    SingleArch::MachO(b) => b.version().ok_or_else(||error::Error::Malformed("Missing or corrupted version".to_string())),
                    SingleArch::Archive(_) => Err(error::Error::Malformed("lib is an archive?".to_string())),
                }).and_then(std::convert::identity)).collect(),
            }
        }
    }

    impl Mach<'_> {
        pub fn versions(self) -> HashMap<CpuType, Version> {
            let mut hash = HashMap::new();
            match self {
                Mach::Binary(b) => {
                    if let Some(v) = b.version() {
                        hash.insert(b.header.cputype, v);
                    }
                },
                Mach::Fat(f) => {
                    for r in f.into_iter() {
                        if let Ok(SingleArch::MachO(b)) = r {
                            if let Some(v) = b.version() {
                                hash.insert(b.header.cputype, v);
                            }
                        }
                    }
                },
            };
            hash
        }
    }
}
