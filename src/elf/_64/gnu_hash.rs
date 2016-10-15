//! TODO add proper writeup for how this is constructed, how it resolves symbols, and how it works, see: https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
//! A Gnu Hash table as 4 sections:
//!
//!   1. Header
//!   2. Bloom Filter
//!   3. Hash Buckets
//!   4. Hash Values
//!
//! The header has is an array of four (4) u32s:
//!
//!   1. nbuckets
//!   2. symndx
//!   3. maskwords
//!   4. shift2

use core::slice;
use core::mem;
use elf::strtab;
use super::sym;

/// GNU hash function: takes a string and returns the u32 hash of that string
pub fn hash(symbol: &str) -> u32 {
    let bytes = symbol.as_bytes();
    const HASH_SEED: u32 = 5381;
    let mut hash = HASH_SEED;
    for b in bytes {
        hash = hash.wrapping_mul(32).wrapping_add(*b as u32).wrapping_add(hash);
    }
    hash
}

pub struct GnuHash<'process> {
    nbuckets: u32,
    symindex: usize,
    shift2: u32,
    maskbits: u32,
    bloomwords: &'process [usize], // either 32 or 64 bit masks, depending on platform
    maskwords_bitmask: u32,
    buckets: &'process [u32],
    hashvalues: &'process [u32],
}

impl<'process> GnuHash<'process> {
    pub fn new(hashtab: *const u32, total_dynsyms: usize) -> GnuHash<'process> {
        unsafe {
            let nbuckets = *hashtab;
            let symindex = *hashtab.offset(1) as usize;
            let maskwords = *hashtab.offset(2) as usize; // how many words our bloom filter mask has
            let shift2 = *hashtab.offset(3);
            let bloomwords_ptr = hashtab.offset(4) as *const usize;
            let buckets_ptr = bloomwords_ptr.offset(maskwords as isize) as *const u32;
            let buckets = slice::from_raw_parts(buckets_ptr, nbuckets as usize);
            let hashvalues_ptr = buckets_ptr.offset(nbuckets as isize);
            let hashvalues = slice::from_raw_parts(hashvalues_ptr, total_dynsyms - symindex);
            let bloomwords = slice::from_raw_parts(bloomwords_ptr, maskwords);
            GnuHash {
                nbuckets: nbuckets,
                symindex: symindex,
                shift2: shift2,
                maskbits: mem::size_of::<usize>() as u32,
                bloomwords: bloomwords,
                hashvalues: hashvalues,
                buckets: buckets,
                maskwords_bitmask: ((maskwords as i32) - 1) as u32,
            }
        }
    }

    #[inline(always)]
    fn lookup(&self,
              hash: u32,
              symbol: &str,
              strtab: &'process strtab::Strtab,
              symtab: &'process [sym::Sym])
              -> Option<sym::Sym> {
        let mut idx = self.buckets[(hash % self.nbuckets) as usize] as usize;
        // println!("lookup idx = buckets[hash % nbuckets] = {}", idx);
        if idx == 0 {
            return None;
        }
        let mut hash_idx = idx - self.symindex;
        let hash = hash & !1;
        // TODO: replace this with an iterator
        loop {
            let symbol_ = &symtab[idx];
            let h2 = self.hashvalues[hash_idx];
            idx += 1;
            hash_idx += 1;
            let name = &strtab[symbol_.st_name as usize];
            // println!("{}: h2 0x{:x} resolves to: {}", i, h2, name);
            if hash == (h2 & !1) && name == symbol {
                // println!("lookup match for {} at: 0x{:x}", symbol, symbol_.st_value);
                return Some(*symbol_);
            }
            if h2 & 1 == 1 {
                break;
            } // end of chain
        }
        None
    }

    #[inline(always)]
    fn filter(&self, hash: u32) -> bool {
        let bloom_idx = (hash / self.maskbits) & self.maskwords_bitmask;
        let h2 = hash >> self.shift2;
        let bitmask = (1u64 << (hash % self.maskbits)) | (1u64 << (h2 % self.maskbits));
        // println!("lookup: maskwords: {} bloom_idx: {} bitmask: {} shift2: {}", self.maskwords, bloom_idx, bitmask, self.shift2);
        let filter = self.bloomwords[bloom_idx as usize];
        filter & (bitmask as usize) != (bitmask as usize) // if true, def _don't have_
    }

    /// Given a name, a hash of that name, a strtab and corresponding symtab to look in, maybe returns a Sym
    pub fn find(&self,
                name: &str,
                hash: u32,
                strtab: &'process strtab::Strtab,
                symtab: &'process [sym::Sym])
                -> Option<sym::Sym> {
        if self.filter(hash) {
            None
        } else {
            self.lookup(hash, name, strtab, symtab)
        }
    }
}
