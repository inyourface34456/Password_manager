#![allow(unused)]
use rand_core::OsRng;
use rand_core::RngCore;

pub struct PwGen {
    alpha_upper: bool,
    alpha_lower: bool,
    numaric: bool,
    symbols: bool,
    misc_nonprintable: bool,
    utf8_printable: bool,
}

impl Default for PwGen {
    fn default() -> Self {
        Self {
            alpha_upper: true,
            alpha_lower: true,
            numaric: true,
            symbols: true,
            misc_nonprintable: false,
            utf8_printable: false,
        }
    }
}

impl PwGen  {
    pub fn new(
        alpha_upper: bool,
        alpha_lower: bool,
        numaric: bool,
        symbols: bool,
        misc_nonprintable: bool,
        utf8_printable: bool
    ) -> Self {
        Self {
            alpha_upper,
            alpha_lower,
            numaric,
            symbols,
            misc_nonprintable,
            utf8_printable,
        }
    }

    fn to_charset(&self) -> Vec<char> {
        let mut base_set: Vec<char> = Vec::new();

        if self.alpha_upper {
            base_set.append(&mut Self::ALPHA_UPPER.to_vec().clone());
        }
        if self.alpha_lower {
            base_set.append(&mut Self::ALPHA_LOWER.to_vec().clone());
        }
        if self.numaric {
            base_set.append(&mut Self::NUMARIC.to_vec().clone());
        }
        if self.symbols {
            base_set.append(&mut Self::SYMBOLS.to_vec().clone());
        }
        if self.misc_nonprintable {
            base_set.append(&mut Self::MISC_NONTYPEABLE.to_vec().clone());
        }
        if self.utf8_printable {
            base_set.append(&mut Self::UTF8_PRINTABLE.to_vec().clone());
        }

        base_set
    }

    pub fn gen_rand_pw(&self, len: usize) -> String {
       let charset = self.to_charset();
       let mut res: Vec<char> = Vec::new();

       for _ in 0..len {
           let idx: usize = OsRng.next_u64().try_into().unwrap();
           let chr = charset[idx%charset.len()];
           res.push(chr);
       }

       res.iter().collect()
    }
}
