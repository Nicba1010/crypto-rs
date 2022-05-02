use std::fmt::{Display, Formatter, Result};
use ::arithmetic::mod_int::ModInt;

/// # ElGamal CipherText.
#[derive(Eq, PartialEq, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct CipherText {
    pub big_g: ModInt,
    pub big_h: ModInt,
    pub random: ModInt
}

impl Display for CipherText {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "(big_g: {}, big_h: {}, random: {})", self.big_g, self.big_h, self.random)
    }
}