use std::fmt::{Display, Formatter, Result};
use ::arithmetic::mod_int::ModInt;

/// # ElGamal CipherText.
#[derive(Eq, PartialEq, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct CipherText {
    #[serde(rename = "g_r")]
    pub big_g: ModInt,
    #[serde(rename = "g_v__s")]
    pub big_h: ModInt,
    #[serde(rename = "random")]
    pub random: ModInt
}

impl Display for CipherText {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "(big_g: {}, big_h: {}, random: {})", self.big_g, self.big_h, self.random)
    }
}