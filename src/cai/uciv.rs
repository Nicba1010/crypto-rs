use std::vec::Vec;
use num::pow::Pow;
use num::Zero;

use std::ops::{Mul, Div, Sub, Add, Neg};

use ::arithmetic::mod_int::From;
use ::arithmetic::mod_int::RandModInt;
use ::arithmetic::mod_int::ModInt;
use ::el_gamal::encryption::PublicKey;
use ::el_gamal::ciphertext::CipherText;
use ::el_gamal::serializer::Serializer;

/// Secret UCIV Information `(x1, x2, ..., xn)`.
/// This information is specific to a particular voter.
/// Each `xn` is further tight to the n-th voting option.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreImageSet {
    pub pre_images: Vec<ModInt>
}

/// Public UCIV Information `(y1, y2, ..., yn)`.
/// This information is specific to a particular voter.
/// Each `yn` is further tight to the n-th voting option.
#[derive(Clone, Serialize, Deserialize)]
pub struct ImageSet {
    pub images: Vec<ModInt>
}

impl ImageSet {
    /// Creates an ImageSet `(y1, y2, ..., yn)` by applying the following
    /// arithmetic operation to each element of the given PreImageSet `(x1, x2, ..., xn)`:
    ///
    /// ```markdown
    /// (y1, y2, ..., yn) = ( F(x1), F(x2), ..., F(xn) )
    ///
    /// (y1, y2, ..., yn) = ( generator^x1, generator^x2, ..., generator^xn)
    /// ```
    ///
    /// - generator: The generator of the cyclic group used also during encryption of the vote
    /// - pre_image_set: A number of pre-images equal to the number of voting options available
    ///                  which are specific to a particular voter.
    ///
    pub fn new(generator: ModInt, pre_image_set: PreImageSet) -> Self {
        let mut vec = vec![];

        // apply g^x as one-way function
        for pre_image in pre_image_set.pre_images.iter() {
            // If modulus is not equal, then we will end up with a different one after the exponentiation
            // TODO: check this
            //assert_eq!(pre_image.modulus.clone(), generator.modulus.clone(), "Modulus of pre-image and generator must be equal");

            vec.push(generator.clone().pow(pre_image.clone()));
        }

        ImageSet {
            images: vec
        }
    }
}

/// Cast-as-Intended proof
#[derive(Eq, PartialEq, Debug, Clone, Hash, Serialize, Deserialize)]
pub struct CaiProof {
    s1_options: Vec<ModInt>,
    s2_options: Vec<ModInt>,
    h1_options: Vec<ModInt>,
    h2_options: Vec<ModInt>,

    h: ModInt
}

impl CaiProof {

    /// Create a new Cast-as-Intended Proof.
    ///
    /// - public_key: The public key of the election system
    /// - cipher_text: The cipher text for which to create the proof
    /// - pre_image_set: The voter and voting option dependent secret set of pre-images
    /// - image_set: The voter and voting option dependent public set of images
    /// - chosen_vote_idx: The index of the chosen vote within the set of available voting options
    /// - voting_options: The set of available voting options
    ///
    /// # Panics
    ///
    /// Panics if the amount of pre-images, images and available voting options are not equal.
    /// In addition, panics if the chosen vote index is out-of-bound of the available set of
    /// voting options.
    pub fn new(public_key: PublicKey, cipher_text: CipherText, pre_image_set: PreImageSet, image_set: ImageSet, chosen_vote_idx: usize, voting_options: Vec<ModInt>) -> Self {
        assert_eq!(pre_image_set.pre_images.len(), image_set.images.len(), "The amount of pre-images and images must be equal");
        assert_eq!(pre_image_set.pre_images.len(), voting_options.len(), "The amount of pre-images must be equal to the amount of voting options");
        assert!(chosen_vote_idx < pre_image_set.pre_images.len(), "The chosen vote index must refer to a voting option for which a pre-image exists");

        // initialize vector with the amount of pre_images which are
        // equal to the number of voting options
        let mut s1_options: Vec<ModInt> = vec![ModInt::zero(); pre_image_set.pre_images.len()];
        let mut s2_options: Vec<ModInt> = vec![ModInt::zero(); pre_image_set.pre_images.len()];
        let mut h1_options: Vec<ModInt> = vec![ModInt::zero(); pre_image_set.pre_images.len()];
        let mut h2_options: Vec<ModInt> = vec![ModInt::zero(); pre_image_set.pre_images.len()];

        let mut z_options: Vec<ModInt> = vec![ModInt::zero(); pre_image_set.pre_images.len()];

        let mut string_to_hash = String::new();
        string_to_hash += &cipher_text.big_g.to_string();
        string_to_hash += &cipher_text.big_h.to_string();

        // TODO: add c3, c4

        for i in 0..pre_image_set.pre_images.len() {
            // generate random values
            let r1_i = ModInt::gen_modint(public_key.q.clone());
            let r2_i = ModInt::gen_modint(public_key.q.clone());
            let r3_i = ModInt::gen_modint(public_key.q.clone());
            z_options[i] = r3_i.clone();

            if i != chosen_vote_idx {
                // case 1: all not-chosen options
                s1_options[i] = r1_i.clone();
                h1_options[i] = r2_i.clone();

                // the specific values for each voting options
                let c1_i = public_key.g.clone().pow(r1_i.clone()).mul(cipher_text.big_g.clone().pow(r2_i.clone().neg()));
                let c2_i = public_key.h.clone().pow(r1_i.clone()).mul((cipher_text.big_h.clone().div(public_key.g.clone().pow(voting_options[i].clone()))).pow(r2_i.clone().neg()));

                let r_i = public_key.g.clone().pow(r3_i.clone());

                string_to_hash += &c1_i.to_string();
                string_to_hash += &c2_i.to_string();
                string_to_hash += &r_i.to_string();
            } else {
                // case 2: the chosen option
                s2_options[i] = r1_i.clone();
                h2_options[i] = r2_i.clone();

                let c1_j = public_key.g.clone().pow(r3_i.clone());
                let c2_j = public_key.h.clone().pow(r3_i.clone());

                let r_j = public_key.g.clone().pow(r1_i).mul(image_set.images[i].clone().pow(r2_i.clone().neg()));

                string_to_hash += &c1_j.to_string();
                string_to_hash += &c2_j.to_string();
                string_to_hash += &r_j.to_string();
            }
        }

        let h_hash = Serializer::string_to_sha512(string_to_hash);
        let s = ModInt::from_hex_string(h_hash, public_key.q.value.clone());

        for i in 0..pre_image_set.pre_images.len() {
            if i != chosen_vote_idx {
                // case 1: all not-chosen options

                let r1_i = s.clone().sub(h1_options[i].clone());
                h2_options[i] = r1_i.clone();

                let r2_i = z_options[i].clone().add(pre_image_set.pre_images[i].clone().mul(r1_i.clone()));
                s2_options[i] = r2_i;

            } else {
                // case 2: the chosen option
                let r1_i = s.clone().sub(h2_options[i].clone());
                let r2_i = z_options[i].clone().add(cipher_text.random.clone().mul(r1_i.clone()));

                h1_options[i] = r1_i.clone();
                s1_options[i] = r2_i.clone();
            }
        }

        CaiProof {
            s1_options,
            s2_options,
            h1_options,
            h2_options,
            h: s
        }
    }

    /// Verify this proof for validity.
    ///
    /// - public_key: The public key of the election system
    /// - cipher_text: The cipher text for which to create the proof
    /// - image_set: The voter and voting option dependent public set of images
    /// - voting_options: The set of available voting options
    pub fn verify(&self, public_key: PublicKey, cipher_text: CipherText, image_set: ImageSet, voting_options: Vec<ModInt>) -> bool {
        let c1 = cipher_text.big_g;
        let c2 = cipher_text.big_h;

        let mut string_to_hash = String::new();
        string_to_hash += &c1.to_string();
        string_to_hash += &c2.to_string();
        // TODO: c3, c4

        // reconstruct h
        for i in 0..self.s1_options.len() {
            let c1_i = public_key.g.clone().pow(self.s1_options[i].clone()).mul(c1.clone().pow(self.h1_options[i].clone().neg()));
            let c2_i = public_key.h.clone().pow(self.s1_options[i].clone()).mul((c2.clone().div(public_key.g.clone().pow(voting_options[i].clone()))).pow(self.h1_options[i].clone().neg()));
            let r_i = public_key.g.clone().pow(self.s2_options[i].clone()).mul(image_set.images[i].clone().pow(self.h2_options[i].clone().neg()));

            string_to_hash += &c1_i.to_string();
            string_to_hash += &c2_i.to_string();
            string_to_hash += &r_i.to_string();
        }

        let h_hash = Serializer::string_to_sha512(string_to_hash);
        let h = ModInt::from_hex_string(h_hash, public_key.q.value.clone());



        self.h == h
    }
}



#[cfg(test)]
mod uciv_proof_test {

    use ::el_gamal::encryption::PublicKey;
    use ::el_gamal::encryption::{encrypt};
    use ::el_gamal::ciphertext::CipherText;
    use ::arithmetic::mod_int::ModInt;
    use arithmetic::mod_int::{From, RandModInt};
    use ::num::bigint::BigInt;
    use ::num::Zero;
    use ::num::One;
    use std::clone::Clone;
    use num::Num;
    use ::cai::uciv::{CaiProof, ImageSet, PreImageSet};

    #[test]
    pub fn test_valid_proof() {
        //h := (g^x) mod p
        //2 := 2^5 mod 5
        let x = BigInt::from_str_radix("896771263533775491364511200158444196377569745583", 10).unwrap();
        //h := (g^x) mod p
        let h = BigInt::from_str_radix("216354726151927782480677585315485875691753344522", 10).unwrap();
        let g = BigInt::from_str_radix("650614565471833138727952492078522919745801716191", 10).unwrap();
        let p = BigInt::from_str_radix("1449901879557492303016150949425292606294424240059", 10).unwrap();
        let q = (p.clone() - BigInt::one()) / BigInt::from_str_radix("2", 10).unwrap();

        let pub_key = PublicKey {
            p: ModInt::from_value_modulus(p.clone(), BigInt::zero()),
            q: ModInt::from_value_modulus(q.clone(), BigInt::zero()),
            h: ModInt::from_value_modulus(h.clone(), p.clone()),
            g: ModInt::from_value_modulus(g.clone(), p.clone()),
        };

        let mut voting_options = vec![ModInt::zero(), ModInt::one()];

        let message: ModInt = ModInt {
            value: BigInt::one(),
            modulus: pub_key.p.value.clone() // must be equal to the value p of the public key
        };
        let cipher_text = encrypt(&pub_key, message.clone());
        let chosen_vote_idx = 1;

        let pre_image_set = PreImageSet {
            pre_images: vec![
                ModInt::gen_modint(pub_key.q.clone()),
                ModInt::gen_modint(pub_key.q.clone())
            ]
        };

        let image_set = ImageSet::new(pub_key.g.clone(), pre_image_set.clone());

        let proof = CaiProof::new(
            pub_key.clone(),
            cipher_text.clone(),
            pre_image_set.clone(),
            image_set.clone(),
            chosen_vote_idx,
            voting_options.clone()
        );

        let is_proven = proof.verify(
            pub_key.clone(),
            cipher_text.clone(),
            image_set.clone(),
            voting_options.clone()
        );

        assert!(is_proven);
    }

    #[test]
    pub fn test_invalid_proof() {
        //h := (g^x) mod p
        //2 := 2^5 mod 5
        let x = BigInt::from_str_radix("896771263533775491364511200158444196377569745583", 10).unwrap();
        //h := (g^x) mod p
        let h = BigInt::from_str_radix("216354726151927782480677585315485875691753344522", 10).unwrap();
        let g = BigInt::from_str_radix("650614565471833138727952492078522919745801716191", 10).unwrap();
        let p = BigInt::from_str_radix("1449901879557492303016150949425292606294424240059", 10).unwrap();
        let q = (p.clone() - BigInt::one()) / BigInt::from_str_radix("2", 10).unwrap();

        let pub_key = PublicKey {
            p: ModInt::from_value_modulus(p.clone(), BigInt::zero()),
            q: ModInt::from_value_modulus(q.clone(), BigInt::zero()),
            h: ModInt::from_value_modulus(h.clone(), p.clone()),
            g: ModInt::from_value_modulus(g.clone(), p.clone()),
        };

        let mut voting_options = vec![ModInt::zero(), ModInt::one()];

        let message: ModInt = ModInt {
            value: BigInt::one(),
            modulus: pub_key.p.value.clone() // must be equal to the value p of the public key
        };

        let cipher_text = encrypt(&pub_key, message.clone());
        let chosen_vote_idx = 1;

        let pre_image_set = PreImageSet {
            pre_images: vec![
                ModInt::gen_modint(pub_key.q.clone()),
                ModInt::gen_modint(pub_key.q.clone())
            ]
        };

        let image_set = ImageSet::new(pub_key.g.clone(), pre_image_set.clone());

        let proof = CaiProof::new(
            pub_key.clone(),
            cipher_text.clone(),
            pre_image_set.clone(),
            image_set.clone(),
            chosen_vote_idx,
            voting_options.clone()
        );

        let fake_cipher_text = CipherText {
            big_g: ModInt::from_value_modulus(BigInt::from(1), pub_key.p.value.clone()),
            big_h: ModInt::from_value_modulus(BigInt::from(2), pub_key.p.value.clone()),
            random: ModInt::from_value_modulus(BigInt::from(3), pub_key.p.value.clone())
        };

        let is_proven = proof.verify(
            pub_key.clone(),
            fake_cipher_text.clone(),
            image_set.clone(),
            voting_options.clone()
        );

        assert!(!is_proven);
    }
}