use ::arithmetic::mod_int::ModInt;
use ::arithmetic::mod_int::RandModInt;
use ::arithmetic::mod_int::mod_int_to_bytes;
use ::el_gamal::ciphertext::CipherText;
use ::el_gamal::encryption::{PublicKey};
use arithmetic::mod_int::From;
use std::str::FromStr;
use num::bigint::{BigInt, Sign};
use num::{Num, Zero};
use num::traits::pow::Pow;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Neg;
use std::ops::Sub;
use std::vec::Vec;
use std::ops::Add;
use std::ptr::hash;
use sha2::{Digest, Sha512};
use ::el_gamal::serializer::Serializer;

#[derive(Eq, PartialEq, Serialize, Deserialize, Hash, Clone, Debug)]
pub struct MembershipProof {
    #[serde(rename = "s")]
    s_responses: Vec<ModInt>,
    #[serde(rename = "c")]
    c_responses: Vec<ModInt>
}

impl MembershipProof {
    pub fn new(public_key: PublicKey, plain_text: ModInt, cipher_text: CipherText, domains: Vec<ModInt>) -> MembershipProof {
        let mut s_response: Vec<ModInt> = vec![];
        let mut c_response: Vec<ModInt> = vec![];

        let mut s_for_valid = ModInt::gen_modint(public_key.q.clone());
        s_for_valid.value = BigInt::from_str_radix("16870143206178733140190693110102914592767898127", 10).unwrap();


        println!("{}", public_key.g);
        println!("{}", cipher_text);

        let mut hasher = Sha512::default();
        hasher.input(mod_int_to_bytes(&public_key.g).as_slice());
        hasher.input(mod_int_to_bytes(&public_key.h).as_slice());
        hasher.input(mod_int_to_bytes(&cipher_text.big_g).as_slice());
        hasher.input(mod_int_to_bytes(&cipher_text.big_h).as_slice());
        println!("{:?}",hasher.clone().result().as_slice());

        // let mut string_to_hash = String::new();
        // string_to_hash += &g.to_string();
        // string_to_hash += &h.to_string();
        // string_to_hash += &cipher_text.big_g.to_string();
        // string_to_hash += &cipher_text.big_h.to_string();

        let mut chosen_vote_idx = 0;
        for i in 0..domains.len() {
            println!("Loop begin");
            println!("{:?}",hasher.clone().result().as_slice());
            let a: ModInt;
            let b: ModInt;

            let domain_val: ModInt = (*domains.get(i).unwrap()).clone();

            if domain_val.eq(&plain_text) {
                // we need to add fake values
                s_response.push(ModInt::zero());
                c_response.push(ModInt::zero());

                a = public_key.g.clone().pow(s_for_valid.clone());
                b = public_key.h.clone().pow(s_for_valid.clone());
                println!("{}", a.clone());
                println!("{}", b.clone());

                chosen_vote_idx = i;
            } else {
                // add fake commitments as well as the corresponding response
                // for a value which is not the plaintext message
                let mut s = ModInt::gen_modint(public_key.q.clone());
                let mut c = ModInt::gen_modint(public_key.q.clone());
                s.value = BigInt::from_str_radix("340426178212846383764710607281056135739139464083", 10).unwrap();
                c.value = BigInt::from_str_radix("359230415343133064330408750969231566014081435744", 10).unwrap();

                s_response.push(s.clone());
                c_response.push(c.clone());

                let neg_c = c.clone().neg();
                let g_pow = public_key.g.clone().pow(domain_val.clone());

                a = public_key.g.clone().pow(s.clone()).mul(cipher_text.big_g.clone().pow(neg_c.clone()));
                b = public_key.h.clone().pow(s.clone()).mul(cipher_text.big_h.clone().div(g_pow).pow(neg_c.clone()));
                println!("{}", public_key.g.clone().pow(s.clone()));
                println!("{}", c.clone());
                println!("{}", neg_c.clone());
                println!("{}", cipher_text.big_g.clone().pow(neg_c.clone()));
                println!("{}", a.clone());
                println!("{}", b.clone());
            }

            hasher.input(mod_int_to_bytes(&a).as_slice());
            hasher.input(mod_int_to_bytes(&b).as_slice());
            println!("Loop end");
            println!("{:?}",hasher.clone().result().as_slice());
            // string_to_hash += &a.to_string();
            // string_to_hash += &b.to_string();
        }


        // let mut hex_string = String::new();
        // for byte in hasher.result().iter() {
        //     hex_string += &format!("{:02x}", byte)
        // }
        //
        // let mut c_0 = ModInt::from_hex_string(hex_string, public_key.q.value.clone());
        //
        //
        let mut c_0 = ModInt::from_value_modulus(
            BigInt::from_bytes_le(Sign::NoSign, hasher.result().as_ref()),
            public_key.q.value.clone()
        );
        println!("{}", c_0.clone());

        for fake_c in c_response.clone() {
            println!("Fake: {}", fake_c.clone());
            c_0 = c_0.sub(fake_c);
            println!("{}", c_0.clone());
        }

        s_response[chosen_vote_idx] = c_0.clone().mul(cipher_text.random.clone()).add(s_for_valid.clone());
        c_response[chosen_vote_idx] = c_0;

        MembershipProof {
            s_responses: s_response,
            c_responses: c_response
        }
    }

    pub fn verify(&self, public_key: PublicKey, cipher_text: CipherText, domain: Vec<ModInt>) -> bool {
        if domain.len() < self.c_responses.len() || domain.len() < self.s_responses.len() {
            // The domain of the message is bigger than specified.
            // Therefore, the proof that the message is within the given domain is invalid.
            panic!("Domain has not the same length as the values of the proof.")
        }

        let mut c_choices = ModInt {
            value: BigInt::zero(),
            modulus: public_key.q.value.clone(),
        };

        let mut hasher = Sha512::default();
        hasher.input(mod_int_to_bytes(&public_key.g).as_slice());
        hasher.input(mod_int_to_bytes(&public_key.h).as_slice());
        hasher.input(mod_int_to_bytes(&cipher_text.big_g).as_slice());
        hasher.input(mod_int_to_bytes(&cipher_text.big_h).as_slice());
        // let mut string_to_hash = String::new();
        // string_to_hash += &g.to_string();
        // string_to_hash += &h.to_string();
        // string_to_hash += &cipher_text.big_g.to_string();
        // string_to_hash += &cipher_text.big_h.to_string();

        for i in 0..self.c_responses.len() {
            let domain_val = domain.get(i).unwrap();
            let g_pow = public_key.g.clone().pow(domain_val.clone());

            let s: ModInt = (*self.s_responses.get(i).unwrap()).clone();
            let c: ModInt = (*self.c_responses.get(i).unwrap()).clone();
            let neg_c = c.clone().neg();

            c_choices = c_choices.add(c.clone());

            let y = public_key.g.clone().pow(s.clone()).mul(cipher_text.big_g.clone().pow(neg_c.clone()));
            let z = public_key.h.clone().pow(s.clone()).mul(cipher_text.big_h.clone().div(g_pow).pow(neg_c.clone()));

            hasher.input(mod_int_to_bytes(&y).as_slice());
            hasher.input(mod_int_to_bytes(&z).as_slice());
            // string_to_hash += &y.to_string();
            // string_to_hash += &z.to_string();
        }

        // let c_hash: String = Serializer::string_to_sha512(string_to_hash);
        // let new_c = ModInt::from_hex_string(c_hash, self.q.value.clone());
        let new_c = ModInt::from_value_modulus(
            BigInt::from_bytes_le(Sign::NoSign, hasher.result().as_ref()),
            public_key.q.value.clone()
        );

        return c_choices.eq(&new_c);
    }
}

#[cfg(test)]
mod membership_proof_test {
    use ::el_gamal::encryption::PublicKey;
    use ::el_gamal::encryption::{encrypt};
    use ::arithmetic::mod_int::ModInt;
    use arithmetic::mod_int::From;
    use ::num::bigint::BigInt;
    use ::num::Zero;
    use ::num::One;
    use ::el_gamal::membership_proof::MembershipProof;
    use std::vec::Vec;
    use std::clone::Clone;
    use num::Num;
    use el_gamal::ciphertext::CipherText;

    #[test]
    pub fn test_one_or_proof() {
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

        let message: ModInt = ModInt {
            value: BigInt::one(),
            modulus: pub_key.p.value.clone(), // must be equal to the value p of the public key
        };

        // let cipher_text = encrypt(&pub_key, message.clone());
        let cipher_text: CipherText = CipherText {
            big_g: ModInt::from_value_modulus(  BigInt::from_str_radix("114174391746769211179057064050450668223944675624", 10).unwrap(),  BigInt::from_str_radix("1449901879557492303016150949425292606294424240059", 10).unwrap()),
            big_h: ModInt::from_value_modulus(  BigInt::from_str_radix("885476757034082641428791475482165474592721569831", 10).unwrap(),  BigInt::from_str_radix("1449901879557492303016150949425292606294424240059", 10).unwrap()),
            random: ModInt::from_value_modulus( BigInt::from_str_radix("7146048211113775906570416131721832206513831805", 10).unwrap(),  BigInt::from_str_radix("724950939778746151508075474712646303147212120029", 10).unwrap())
        };

        let mut domains = Vec::new();
        domains.push(ModInt::zero());
        domains.push(ModInt::one());


        let proof = MembershipProof::new(
            pub_key.clone(),
            message,
            cipher_text.clone(),
            domains.clone(),
        );

        let is_proven = proof.verify(pub_key.clone(), cipher_text.clone(), domains.clone());

        assert!(is_proven);
    }

    #[test]
    pub fn test_zero_or_proof() {
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

        let message: ModInt = ModInt {
            value: BigInt::zero(),
            modulus: pub_key.p.value.clone(), // must be equal to the value p of the public key
        };

        let cipher_text = encrypt(&pub_key, message.clone());

        let domains = vec![ModInt::zero(), ModInt::one()];

        let proof = MembershipProof::new(
            pub_key.clone(),
            message, // <- other message than encrypted
            cipher_text.clone(),
            domains.clone(),
        );

        let is_proven = proof.verify(pub_key.clone(), cipher_text.clone(), domains.clone());

        assert!(is_proven);
    }
}
