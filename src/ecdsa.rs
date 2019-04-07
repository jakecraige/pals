use num_bigint::{BigInt};
use finite_field::{FieldElement};
use elliptic_curve::{Point};
use secp256k1::{Secp256k1};
use util::{hash256_bigint, bigint_to_bytes32_be};

#[derive(Debug)]
struct Sig {
    z: FieldElement, // content hash
    r: FieldElement, // rand
    s: FieldElement  // sig
}

impl Sig {
    fn new(r: FieldElement, s: FieldElement, z: FieldElement) -> Sig {
        Sig { r, s, z }
    }
}

// Distinguished Encoding Rules (DER) serialization
trait Der {
    fn as_der(&self) -> Vec<u8>;
}

// Helper function to encode a value into a marked format for der encoding
fn der_encode_value(v: &BigInt) -> Vec<u8> {
    let mut bytes = bigint_to_bytes32_be(v, false);

    // Since DER is built to work with signed numbers but we're only dealing with unsigned, we must
    // explicitly add a 0 byte if it's already set so that it considers it positive.
    // Byte is 00000000
    // 0x80 is 10000000
    // BitAnd will be 0 unless first bit is 1.
    if (bytes[0] & 0x80) > 0 {
        bytes.insert(0, 0);
    }

    let mut res = vec![0x2u8];   // marker
    res.push(bytes.len() as u8); // len of value
    res.append(&mut bytes);      // value

    res
}

impl Der for Sig {
    // marker + sig len + r (marker, length, value) + s (marker, length, value)
    fn as_der(&self) -> Vec<u8> {
        let mut r_der = der_encode_value(&self.r.value);
        let mut s_der = der_encode_value(&self.s.value);

        let mut res = vec![0x30u8];  // marker
        res.push((r_der.len() + s_der.len()) as u8);
        res.append(&mut r_der);
        res.append(&mut s_der);
        res
    }
}

struct Signer {
    curve: Secp256k1
}

impl Signer {
    fn new() -> Self {
        Signer { curve: Secp256k1::new() }
    }

    fn sign_message(&self, message: &[u8], k: &BigInt, privkey: &BigInt) -> Sig {
        let z = &hash256_bigint(message);
        self.sign(z, k, privkey)
    }

    fn sign(&self, z: &BigInt, k: &BigInt, privkey: &BigInt) -> Sig {
        let p = self.curve.mul_g(k);
        let r = &self.compute_r(&p);
        let k = &self.elem(k);
        let z = &self.elem(z);
        let privkey = &self.elem(privkey);

        // TODO: low-s value preferred by Bitcoin. Reduce S further if > subgroup order/2
        let s = k.inverse() * (z + (r * privkey));
        if s == 0 { panic!("s was 0. Choose another k.") }

        Sig { z: z.clone(), r: r.clone(), s: s.clone() }
    }

    fn verify(&self, sig: &Sig, pubkey: &Point) -> bool {
        let s_inv = &sig.s.inverse();
        let u_1 = s_inv * &sig.z;
        let u_2 = s_inv * &sig.r;
        let p = self.curve.mul_g(&u_1.value).add(&pubkey.mul(&u_2.value, &self.curve), &self.curve);
        let computed_r = self.compute_r(&p);

        sig.r == computed_r
    }

    // This whole method is gross. Ideally this can be done nicer within the type system.
    fn compute_r(&self, p: &Point) -> FieldElement {
        let xp;
        match p {
            Point::Infinity => panic!("expected a coordinate"),
            Point::Coordinate { x, y } => xp = x
        }
        let r = self.elem(&xp.value);
        if r == 0 { panic!("r was 0. Choose another k.") }

        r
    }

    fn elem(&self, n: &BigInt) -> FieldElement {
        self.curve.subgroup_field_elem(n.clone())
    }
}


#[cfg(test)]
mod tests {
    use num_traits::{Num};
    use ecdsa::*;

    #[test]
    fn ecdsa_sign_and_verify() {
        let curve = Secp256k1::new();
        let privk = BigInt::from(1);
        let pubk = curve.pubkey(&privk);
        let k = BigInt::from(20);
        let z = BigInt::from(2);

        let signer = Signer::new();
        let sig = signer.sign(&z, &k, &privk);
        assert!(signer.verify(&sig, &pubk))
    }

    #[test]
    fn ecdsa_sign_message_and_verify_examples() {
        let curve = Secp256k1::new();
        let privk = BigInt::from(12345);
        let pubk = curve.pubkey(&privk);
        let k = BigInt::from(1234567890);
        let message = b"Programming Bitcoin!";

        let signer = Signer::new();
        let sig = signer.sign_message(message, &k, &privk);

        let r_hex = sig.r.value.to_str_radix(16);
        let s_hex = sig.s.value.to_str_radix(16);
        assert_eq!(r_hex, "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22");
        assert_eq!(s_hex, "1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a");
        assert!(signer.verify(&sig, &pubk));
    }

    #[test]
    fn ecdsa_der_serialization() {
        let values = vec![
            (
                BigInt::from_str_radix("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap(),
                BigInt::from_str_radix("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap(),
                b"0E\x02 7 j\x06\x10\x99\\X\x07I\x99\xcb\x97g\xb8z\xf4\xc4\x97\x8d\xb6\x8c\x06\xe8\xe6\xe8\x1d( G\xa7\xc6\x02!\x00\x8c\xa67Y\xc1\x15~\xbe\xae\xc0\xd0<\xec\xca\x11\x9f\xc9\xa7[\xf8\xe6\xd0\xfae\xc8A\xc8\xe2s\x8c\xda\xec"
            )
        ];

        let curve = Secp256k1::new();
        for (r, s, sig_bytes) in values {
            let sig = Sig::new(curve.field_elem(r), curve.field_elem(s), curve.field_elem(1));
            assert_eq!(sig.as_der(), &sig_bytes[..]);
        }
    }
}
