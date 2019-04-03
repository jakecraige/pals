use num_bigint::{BigInt};
use finite_field::{FieldElement};
use elliptic_curve::{Point};
use secp256k1::{Secp256k1};
use util::{hash256_bigint};

#[derive(Debug)]
struct Sig {
    z: FieldElement, // content hash
    r: FieldElement, // rand
    s: FieldElement  // sig
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
        let p = self.curve.add(&self.curve.mul_g(&u_1.value), &self.curve.mul(pubkey, &u_2.value));
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
}
