use secp256k1::{Secp256k1, Point, Field, FieldElement};
use num_bigint::{BigInt};

struct Signer {
    curve: Secp256k1,
    field: Field
}

#[derive(Debug)]
struct Sig {
    z: FieldElement, // content hash
    r: FieldElement, // rand
    s: FieldElement  // sig
}

impl Signer {
    fn new() -> Self {
        Signer {
            curve: Secp256k1::new(),
            field: Field::new(Secp256k1::order())
        }
    }

    fn sign(&self, z: &BigInt, k: &BigInt, privkey: &BigInt) -> Sig {
        let p = self.curve.mul_g(k);
        let r = &self.compute_r(&p);
        let k = &self.elem(k);
        let z = &self.elem(z);
        let privkey = &self.elem(privkey);

        // TODO: low-s value preferred by Bitcoin. Reduce S further
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
        self.field.elem(n.clone())
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
}
