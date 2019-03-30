use secp256k1::{Secp256k1, Point};
use num_bigint::{BigInt, RandBigInt};
use rand::{thread_rng};
use num_traits::*;

// Secp256k1 with g + h where h is hash of string "Provisions"
struct ProvisionsCurve {
    curve: Secp256k1,
    h: Point
}

impl ProvisionsCurve {
    fn new() -> Self {
        let provisions_sha256 = BigInt::from_str_radix(
            "7982ad72bd36e6f2a1b65cc0f14a1610c7822a6d1efff818ab95a3ba1793847f",
            16
        ).unwrap();

        let curve = Secp256k1::new();
        // TODO: This breaks the ZK-ness of the proof. Will need to later look up how to actually
        // derive a point from this in a secure way.
        let h = curve.mul_g(&provisions_sha256);

        ProvisionsCurve { curve, h }
    }

    pub fn mul(&self, p: &Point, n: &BigInt) -> Point {
        self.curve.mul(p, n)
    }

    pub fn mul_g(&self, n: &BigInt) -> Point {
        self.curve.mul_g(n)
    }

    pub fn mul_h(&self, n: &BigInt) -> Point {
        self.curve.mul(&self.h, n)
    }

    pub fn add(&self, p: &Point, q: &Point) -> Point {
        self.curve.add(p, q)
    }
}

// Generate a random number in Z_q for Secp256k1
fn gen_rand() -> BigInt {
    let mut rng = thread_rng();
    // NOTE: To speed up test runs, you can use a smaller value like the example below:
    //       rng.gen_bigint_range(&BigInt::zero(), &BigInt::from(100))
    rng.gen_bigint_range(&BigInt::zero(), &Secp256k1::p())
}

#[derive(Clone)]
struct PublicKey {
    private_key: Option<BigInt>,
    public_key: Point,
    balance: BigInt
}

impl PublicKey {
    fn new_from_privkey(private_key: BigInt, curve: &ProvisionsCurve, balance: BigInt) -> Self {
        PublicKey {
            public_key: curve.mul_g(&private_key),
            private_key: Some(private_key),
            balance
        }
    }

    fn new(private_key: Option<BigInt>, balance: BigInt) -> Self {
        PublicKey {
            private_key,
            public_key: Point::Infinity, // TODO: This is very wrong :)
            balance
        }
    }

    // Convenience method to match naming to paper
    fn y(&self) -> Point {
        self.public_key.clone()
    }

    fn s(&self) -> BigInt {
        self.private_key.clone().map_or(BigInt::zero(), |_| BigInt::one())
    }

    fn b(&self, curve: &ProvisionsCurve) -> Point {
        // b = g^(bal)
        curve.mul_g(&self.balance)
    }

    // Generate a pedersen commitment (c = g^m * h^r) to the balance
    // For provisions: p = b^s * h^v, where v is random
    fn commitment(&self, curve: &ProvisionsCurve) -> (Point, BigInt) {
        let v = gen_rand();
        self.commitment_with_v(curve, v)
    }

    // Just a helper for testing to create the commitment with a specific value
    fn commitment_with_v(&self, curve: &ProvisionsCurve, v: BigInt) -> (Point, BigInt) {
        // p = b^s * h^v
        let b_s = curve.mul(&self.b(&curve), &self.s());
        let h_v = curve.mul_h(&v);
        let p = curve.add(&b_s, &h_v);

        (p, v)
    }

    fn x_hat(&self) -> BigInt {
        self.private_key.clone().map_or(BigInt::zero(), |privk| privk)
    }

    // Generate a pedersen commitment to prove private key ownership:
    //     l = y^s * h^t = g^x*s * h^t, where t is random
    // Reason: y^s = g^x*s
    //     when s=0, y^0=0, g^0=0
    //     when s=1, y^1=y, g^x*1=g^x=y
    fn l(&self, curve: &ProvisionsCurve) -> (Point, BigInt) {
        let x_hat = self.x_hat();
        let t = gen_rand();
        // g^x_s * h^t
        (curve.add(&curve.mul_g(&x_hat), &curve.mul_h(&t)), t)
    }
}

// Representation of the proof that the prover needs as part of the interactive protocol of
// verifying it.
#[derive(Clone)]
struct ProverPublicKeyProof {
    y: Point,
    b: Point,

    p: Point,
    v: BigInt,

    l: Point,
    t: BigInt,

    s: BigInt,
    x_hat: BigInt
}

// Representation of the proof that the verifier has from the prover publisishing it. Basically,
// this excludes blinding factors and the private keys.
#[derive(Clone)]
struct VerifierPublicKeyProof {
    y: Point,
    b: Point,
    p: Point,
    l: Point,
}

// Public data:
//     (y, b) for i..n and g, h
// Prover input:
//     s in 0..1 and (v, t, x_hat) for i..n
// Verifier input:
//     (p, l) for i..n
struct ProofOfAssets {
    curve: ProvisionsCurve,
    pks: Vec<PublicKey>
}

impl ProofOfAssets {
    fn new() -> Self {
        ProofOfAssets {
            curve: ProvisionsCurve::new(),
            pks: vec![]
        }
    }
}

impl ProofOfAssets {
    fn gen_pk_proof(&self, pk: &PublicKey) -> (ProverPublicKeyProof, VerifierPublicKeyProof) {
        let y = pk.y();
        let b = pk.b(&self.curve);
        let (p, v) = pk.commitment(&self.curve);
        let (l, t) = pk.l(&self.curve);
        let s = pk.s();
        let x_hat = pk.x_hat();

        let verifier = VerifierPublicKeyProof { 
            y: y.clone(),
            b: b.clone(),
            p: p.clone(),
            l: l.clone()
        };
        let prover = ProverPublicKeyProof { y, b, p, v, l, t, s, x_hat };

        (prover, verifier)
    }

    // Ineractive algorithm for verifying the proof validity for a particular public key.
    //
    // a) Prover chooses random u_i for i..4
    // b) Prover computes a for i..3 and sends to Verifier
    //     a_1 = b^u_1 * h^u_2
    //     a_2 = y^u_1 * h^u_3
    //     a_3 = g^u_4 * h^u_3
    // c) Verifier replies with challenge c
    // d) Prover replies with:
    //     r_s     = u_1 + c * s
    //     r_v     = u_2 + c * v
    //     r_t     = u_3 + c * t
    //     r_x_hat = u_4 + c * x_hat
    // e) Verifier accepts if:
    //     b^r_s     * h^r_v = p^c * a_1
    //     y^r_s     * h^r_t = l^c * a_2
    //     g^r_x_hat * h^r_t = l^c * a_3
    fn verify_pk_proof(&self, prover_proof: &ProverPublicKeyProof, verifier_proof: &VerifierPublicKeyProof) -> Result<(), &str> {
        let curve = &self.curve;

        // Prover
        let (u_1, u_2, u_3, u_4) = (gen_rand(), gen_rand(), gen_rand(), gen_rand());

        let (a_1, a_2, a_3) = (
            // a_1 = b^u_1 * h^u_2
            curve.add(&curve.mul(&prover_proof.b, &u_1), &curve.mul_h(&u_2)),
            // a_2 = y^u_1 * h^u_3
            curve.add(&curve.mul(&prover_proof.y, &u_1), &curve.mul_h(&u_3)),
            // a_3 = g^u_4 * h^u_3
            curve.add(&curve.mul_g(&u_4), &curve.mul_h(&u_3))
        );

        // Verifier
        let c = gen_rand();

        // Prover
        let (r_s, r_v, r_t, r_x_hat) = (
            u_1 + (&c * &prover_proof.s),
            u_2 + (&c * &prover_proof.v),
            u_3 + (&c * &prover_proof.t),
            u_4 + (&c * &prover_proof.x_hat)
        );

        // Verifier acceptance
        let (bh, pa1) = (
            // b^r_s * h^r_v
            curve.add(&curve.mul(&verifier_proof.b, &r_s), &curve.mul_h(&r_v)),
            // p^c * a_1
            curve.add(&curve.mul(&verifier_proof.p, &c), &a_1)
        );
        let (yh, la2) = (
            // y^r_s * h^r_t
            curve.add(&curve.mul(&verifier_proof.y, &r_s), &curve.mul_h(&r_t)),
            // l^c * a_2
            curve.add(&curve.mul(&verifier_proof.l, &c), &a_2)
        );
        let (gh, la3) = (
            // g^r_x_hat * h^r_t
            curve.add(&curve.mul_g(&r_x_hat), &curve.mul_h(&r_t)),
            // l^c * a_3
            curve.add(&curve.mul(&verifier_proof.l, &c), &a_3)
        );

        let p1 = bh == pa1;
        let p2 = yh == la2;
        let p3 = gh == la3;
        println!("p1: {}, p2: {}, p3: {}", p1, p2, p3);

        if p1 {
            if p2 {
                if p3 {
                    Ok(())
                } else {
                    Err("Unable to verify proof part 3")
                }
            }  else {
                Err("Unable to verify proof part 2")
            }
        } else {
            Err("Unable to verify proof part 1")
        }
    }

    // PK: The set of public keys that we generate the proof from. If we own the address the
    // optional private_key on the struct should be set.
    //
    // Returns a tuple (z_assets, vec(p, v))
    fn generate_z_assets(&self, pks: &[PublicKey]) -> (Point, Vec<(Point, BigInt)>) {
        // 1. Generate b for all keys g*bal(y) (Assets = sum(s * bal(y)))
        // 2. Generate commitments p=b^s * h^v where v is random value
        // 3. Z_assets commitment = product(p) or g^Assets * h^(sum(v))
        let mut out = Point::Infinity;
        let mut commitments: Vec<(Point, BigInt)> = vec![];

        for p in pks.iter() {
            let (p, v) = p.commitment(&self.curve);
            out = self.curve.add(&out, &p);
            commitments.push((p, v));
        }

        (out, commitments)
    }
}


#[cfg(test)]
mod tests {
    use provisions::proof_of_assets::*;

    #[test]
    fn poa_public_key_b() {
        let curve = ProvisionsCurve::new();
        let pk = PublicKey::new(Some(BigInt::from(5)), BigInt::one());
        assert_eq!(pk.b(&curve), curve.mul_g(&BigInt::one()));

        let pk = PublicKey::new(None, BigInt::one());
        assert_eq!(pk.b(&curve), curve.mul_g(&BigInt::one()));
    }

    #[test]
    fn poa_public_key_commitment() {
        let curve = ProvisionsCurve::new();
        let pk = PublicKey::new(Some(BigInt::from(5)), BigInt::one());

        let (p, v) = pk.commitment(&curve);

        let b_s = curve.mul(&pk.b(&curve), &pk.s());
        let h_v = curve.mul_h(&v);
        let p_prime = curve.add(&b_s, &h_v);
        assert_eq!(p, p_prime);
    }

    #[test]
    fn poa_z_assets() {
        let curve = ProvisionsCurve::new();
        let pk1 = PublicKey::new(Some(BigInt::from(5)), BigInt::one());
        let pk2 = PublicKey::new(None, BigInt::one());
        let poa = ProofOfAssets::new();

        let (z_assets, mut commitments) = poa.generate_z_assets(&[pk1.clone(), pk2.clone()]);

        let v2 = commitments.pop().unwrap().1;
        let v1 = commitments.pop().unwrap().1;
        let (pk1_p, _) = pk1.commitment_with_v(&curve, v1);
        let (pk2_p, _) = pk2.commitment_with_v(&curve, v2);
        let expected = curve.add(&pk1_p, &pk2_p);
        assert_eq!(z_assets, expected);
    }

    #[test]
    fn poa_public_key_proof() {
        let poa = ProofOfAssets::new();
        let pk = PublicKey::new_from_privkey(BigInt::from(2), &poa.curve, BigInt::from(2));

        let (prover, verifier) = poa.gen_pk_proof(&pk);
        let res = poa.verify_pk_proof(&prover, &verifier);

        assert_eq!(res, Ok(()));
    }
}
