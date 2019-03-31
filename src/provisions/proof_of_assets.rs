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

    // Produce the public key from a provided private key. Helper method to provide more semantic
    // API to caller.
    pub fn pubkey(&self, private_key: &BigInt) -> Point {
        self.mul_g(private_key)
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
    fn new(private_key: BigInt, public_key: Point, balance: BigInt) -> Self {
        PublicKey {
            public_key,
            private_key: Some(private_key),
            balance
        }
    }

    fn new_from_pubkey(public_key: Point, balance: BigInt) -> Self {
        PublicKey {
            public_key,
            private_key: None,
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

    // Generate a pedersen commitment of pk ownership
    //     l = y^s * h^t, where t is random
    fn l(&self, curve: &ProvisionsCurve) -> (Point, BigInt) {
        let t = gen_rand();
        (curve.add(&curve.mul(&self.y(), &self.s()), &curve.mul_h(&t)), t)
    }
}

trait PublicKeyProof {
    fn p(&self) -> &Point;
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

impl PublicKeyProof for ProverPublicKeyProof {
    fn p(&self) -> &Point { &self.p }
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

impl PublicKeyProof for VerifierPublicKeyProof {
    fn p(&self) -> &Point { &self.p }
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

    // Product of p for each proof
    fn gen_z_assets(&self, proofs: &[impl PublicKeyProof]) -> Point {
        proofs.iter().fold(Point::Infinity, |acc, proof| self.curve.add(&acc, proof.p()))
    }
}


#[cfg(test)]
mod tests {
    use provisions::proof_of_assets::*;

    #[test]
    fn poa_public_key_b() {
        let curve = ProvisionsCurve::new();
        let (pubkey, privkey) = gen_pubkey();
        let pk = PublicKey::new(privkey, pubkey, BigInt::one());
        assert_eq!(pk.b(&curve), curve.mul_g(&BigInt::one()));

        let (pubkey, _) = gen_pubkey();
        let pk = PublicKey::new_from_pubkey(pubkey, BigInt::one());
        assert_eq!(pk.b(&curve), curve.mul_g(&BigInt::one()));
    }

    #[test]
    fn poa_public_key_commitment() {
        let curve = ProvisionsCurve::new();
        let (pubkey, privkey) = gen_pubkey();
        let pk = PublicKey::new(privkey, pubkey, BigInt::one());

        let (p, v) = pk.commitment(&curve);

        let b_s = curve.mul(&pk.b(&curve), &pk.s());
        let h_v = curve.mul_h(&v);
        let p_prime = curve.add(&b_s, &h_v);
        assert_eq!(p, p_prime);
    }

    #[test]
    fn poa_public_key_proof() {
        let poa = ProofOfAssets::new();

        // Private key known
        let (pubkey, privkey) = gen_pubkey();
        let pk = PublicKey::new(privkey, pubkey, BigInt::from(2));
        let (prover, verifier) = poa.gen_pk_proof(&pk);
        let res = poa.verify_pk_proof(&prover, &verifier);
        assert_eq!(res, Ok(()));

        // Private key not known
        let (pubkey, _) = gen_pubkey();
        let pk = PublicKey::new_from_pubkey(pubkey, BigInt::from(5));
        let (prover, verifier) = poa.gen_pk_proof(&pk);
        let res = poa.verify_pk_proof(&prover, &verifier);
        assert_eq!(res, Ok(()));
    }

    #[derive(Clone)]
    struct TestProof { p: Point }
    impl TestProof {
        fn new(p: Point) -> Self { TestProof { p } }
    }
    impl PublicKeyProof for TestProof {
        fn p(&self) -> &Point { &self.p }
    }

    #[test]
    fn poa_gen_z_assets() {
        let (pubk1, _) = gen_rand_pubkey();
        let proof1 = TestProof::new(pubk1);
        let (pubk2, _) = gen_rand_pubkey();
        let proof2 = TestProof::new(pubk2);
        let poa = ProofOfAssets::new();

        let z_assets = poa.gen_z_assets(&[proof1.clone(), proof2.clone()]);

        let expected = poa.curve.add(proof1.p(), proof2.p());
        assert_eq!(z_assets, expected);
    }

    fn gen_pubkey() -> (Point, BigInt) {
        let privkey = BigInt::from(5);
        (ProvisionsCurve::new().pubkey(&privkey), privkey)
    }

    fn gen_rand_pubkey() -> (Point, BigInt) {
        let mut rng = thread_rng();
        let privkey = rng.gen_bigint_range(&BigInt::zero(), &BigInt::from(100));
        (ProvisionsCurve::new().pubkey(&privkey), privkey)
    }
}
