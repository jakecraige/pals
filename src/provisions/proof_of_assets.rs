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

#[derive(Clone)]
struct PublicKey {
    private_key: Option<BigInt>,
    public_key: Point,
    balance: BigInt
}

impl PublicKey {
    fn new(private_key: Option<BigInt>, balance: BigInt) -> Self {
        PublicKey {
            private_key,
            public_key: Point::Infinity,
            balance
        }
    }

    fn s(&self) -> BigInt {
        self.private_key.clone().map_or(BigInt::zero(), |_| BigInt::one())
    }

    // b = g^(bal * s), s = 1 when private key known
    fn b(&self, curve: &ProvisionsCurve) -> Point {
        let val = &self.balance * self.s();
        curve.mul_g(&val)
    }

    // Generate a pedersen commitment (c = g^m * h^r) to the balance
    // For provisions: p = b^s * h^v, where v is random
    fn commitment(&self, curve: &ProvisionsCurve) -> (Point, BigInt) {
        let mut rng = thread_rng();
        let v = rng.gen_bigint(256);

        self.commitment_with_v(curve, v)
    }

    // Just a helper for testing to create the commitment with a specific value
    fn commitment_with_v(&self, curve: &ProvisionsCurve, v: BigInt) -> (Point, BigInt) {
        let b_s = curve.mul(&self.b(&curve), &self.s());
        let h_v = curve.mul_h(&v);
        let p = curve.add(&b_s, &h_v);

        (p, v)
    }
}

struct ProofOfAssets {
    curve: ProvisionsCurve
}

impl ProofOfAssets {
    fn new() -> Self {
        ProofOfAssets { curve: ProvisionsCurve::new() }
    }
}

impl ProofOfAssets {
    // PK: The set of public keys that we generate the proof from. If we own the address the
    // optional private_key on the struct should be set.
    //
    // Returns a tuple (z_assets, vec(pedersen_commitment, rand_value))
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
        assert_eq!(pk.b(&curve), curve.mul_g(&BigInt::zero()));
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
}
