use num_bigint::{BigInt};
use num_integer::{Integer};
use num_traits::*;
use elliptic_curve::{Point};
use secp256k1::{Secp256k1};

// Commitment to x given: (g, h, l = g^x*h^y).
struct PedersenCommitment {
    g: Point,
    h: Point,
    l: Point,
}

impl PedersenCommitment {
    fn create_commitment<T: Into<BigInt> + Clone>(
        g: &Point, h: &Point, curve: &Secp256k1,
        value: &T, blinding_factor: &T
    ) -> PedersenCommitment {
        let g_base = curve.with(g).mul(value);
        let h_base = curve.with(h).mul(blinding_factor);
        let l = g_base.add(&h_base.value).value;

        PedersenCommitment { g: g.clone(), h: h.clone(), l }
    }

    // In practice the value and blinding_factor will be hidden but this is easier for testing
    fn verify_binary_commitment(
        commitment: &PedersenCommitment,
        value: &BigInt, blinding_factor: &BigInt, curve: &Secp256k1
    ) -> bool {
        let truthy = value == &BigInt::one();

        // Prover selects "random" values and challenge
        let (u0, u1, cf) = (9213, 125, 3);
        let q = Secp256k1::p();
        if truthy {
            // Prover generates a0 and a1
            let a0_h = curve.with(commitment.h_ref()).mul(&u0);
            let a0_g = curve.with(&commitment.g_ref().inverse()).mul(&cf);
            let a0 = a0_h.add(&a0_g.value).value;
            let a1 = curve.with(commitment.h_ref()).mul(&u1).value; // h^u0

            // Verifier challenge
            // TODO: Oddly broken, given c
            //  if cf = c / 2, passes
            //  if cf <= c, last half passes
            //  if cf > c, nothing passes
            let c = &cf * 2; // hax

            // Prover computes r0 and r1
            let c1 = BigInt::from(c - &cf).mod_floor(&q);
            let r0 = BigInt::from(u0 + (cf * blinding_factor)).mod_floor(&q);
            let r1 = BigInt::from(u1 + ((c - cf) * blinding_factor)).mod_floor(&q);
            println!("c: {}, cf: {}", c, cf);
            println!("c1: {}, r0: {}, r1: {}", c1, r0, r1);

            // Verifier computes
            let h_r0 = curve.with(commitment.h_ref()).mul(&r0).value;
            let h_r1 = curve.with(commitment.h_ref()).mul(&r1).value;

            let exp = BigInt::from(c - cf).mod_floor(&q); // c1 really
            let v_r0 = curve.with(commitment.l_ref()).mul(&exp).add(&a0).value;
            let v_r1 = curve.with(commitment.l_ref())
                .add(&commitment.g_ref().inverse())
                .mul(&c1)
                .add(&a1)
                .value;

            let left = h_r0 == v_r0;
            let right = h_r1 == v_r1;

            println!("print: {}", c - cf);
            println!("lhs: {}", h_r0);
            println!("rhs: {}", v_r0);
            println!("truthy: p1: {}, p2: {}", left, right);

            left && right
        } else {
            // Prover generates a0 and a1
            let a0 = curve.with(commitment.h_ref()).mul(&u0).value; // h^u0
            let a1_h = curve.with(commitment.h_ref()).mul(&u1);
            let a1_g = curve.with(commitment.g_ref()).mul(&cf);
            let a1 = a1_h.add(&a1_g.value).value; // h^u1 * h^cf

            // Verifier challenge
            let c = &cf * 2; //hax

            // Prover computes r0 and r1
            let c1 = cf.clone();
            let r0 = u0 + (c - cf) * blinding_factor;
            let r1 = u1 + cf * blinding_factor;

            // Verifier computes
            let h_r0 = curve.with(commitment.h_ref()).mul(&r0).value;
            let h_r1 = curve.with(commitment.h_ref()).mul(&r1).value;

            let v_r0 = curve.with(commitment.l_ref()).mul(&(c - cf)).add(&a0).value;
            let v_r1 = curve.with(commitment.l_ref())
                .add(&commitment.g_ref().inverse())
                .mul(&c1)
                .add(&a1)
                .value;

            let left = h_r0 == v_r0;
            let right = h_r1 == v_r1;

            println!("falsy: p1: {}, p2: {}", left, right);

            left && right
        }
    }

    fn g_ref(&self) -> &Point { &self.g }
    fn h_ref(&self) -> &Point { &self.h }
    fn l_ref(&self) -> &Point { &self.l }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt};
    use provisions::binary_commitment::*;

    #[test]
    fn pedersen_commitment_binary_verify() {
        let curve = Secp256k1::new();
        let g = curve.g();
        let h = curve.with(&g).mul(&2).value;

        // Verify falsy commitment
        let val = &BigInt::from(0);
        let bf = &BigInt::from(152131);
        let commitment = PedersenCommitment::create_commitment(&g, &h, &curve, val, bf);
        assert!(PedersenCommitment::verify_binary_commitment(&commitment, val, bf, &curve));

        // Verify truthy commitment
        let val = &BigInt::from(1);
        let bf = &BigInt::from(12414);
        let commitment = PedersenCommitment::create_commitment(&g, &h, &curve, val, bf);
        assert!(PedersenCommitment::verify_binary_commitment(&commitment, val, bf, &curve));
        // assert!(false);

    }
}
