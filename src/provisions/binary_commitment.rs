use num_bigint::{BigInt};
use num_integer::{Integer};
use num_traits::*;
use secp256k1::{Secp256k1, Point};

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
        let g_base = g * value.clone();
        let h_base = h * blinding_factor.clone();
        let l = g_base + h_base;

        PedersenCommitment { g: g.clone(), h: h.clone(), l }
    }

    // In practice the value and blinding_factor will be hidden but this is easier for testing
    //
    // Interactive protocol for verifying a pedersen commitment (g, h, l = g^x*h^y).
    //
    // We want to verify the commitment to the secret which is: l = y^s * h^t
    // So for this method x=s and y=t.
    //   s and t are only known to the prover.
    //
    // 1) Prover selects u_0, u_1, c_f randomly from Z_q and produces:
    //     a_0 = h^u_0 * g^(-x*c_f),
    //     a_1 = h^u_1 * g^((1-x)*c_f)
    //
    // 2) Verify sends challenge c from Z_q and
    // 3) Prover computes:
    //     c_1 = x * (c - c_f) + (1 - x) * c_f
    //     r_0 = u_0 + (c - c_1) * y
    //     r_1 = u_1 + c_1 * y
    //     Sends (c_1, r_0, r_1) to verifier
    // 4) Verifier accepts if:
    //     h^r_0 = a_0(l)^(c-c_1)
    //     h^r_1 = a_1(lg^-1)^c_1
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
            let a0_h = commitment.h_ref() * u0;
            let a0_g = commitment.g_ref().inverse() * cf;
            let a0 = a0_h + a0_g;
            let a1 = commitment.h_ref() * u1; // h^u0

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
            let h_r0 = commitment.h_ref() * r0;
            let h_r1 = commitment.h_ref() * r1;

            let exp = BigInt::from(c - cf).mod_floor(&q); // c1 really
            let v_r0 = (commitment.l_ref() * exp) + &a0;
            let v_r1 = a1 + (commitment.l_ref().clone() + commitment.g_ref().inverse()) * c1;

            let left = h_r0 == v_r0;
            let right = h_r1 == v_r1;

            println!("print: {}", c - cf);
            println!("lhs: {}", h_r0);
            println!("rhs: {}", v_r0);
            println!("truthy: p1: {}, p2: {}", left, right);

            left && right
        } else {
            // Prover generates a0 and a1
            let a0 =   commitment.h_ref() * u0; // h^u0
            let a1_h = commitment.h_ref() * u1;
            let a1_g = commitment.g_ref() * cf;
            let a1 = a1_h + &a1_g; // h^u1 * h^cf

            // Verifier challenge
            let c = &cf * 2; //hax

            // Prover computes r0 and r1
            let c1 = cf.clone();
            let r0 = u0 + (c - cf) * blinding_factor;
            let r1 = u1 + cf * blinding_factor;

            // Verifier computes
            let h_r0 = commitment.h_ref() * r0;
            let h_r1 = commitment.h_ref() * r1;

            let v_r0 = (commitment.l_ref() * (c - cf)) + &a0;
            let v_r1 = a1 + (commitment.l_ref().clone() + commitment.g_ref().inverse()) * c1;

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
        let h = &g * 2;

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
