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
        let l = g * value.clone() + h * blinding_factor.clone();

        PedersenCommitment { g: g.clone(), h: h.clone(), l }
    }

    // Interactive protocol for verifying a bimary pedersen commitment (g, h, l = g^x*h^y).
    // In practice the value and blinding_factor will be hidden but this is easier for testing
    //
    // 1) Prover selects u0, u1, cf randomly from Z_q and produces:
    //     a0 = h^u0 * g^(-x*cf),
    //     a1 = h^u1 * g^((1-x)*cf)
    //
    // 2) Verify sends challenge c from Z_q and
    // 3) Prover computes:
    //     c1 = x * (c - cf) + (1 - x) * cf
    //     r0 = u0 + (c - c1) * y
    //     r1 = u1 + c1 * y
    //     Sends (c1, r0, r1) to verifier
    // 4) Verifier accepts if:
    //     h^r0 = a0(l)^(c-c1)
    //     h^r1 = a1(lg^-1)^c1
    fn verify_binary_commitment(
        comm: &PedersenCommitment,
        value: &BigInt, blinding_factor: &BigInt, curve: &Secp256k1
    ) -> bool {
        let truthy = value == &BigInt::one();

        // Prover selects "random" values and challenge
        let (u0, u1, cf) = (9213, 125, 3);
        // a_0 = h^u_0 * g^(-x*c_f),
        // a_1 = h^u_1 * g^((1-x)*c_f)
        let a0 = comm.h_ref() * u0 + comm.g_ref() * (-value * cf);
        let a1 = comm.h_ref() * u1 + comm.g_ref() * ((1 - value) * cf);

        let c = 6; // verifier challenge

        // Prover computes:
        // c_1 = x * (c - c_f) + (1 - x) * c_f
        // r_0 = u_0 + (c - c_1) * y
        // r_1 = u_1 + c_1 * y
        let c1: BigInt = value * (c - cf) + (1 - value) * cf;
        let r0 = u0 + (c - &c1) * blinding_factor;
        let r1 = u1 + &c1 * blinding_factor;

        // Verifier verifies:
        // h^r_0 = a_0(l)^(c-c_1)
        // h^r_1 = a_1(lg^-1)^c_1
        let p1 = comm.h_ref() * r0 == a0 + comm.l_ref() * (c - &c1);
        let p2 = comm.h_ref() * r1 == a1 + (comm.l_ref() + &comm.g_ref().inverse()) * c1.clone();

        println!("p1: {}, p2: {}", p1, p2);
        p1 && p2
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
        let h = curve.hash_onto_curve(b"PROVISIONS");

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
    }
}
