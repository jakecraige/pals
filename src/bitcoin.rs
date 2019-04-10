use base58::{base58check_encode};
use elliptic_curve::{Sec};
use secp256k1::{Point};
use util::{hash160};

fn derive_address(public_key: &Point, compressed: bool, testnet: bool) -> Vec<u8> {
    let prefix = if testnet { 0x6f } else { 0x00 };
    let sec = if compressed { public_key.as_sec_compressed() } else { public_key.as_sec() };
    let hashed_pubkey = hash160(&sec);

    let mut hash_with_prefix: Vec<u8> = vec![prefix];
    hash_with_prefix.extend(hashed_pubkey);
    base58check_encode(&hash_with_prefix)
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt};
    use num_traits::{Pow};
    use secp256k1::{Secp256k1};
    use bitcoin::*;

    #[test]
    fn test_derive_address() {
        let curve = Secp256k1::new();

        let privkey = BigInt::from(5002);
        let pubkey = curve.pubkey(&privkey);
        let result = derive_address(&pubkey, false, true);
        assert_eq!(result, b"mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA".to_vec());

        let privkey = BigInt::from(2020).pow(5u8);
        let pubkey = curve.pubkey(&privkey);
        let result = derive_address(&pubkey, true, true);
        assert_eq!(result, b"mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH".to_vec());

        let privkey = BigInt::from(0x12345deadbeefu64);
        let pubkey = curve.pubkey(&privkey);
        let result = derive_address(&pubkey, true, false);
        assert_eq!(result, b"1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1".to_vec());
    }
}
