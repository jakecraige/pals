use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Implements the Hash256 algorithm.
///
/// Hash256(x) = SHA256(SHA256(x)) - two rounds of SHA-256 on data.
pub fn hash256(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

/// Hash256(x) = SHA256(SHA256(x)) - two rounds of SHA-256 on data.
pub fn hash256_bigint(data: &[u8]) -> BigInt {
    let h = hash256(data);
    BigInt::from_bytes_be(Sign::Plus, &h)
}

#[cfg(test)]
mod tests {
    use util::*;
    use set1::{hex_encode};

    #[test]
    fn sha256_test() {
        let s = b"hello world";

        let hash = hex_encode(&sha256(s));

        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    }

    #[test]
    fn hash256_test() {
        let s = b"hello world";

        let hash = hex_encode(&hash256(s));

        assert_eq!(hash, "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423")
    }

    #[test]
    fn hash256_bigint_test() {
        let s = b"hello world";

        let hash = hash256_bigint(s).to_str_radix(16);

        assert_eq!(hash, "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423")
    }
}