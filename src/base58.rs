use std::iter;
use num_bigint::{BigInt, Sign};
use num_traits::*;
use num_integer::{Integer};
use util::{hash256};

static BASE58_ALPHABET : &'static [u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> Vec<u8> {
    let mut zero_bytes_num = 0;
    for byte in bytes {
        if *byte == 0 {
            zero_bytes_num += 1;
        } else {
            break;
        }
    }


    let mut num = BigInt::from_bytes_be(Sign::Plus, bytes);
    let fifty_eight = BigInt::from(58);
    let mut result: Vec<u8> = vec![];
    while num > BigInt::zero() {
        let (quotient, rem) = num.div_mod_floor(&fifty_eight);
        // we know this is safe since we mod 58
        let next_char = BASE58_ALPHABET[rem.to_usize().unwrap()];
        result.push(next_char);
        num = quotient;
    }
    result.reverse();

    let prefix: Vec<u8> = iter::repeat('1' as u8).take(zero_bytes_num).collect();

    let mut final_val = prefix;
    final_val.extend(result);
    final_val
}

pub fn base58check_encode(bytes: &[u8]) -> Vec<u8> {
    let checksum = &hash256(bytes)[0..4];
    let mut bytes_with_checksum = bytes.to_vec();
    bytes_with_checksum.append(&mut checksum.to_vec());
    base58_encode(&bytes_with_checksum)
}

#[cfg(test)]
mod tests {
    use base58::*;
    use set1::{hex_decode};

    #[test]
    fn base58_encoding() {
        let test_vectors: Vec<(&str, &[u8])> = vec![
            (
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                b"9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6"
            ),
            (
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                b"4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd"
            ),
            (
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                b"EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7"
            )
        ];

        for (hex_input, expected_bytes) in &test_vectors[0..] {
            let bytes = hex_decode(&hex_input);
            let output = base58_encode(&bytes);
            assert_eq!(output, expected_bytes.to_vec());
        }
    }
}
