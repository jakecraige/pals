// Helpful resource for testing: https://cryptii.com/pipes/base64-to-hex
// Resource for bit fiddling: http://www.coranac.com/documents/working-with-bits-and-bitfields/
use std::collections::HashMap;
use std::str;

fn hex_to_nibbles(input: &str) -> Vec<u8> {
    // Can also be done with some ascii shifting described in
    // https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/
    let mut mapping: HashMap<char, u8> = HashMap::new();
    mapping.insert('0', 0);
    mapping.insert('1', 1);
    mapping.insert('2', 2);
    mapping.insert('3', 3);
    mapping.insert('4', 4);
    mapping.insert('5', 5);
    mapping.insert('6', 6);
    mapping.insert('7', 7);
    mapping.insert('8', 8);
    mapping.insert('9', 9);
    mapping.insert('a', 10);
    mapping.insert('b', 11);
    mapping.insert('c', 12);
    mapping.insert('d', 13);
    mapping.insert('e', 14);
    mapping.insert('f', 15);

    input.chars().map(|c| *mapping.get(&c).unwrap()).collect()
}

fn nibs_to_byte(left: u8, right: u8) -> u8 {
    // add in the left half, shift it left, then add in the right
    ((0 ^ left) << 4) ^ right
}

fn nibs_to_bytes(nibs: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for nibs in nibs.chunks(2) {
        out.push(nibs_to_byte(nibs[0], nibs[1]));
    }
    out
}

// The encoding process represents 24-bit groups of input bits as output
// strings of 4 encoded characters.  Proceeding from left to right, a
// 24-bit input group is formed by concatenating 3 8-bit input groups.
// These 24 bits are then treated as 4 concatenated 6-bit groups, each
// of which is translated into a single digit in the base 64 alphabet.

// Each 6-bit group is used as an index into an array of 64 printable
// characters.  The character referenced by the index is placed in the
// output string.
fn bytes_to_base64(bytes: &[u8]) -> String {
    // create 24 bit groups
    let mut grouped: Vec<(u8, u8, u8)> = vec![];
    for chunk in bytes.chunks(3) {
        match chunk.len() {
            3 => grouped.push((chunk[0], chunk[1], chunk[2])),
            // NOTE: This is not the right way to handle padding. It'll lead to the padding
            // displayed as `AA` and `A` instead of `==` and `=`.
            2 => grouped.push((chunk[0], chunk[1], 0)),
            1 => grouped.push((chunk[0], 0, 0)),
            _ => unreachable!()
        }
    }

    // split into 6-bit groups
    let mut bit6vec: Vec<u8> = vec![];
    for byte_triple in grouped {
        let (b1, b2, b3, b4) = byte_triple_to_6bit(byte_triple);
        bit6vec.push(b1);
        bit6vec.push(b2);
        bit6vec.push(b3);
        bit6vec.push(b4);
    }

    // map 6-bit u8s to char
    let mut result = String::new();
    for val in bit6vec {
        match val {
            0...25 => result.push((val + 65) as char),
            26...51 => result.push((val + 71) as char),
            52...61 => result.push((val - 4) as char),
            62 => result.push('+'),
            63 => result.push('/'),
            _ => unreachable!() // should be 6 bit, this should not be reachable
        }
    }
    result
}

fn nibs_to_hex(nibbles: &[u8]) -> String {
    let mut hex = String::new();
    for nib in nibbles {
        match nib {
            0...9 => hex.push((nib + 48) as char),
            10...15 => hex.push((nib + 87) as char),
            _ => unreachable!() // should be 4 bit, this should not be reachable
        }
    }
    hex
}

// Convert 3 bytes into 4 6-bit u8s
fn byte_triple_to_6bit(bytes: (u8, u8, u8)) -> (u8, u8, u8, u8) {
    let (b1, b2, b3) = bytes;

    // First 6 of b1
    let p1 = b1 >> 2;
    // Last 2 of b1, zero left 2, add in first 4 of b3
    let p2 = ((b1 << 4) & 0b00111111u8) ^ (b2 >> 4);
    // Zero left 4 bits, then last 4 of b2, first 2 of b3
    let p3 = ((b2 & 0b00001111u8) << 2) ^ (b3 >> 6);
    // Last 6 of b3
    let p4 = b3 & 0b00111111u8;

    (p1, p2, p3, p4)
}

fn hex_to_base64(input: &str) -> String {
    let nibs = hex_to_nibbles(input);
    let bytes = nibs_to_bytes(&nibs);
    // There be easter egg here:
    // println!("{:?}", str::from_utf8(&bytes).unwrap());
    let res = bytes_to_base64(&bytes);
    res
}

fn xor(left_hex: &str, right_hex: &str) -> String {
    let left_nibs = hex_to_nibbles(left_hex);
    let right_nibs = hex_to_nibbles(right_hex);

    let xored: Vec<u8> = left_nibs.iter()
        .zip(right_nibs.iter())
        .map(|(left, right)| left ^ right)
        .collect();

    nibs_to_hex(&xored)
}

fn decrypt_bytes_with_byte(bytes: &[u8], s: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ s).collect()
}


fn decrypt_single_byte_xor(input: &str) -> String {
    let nibs = hex_to_nibbles(input);
    let bytes = nibs_to_bytes(&nibs);

    // Decrypt using only ascii A-Za-z
    let raw_plaintexts = (65..123u8) // ASCII letters
        .map(|char_int| decrypt_bytes_with_byte(&bytes, char_int))
        .collect::<Vec<_>>();

    // Filter down list into just ones with ascii characters
    let ascii_plaintexts = raw_plaintexts.iter()
        .filter(|bytes| {
            bytes.iter().all(|byte| byte >= &32 && byte < &126)
        }).collect::<Vec<_>>();


    let best_score_with_plaintext = ascii_plaintexts.iter().map(|plaintext| {
        let frequency = text_frequency(&plaintext);
        let score = frequency_score(&frequency);
        (score, plaintext)
    }).max_by_key(|x| x.0);


    let plaintext = best_score_with_plaintext
        .map(|x| x.1)
        .and_then(|bytes| str::from_utf8(&bytes).ok())
        .unwrap();

    plaintext.to_string()
}


fn text_frequency(plaintext: &[u8]) -> HashMap<char, usize> {
    let mut score = HashMap::new();
    for c in plaintext {
        let counter = score.entry((*c as char).to_lowercase().next().unwrap()).or_insert(0);
        *counter += 1;
    }
    score
}

// Simple summing of the most common letters in english. Frequency has everything stored in
// lowercase so we don't need to to uppercase.
fn frequency_score(frequency: &HashMap<char, usize>) -> usize {
    // ETAOIN SHRDLU
    frequency.get(&'e').unwrap_or(&0) +
        frequency.get(&'t').unwrap_or(&0) +
        frequency.get(&'a').unwrap_or(&0) +
        frequency.get(&'o').unwrap_or(&0) +
        frequency.get(&'i').unwrap_or(&0) +
        frequency.get(&'n').unwrap_or(&0) +
        frequency.get(&' ').unwrap_or(&0) +
        frequency.get(&'s').unwrap_or(&0) +
        frequency.get(&'h').unwrap_or(&0) +
        frequency.get(&'r').unwrap_or(&0) +
        frequency.get(&'d').unwrap_or(&0) +
        frequency.get(&'l').unwrap_or(&0) +
        frequency.get(&'u').unwrap_or(&0)
}

#[cfg(test)]
mod tests {
    use set1;

    #[test]
    fn hex_to_nibbles() {
        let input = "0f";
        let output = set1::hex_to_nibbles(&input);

        assert_eq!(output, &[0b0000, 0b1111])
    }

    #[test]
    fn nibs_to_byte() {
        assert_eq!(set1::nibs_to_byte(0b0000, 0b0000), 0b00000000);
        assert_eq!(set1::nibs_to_byte(0b1111, 0b0000), 0b11110000);
        assert_eq!(set1::nibs_to_byte(0b0000, 0b1111), 0b00001111);
        assert_eq!(set1::nibs_to_byte(0b1010, 0b1010), 0b10101010);
    }

    #[test]
    fn nibs_to_bytes() {
        assert_eq!(set1::nibs_to_bytes(&[0b0000, 0b0000]), &[0b00000000]);
        assert_eq!(set1::nibs_to_bytes(&[0b1111, 0b0000]), &[0b11110000]);
        assert_eq!(set1::nibs_to_bytes(&[0b0000, 0b1111]), &[0b00001111]);
        assert_eq!(set1::nibs_to_bytes(&[0b1010, 0b1010]), &[0b10101010]);
    }

    #[test]
    fn byte_triple_to_6bit() {
        assert_eq!(
            set1::byte_triple_to_6bit((0b00000000, 0b00010000, 0b10000011)),
            (0b000000, 0b000001, 0b000010, 0b000011)
        );

        assert_eq!(
            set1::byte_triple_to_6bit((0b01101111, 0b01101111, 0b01101101)),
            (0b011011, 0b110110, 0b111101, 0b101101)
        );
    }

    #[test]
    fn bytes_to_base64() {
        assert_eq!(
            set1::bytes_to_base64(&[0b00000000, 0b00010000, 0b10000011]),
            "ABCD"
        );
        // If I make padding work
        // assert_eq!(set1::bytes_to_base64(&[0b00000000]), "AA==");
    }

    #[test]
    fn hex_to_base64() {
        // Data from: https://cryptopals.com/sets/1/challenges/1
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let result = set1::hex_to_base64(&input);

        assert_eq!(result, output);
    }

    #[test]
    fn xor() {
        //Data from: https://cryptopals.com/sets/1/challenges/2
        let left = "1c0111001f010100061a024b53535009181c";
        let right = "686974207468652062756c6c277320657965";

        let result = set1::xor(&left, &right);

        assert_eq!(result, "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn decrypt_single_byte_xor() {
        // Decrypt hex encoded string xor'd with single character
        // https://cryptopals.com/sets/1/challenges/3
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let result = set1::decrypt_single_byte_xor(&ciphertext);

        assert_eq!(result, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn text_frequency() {
        let plaintext = "ab ab abc deb";

        let frequency = set1::text_frequency(plaintext.as_bytes());

        assert_eq!(frequency.get(&'a'), Some(&3usize));
        assert_eq!(frequency.get(&'b'), Some(&4usize));
        assert_eq!(frequency.get(&'c'), Some(&1usize));
        assert_eq!(frequency.get(&'d'), Some(&1usize));
        assert_eq!(frequency.get(&'e'), Some(&1usize));
        assert_eq!(frequency.get(&' '), Some(&3usize));
        assert_eq!(frequency.get(&'z'), None);
    }

    #[test]
    fn frequency_score() {
        let plaintext = "ab ab abc deb";

        let frequency = set1::text_frequency(plaintext.as_bytes());
        let score = set1::frequency_score(&frequency);

        assert_eq!(score, 8);
    }
}
