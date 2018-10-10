// Helpful resource for testing: https://cryptii.com/pipes/base64-to-hex
// Resource for bit fiddling: http://www.coranac.com/documents/working-with-bits-and-bitfields/
use base64::decode as base64decode;
use std::collections::HashMap;
use std::str;
use openssl::symm::{decrypt, Cipher};
use openssl::error::ErrorStack;

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
            _ => unreachable!(),
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
            _ => unreachable!(), // should be 6 bit, this should not be reachable
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
            _ => unreachable!(), // should be 4 bit, this should not be reachable
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

fn hex_decode(hex: &str) -> Vec<u8> {
    let nibs = hex_to_nibbles(hex);
    nibs_to_bytes(&nibs)
}

fn hex_to_base64(input: &str) -> String {
    let bytes = hex_decode(input);
    // There be easter egg here:
    // println!("{:?}", str::from_utf8(&bytes).unwrap());
    let res = bytes_to_base64(&bytes);
    res
}

fn xor(left_hex: &str, right_hex: &str) -> String {
    let left_nibs = hex_to_nibbles(left_hex);
    let right_nibs = hex_to_nibbles(right_hex);

    let xored: Vec<u8> = left_nibs
        .iter()
        .zip(right_nibs.iter())
        .map(|(left, right)| left ^ right)
        .collect();

    nibs_to_hex(&xored)
}

fn decrypt_bytes_with_byte(bytes: &[u8], s: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ s).collect()
}

fn decrypt_single_byte_xor_with_score(input: &str) -> Option<(usize, Vec<u8>)> {
    let nibs = hex_to_nibbles(input);
    let bytes = nibs_to_bytes(&nibs);

    decrypt_single_byte_xor_with_score_bytes(&bytes).map(|(score, _, bytes)| (score, bytes))
}

fn decrypt_single_byte_xor_with_score_bytes(bytes: &[u8]) -> Option<(usize, char, Vec<u8>)> {
    let ascii_plaintexts_with_scores = (0..127u8) // ASCII letters
        .map(|char_int| (char_int, decrypt_bytes_with_byte(&bytes, char_int)))
        // Calculate frequency and score
        .map(|(char_int, plaintext)| {
            let frequency = text_frequency(&plaintext);
            let score = frequency_score(&frequency);
            (score, char_int as char, plaintext)
        });

    // Return the one with the highest score
    ascii_plaintexts_with_scores.max_by_key(|x| x.0)
}

fn decrypt_single_byte_xor(input: &str) -> String {
    let decrypted_with_score = decrypt_single_byte_xor_with_score(input);
    let bytes = decrypted_with_score.map(|(_, bytes)| bytes);
    let plaintext = bytes.and_then(|b| String::from_utf8(b).ok());

    plaintext.unwrap() // YOLO
}

fn detect_single_byte_xor(inputs: Vec<&str>) -> Option<String> {
    inputs
        .iter()
        .filter_map(|input| decrypt_single_byte_xor_with_score(input))
        .max_by_key(|x| x.0)
        .map(|x| x.1)
        .and_then(|b| String::from_utf8(b).ok())
}

fn text_frequency(plaintext: &[u8]) -> HashMap<char, usize> {
    let mut score = HashMap::new();
    for c in plaintext {
        let counter = score
            .entry((*c as char).to_lowercase().next().unwrap())
            .or_insert(0);
        *counter += 1;
    }
    score
}

// Simple summing of the most common letters in english. Frequency has everything stored in
// lowercase so we don't need to to uppercase.
fn frequency_score(frequency: &HashMap<char, usize>) -> usize {
    // ETAOIN SHRDLU
    frequency.get(&'e').unwrap_or(&0)
        + frequency.get(&'t').unwrap_or(&0)
        + frequency.get(&'a').unwrap_or(&0)
        + frequency.get(&'o').unwrap_or(&0)
        + frequency.get(&'i').unwrap_or(&0)
        + frequency.get(&'n').unwrap_or(&0)
        + frequency.get(&' ').unwrap_or(&0)
        + frequency.get(&'s').unwrap_or(&0)
        + frequency.get(&'h').unwrap_or(&0)
        + frequency.get(&'r').unwrap_or(&0)
        + frequency.get(&'d').unwrap_or(&0)
        + frequency.get(&'l').unwrap_or(&0)
        + frequency.get(&'u').unwrap_or(&0)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::new();
    for byte in bytes {
        // If I want to actually implement hex encoding, turn bytes into nibbles, then map them to
        // the expected values.
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn xor_encrypt_with_key(plaintext: &str, key: &str) -> String {
    let encrypted = plaintext
        .as_bytes()
        .iter()
        .zip(key.as_bytes().iter().cycle())
        .map(|(p, s)| p ^ s)
        .collect::<Vec<u8>>();

    hex_encode(&encrypted)
}

fn xor_decrypt_with_key(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext
        .iter()
        .zip(key.iter().cycle())
        .map(|(p, s)| p ^ s)
        .collect::<Vec<u8>>()
}

fn decrypt_repeating_xor(base64: &str) -> String {
    let bytes = base64decode(base64).unwrap();

    // For each KEYSIZE, 2-40, take first and second keysize of bytes, calculate normalized
    // distance, and select the lowest as the likely key size.
    let mut lowest_distance = 999999;
    let mut best_sizes: Vec<usize> = vec![];
    for key_size in 2..41 {
        let mut chunks = bytes.chunks(key_size);
        // Take 4 blocks and average them for the distance
        let distance1 = hamming_distance(chunks.next().unwrap(), chunks.next().unwrap());
        let distance2 = hamming_distance(chunks.next().unwrap(), chunks.next().unwrap());
        let normalized_distance = ((distance1 + distance2) / 2) / key_size;

        if normalized_distance < lowest_distance {
            // We have a new best distance, clear out prev sizes and add in the new one.
            best_sizes.clear();
            best_sizes.push(key_size);
            lowest_distance = normalized_distance;
        } else if normalized_distance == lowest_distance {
            // Same distance, we add this key size to the options
            best_sizes.push(key_size);
        }
    }

    let mut best_score = 0;
    let mut found_key = String::new();
    for key_size in &best_sizes {
        let blocks: Vec<Vec<u8>> = bytes
            .chunks(*key_size)
            .map(|block| block.to_vec())
            .collect();
        let transposed: Vec<Vec<u8>> = transpose(blocks);

        // Solve each block as if it was single-character XOR. You already have code to do this.
        //
        // For each block, the single-byte XOR key that produces the best looking histogram is the
        // repeating-key XOR key byte for that block. Put them together and you have the key.
        let mut key = String::new();
        let mut total_score = 0;
        for block in &transposed {
            let res = decrypt_single_byte_xor_with_score_bytes(&block);
            if let Some((score, c, plaintext)) = &res {
                if score > &0 {
                    total_score += score;
                    key.push(*c);
                }
            }
        }
        if total_score > best_score {
            best_score = total_score;
            found_key = key;
        }
    }

    let plaintext = xor_decrypt_with_key(&bytes, found_key.as_bytes());
    String::from_utf8(plaintext).unwrap()
}

fn transpose(input: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let len = input.len();
    let mut output: Vec<Vec<u8>> = vec![];

    for i in 0..len {
        let mut block: Vec<u8> = vec![];

        for inner in input.iter() {
            if i < inner.len() {
                let val = inner[i];
                block.push(val);
            }
        }

        output.push(block);
    }

    output
}

fn byte_hamming_distance(left: &u8, right: &u8) -> usize {
    // C impl from: https://en.wikipedia.org/wiki/Hamming_distance
    //
    // Example:
    //  left: 1111, right: 1010 = expected distance: 2
    //  val = 1111 ^ 1010 =   0101
    //      distance++, val = 0101 & 0100 = 0100, val != 0
    //      distance++, val = 0100 & 0011 = 0000, val == 0
    //  distance = 2
    let mut distance: usize = 0;
    let mut val = left ^ right;

    while val != 0 {
        distance += 1;
        val &= val - 1;
    }

    distance
}

fn hamming_distance(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .map(|(l, r)| byte_hamming_distance(l, r))
        .sum()
}

fn aes_ecb_decrypt(input: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, input)
}

fn bytes_to_16bit_blocks(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks(2).map(|byte_pair| {
        let mut block = 0u16;
        block ^= byte_pair[0] as u16;
        block <<= 8;
        block ^= byte_pair[1] as u16;
        block
    }).collect()
}

fn num_duplicate_blocks(bytes: &[u16]) -> usize {
    let mut byte_map: HashMap<u16, usize> = HashMap::new();

    for byte in bytes {
        let count = byte_map.entry(*byte).or_insert(0);
        *count += 1;
    }

    let max_dup = byte_map.iter().map(|kv| kv.1).max();
    max_dup.unwrap_or(&0).clone()
}

fn detect_aes_ecb_from_hex_lines(input: &str) -> Option<String> {
    input.lines()
        .map(|line| hex_decode(line))
        // Retain bytes value in u8 while making sure to check duplicate blocks with 16 bit values
        // since that's the length of the key that was used for the input.
        .map(|bytes| (bytes.clone(), num_duplicate_blocks(&bytes_to_16bit_blocks(&bytes))))
        .max_by_key(|tup| tup.1)
        .map(|tup| hex_encode(&tup.0))
}

#[cfg(test)]
mod tests {
    use set1;
    use std::fs::File;
    use std::io::Read;
    use base64::decode as base64decode;

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

    #[test]
    fn detect_single_byte_xor() {
        let mut f = File::open("src/data/challenge4.txt").expect("file not found");
        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");
        let input: Vec<&str> = contents.split("\n").collect();

        let result = set1::detect_single_byte_xor(input);

        assert_eq!(result, Some("Now that the party is jumping\n".to_string()));
    }

    #[test]
    fn xor_encrypt_with_key() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let ciphertext = set1::xor_encrypt_with_key(&plaintext, &key);

        assert_eq!(
            ciphertext,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn decrypt_repeating_xor() {
        let mut f = File::open("src/data/challenge6.txt").expect("file not found");
        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");
        // base64 crate can't handle newlines
        contents = contents.replace("\n", "");

        let result = set1::decrypt_repeating_xor(&contents);

        // If you want to see it...
        // println!("Plaintext: {}", result);
        assert_eq!(result.len(), 2876);
    }

    #[test]
    fn hamming_distance() {
        let left = "this is a test";
        let right = "wokka wokka!!!";

        let distance = set1::hamming_distance(left.as_bytes(), right.as_bytes());

        assert_eq!(distance, 37usize);
    }

    #[test]
    fn transpose() {
        let input = vec![vec![1, 2], vec![3, 4]];
        let output = vec![vec![1, 3], vec![2, 4]];

        let result = set1::transpose(input);

        assert_eq!(result, output);
    }

    #[test]
    fn aes_ecb_decrypt() {
        let key = "YELLOW SUBMARINE";
        let input = base64decode(&read_file("src/data/challenge7.txt", true)).unwrap();

        let pt_bytes = set1::aes_ecb_decrypt(&input, key.as_bytes()).unwrap();
        let plaintext = String::from_utf8(pt_bytes).unwrap();

        println!("Plaintext: {}", plaintext);
        assert!(plaintext.contains("My posse's to the side yellin', Go Vanilla Go!"));
    }

    #[test]
    fn detect_aes_ecb_from_hex_lines() {
        let input = read_file("src/data/challenge8.txt", false);

        let hex_str = set1::detect_aes_ecb_from_hex_lines(&input).unwrap();

        println!("Plaintext: {}", hex_str);
        assert!(hex_str.contains("d880619740a8a19b"));
    }

    #[test]
    fn bytes_to_16bit_blocks() {
        let output = set1::bytes_to_16bit_blocks(&vec![0b00000000, 0b11111111]);
        assert_eq!(output, vec![0b0000000011111111]);
    }

    // Helper to read a file from disk unsafely and strip newlines
    fn read_file(path: &str, remove_newlines: bool) -> String {
        let mut f = File::open(path).expect("file not found");
        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .expect("something went wrong reading the file");
        // base64 crate can't handle newlines
        if remove_newlines {
            contents = contents.replace("\n", "");
        }

        contents
    }
}
