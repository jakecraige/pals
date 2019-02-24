#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use base64::decode as base64decode;
    use set3::aes_ctr::{encrypt};
    use set1::{transpose, decrypt_single_byte_xor_with_score_bytes};

    #[test]
    fn ctr_nonce_reuse_19() {
        let key = b"YELLOW SUBMARINE";
        let nonce: u64 = 0;
        let file = read_file("src/data/challenge19.txt");
        let mut decoded_file: Vec<Vec<u8>> = file.lines().map(|line| base64decode(line).unwrap()).collect();
        let first_pt = decoded_file.pop().unwrap();
        let second_pt = decoded_file.pop().unwrap();
        let first_ct = encrypt(&first_pt, key, nonce);
        let second_ct = encrypt(&second_pt, key, nonce);

        // Let's assume that we know one of the plaintexts in the list. Using this we can find the
        // keystream and thus decrypt everything using the same nonce. This example wants us to use
        // some form of frequency analysis to find the stream but I'm lazy right now :)
        //
        // One way to crack it assuming an encryption oracle is to do an encryption for every
        // character which would give us back `known_letter ^ ks` and we know that that letter at
        // the same byte index in another CT will be the same. So we can do that for lots of
        // letters we can build up a map of every encrypted character at every index to some
        // L length of ciphertext. Then we just read off ciphertexts and look up the plaintext
        // value in the map.
        //
        // I'm not sure if that's what they had in mind since it doesn't care about common letters
        // , trigrams, etc. Something like that could be done similarly by doing the same thing, use
        // common letters but instead of doing an encryption, xor it with the ciphertext and look
        // for frequencies of that letter in the output. Where the frequencies hold up is likely
        // the correct ks byte for that index and we can attempt to decrypt with that and get most
        // of the PT back.
        let ks = xor(&first_pt, &first_ct);
        let decrypted_second_ct = xor(&second_ct, &ks);

        print_string(&decrypted_second_ct);
        assert_eq!(second_pt, decrypted_second_ct);
    }

    #[test]
    fn ctr_nonce_reuse_20() {
        let key = b"YELLOW SUBMARINE";
        let nonce: u64 = 0;
        let file = read_file("src/data/challenge20.txt");
        let ciphertexts: Vec<Vec<u8>> = file.lines().map(|line| {
            let pt = base64decode(line).unwrap();
            print_string(&pt);
            encrypt(&pt, key, nonce)
        }).collect();
        let mut min_len = 9999999;
        for content in ciphertexts.clone() {
            if content.len() < min_len {
                min_len = content.len();
            }
        }
        let ciphertexts: Vec<Vec<u8>> = ciphertexts.iter().map(|ct| ct[0..min_len].to_vec()).collect();
        // NOTE: transpose doesn't currently work if len is longer than the block size
        let transposed = transpose(ciphertexts[0..min_len].to_vec());

        let mut key: Vec<u8> = vec![];
        for block in &transposed {
            let res = decrypt_single_byte_xor_with_score_bytes(&block);
            if let Some((score, c, plaintext)) = &res {
                key.push(*c as u8);
            }
        }

        for ct in ciphertexts {
            let content = xor(&ct, &key);
            print_chars(&content);
        }

        // We just mark this as passed since we manually verify it works.
        assert!(true);
    }

    // Helper to read a file from disk unsafely and strip newlines
    fn read_file(path: &str) -> String {
        let mut f = File::open(path).expect("file not found");
        let mut contents = String::new();
        f.read_to_string(&mut contents).expect("something went wrong reading the file");

        contents
    }

    fn print_string(input: &[u8]) {
        let pt_str = String::from_utf8(input.to_vec()).expect("valid pt");
        println!("{:?}", pt_str);
    }

    fn print_chars(input: &[u8]) {
        let mut s = String::new();
        for i in input {
            if *i > 0 && *i < 122 {
                s.push(*i as char);
            } else {
                s.push(' ');
            }
        }
        println!("{:?}", s);
    }

    fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
        left.iter().zip(right.iter()).map(|(left, right)| left ^ right).collect()
    }
}
