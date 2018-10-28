use set2::aes_cbc;
use set2::{pkcs_7_pad};

const BLOCK_SIZE: usize = 16;

// Encrypt input that's always padded to at least a block. I think this part is needed so that
// there's always at least 2 blocks.
fn encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let pt = if input.len() < 16 { pkcs_7_pad(input, BLOCK_SIZE) } else { input.to_vec() };

    aes_cbc::encrypt(&pt, key, iv).expect("encryption works")
}

fn is_valid_padding(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let decryption = aes_cbc::decrypt(&ciphertext, &key, &iv);
    match decryption {
        Ok(_) => true,
        Err(_) => false
    }
}

// Returns (plaintext byte, intermediate byte)
fn decrypt_byte(prev_block: &[u8], target_block: &[u8], target_byte: usize, key: &[u8], iv: &[u8]) -> (u8, u8) {
    let mut mut_prev = prev_block.to_vec();
    mut_prev[target_byte] = 0;
    // Calculate known padding byte value from target. When 16 it's not 0, it's 16
    // We don't expect to lose any info with u8 conversion since target byte sould be < 16
    let known_padding = (BLOCK_SIZE - target_byte) as u8;

    loop {
        let mut ct = vec![];
        ct.append(&mut mut_prev.clone());
        ct.append(&mut target_block.to_vec());
        let is_valid = is_valid_padding(&ct, key, iv);

        if is_valid {
            //   Once it's valid, we generally know P2'[15] is 1. (This isn't 100% though?)
            // Once we know the C1'[15] that leads to valid padding...
            //   C1'[15] ^ P2'[15] = I2[15]
            //   C1'[15] ^ 1       = I2[15]
            //   And with how CBC works:
            //   I2[15] ^ C1[15] = P2[15] (decrypted byte!)

            let intermediate_byte = mut_prev[target_byte] ^ known_padding; // I = C ^ P
            let pt_byte = prev_block[target_byte] ^ intermediate_byte; // P = C ^ I
            return (pt_byte, intermediate_byte);
        } else {
            mut_prev[target_byte] += 1;
        }
    }
}

fn decrypt_block(prev_block: &[u8], target_block: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut pt: Vec<u8> = vec![0; 16];
    let mut ibytes: Vec<u8> = vec![0; 16];
    let mut prev_block = prev_block.to_vec();

    for target_byte in (0..16).rev() {
        let (pt_byte, i_byte) = decrypt_byte(&prev_block, target_block, target_byte, key, iv);
        pt[target_byte] = pt_byte;
        ibytes[target_byte] = i_byte;
        // For the next iteration, set prev block values to ones known to produce valid padding
        // after the target byte. This way we can find the target byte value, knowing that the
        // padding after will be good.
        let next_pad = (BLOCK_SIZE - target_byte) as u8 + 1;
        for idx in target_byte..16 {
            prev_block[idx] = ibytes[idx] ^ next_pad; 
        }
    }

    pt
}

// block_num should be 0 indexed
fn get_block(ciphertext: &[u8], block_num: usize) -> &[u8] {
    let start_idx = block_num * BLOCK_SIZE;
    let end_idx = (block_num + 1) * BLOCK_SIZE;
    &ciphertext[start_idx..end_idx]
}

// Attack works like so:
//
// Give target block C2, set C1'[15] to 0.
// Continue incrementing values of C1'[15] until valid. 
//   Once it's valid, we generally know P2'[15] is 1. (This isn't 100% though?)
// Once we know the C1'[15] that leads to valid padding...
//   C1'[15] ^ P2'[15] = I2[15]
//   C1'[15] ^ 1       = I2[15]
//   And with how CBC works:
//   I2[15] ^ C1[15] = P2[15] (decrypted byte!)
//
// To get more, set C1'[14] to 0, and C1'[15] such that P2'[15] is 2 (to keep valid padding)
//                                    C1'[15] = 2 ^ I2[15]
// Continue incrementing values of C1[14] until valid padding. Similarly...
//   C1'[14] ^ 2 = I2[14]
//   I2[14] ^ C1[14] = P2[14] (second decrypted byte!)
//
// Repeat until block is decrypted.
//
// To do more blocks, start at the end and chop blocks off once we know the PT.
fn attack(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let num_blocks = ciphertext.len() / 16;

    let mut pt: Vec<u8> = vec![];
    for block_num in 0..num_blocks {
        let prev_block = if block_num == 0 { iv } else { get_block(ciphertext, block_num - 1) };
        let target_block = get_block(ciphertext, block_num);
        let mut decrypted = decrypt_block(prev_block, target_block, key, iv);
        pt.append(&mut decrypted);
    }

    pt
}

#[cfg(test)]
mod tests {
    use set2::padding_oracle;
    use set2::mode_detection::{rand_bytes};
    use base64::decode as base64decode;

    #[test]
    fn encrypt_and_check_padding() {
        let key = rand_bytes(16);
        let iv = rand_bytes(16);
        let input = b"bye bye bye";

        let ciphertext = padding_oracle::encrypt(input, &key, &iv);

        assert_eq!(padding_oracle::is_valid_padding(&ciphertext, &key, &iv), true);

        let mut invalid_ciphertext = ciphertext.clone();
        invalid_ciphertext[ciphertext.len() - 1] = 17; // 17 is never valid padding
        assert_eq!(padding_oracle::is_valid_padding(&invalid_ciphertext, &key, &iv), false);
    }

    #[test]
    // NOTE: This test sometimes fails and I'm not entirely sure why. Weirdly, it seems to be
    // something with the key/iv since that's the only randomness in this test. The failure
    // surfaces as an overflow error in the loop decrypting a byte.
    fn padding_oracle_decrypt() {
        let key = rand_bytes(16);
        let iv = rand_bytes(16);
        // Possible random strings:
        // MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        // MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        // MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        // MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        // MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        // MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        // MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        // MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        // MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        // MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
        // let rand = "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==";
        let rand = "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=";
        let input = base64decode(rand).unwrap();
        let ciphertext = padding_oracle::encrypt(&input, &key, &iv);
        let plaintext = padding_oracle::attack(&ciphertext, &key, &iv);

        let pt_str = String::from_utf8(plaintext).expect("valid padding");
        println!("{:?}", pt_str);
        assert!(pt_str.contains("With the bass kicked in and the Vega's are pumpin'"));
    }
}
