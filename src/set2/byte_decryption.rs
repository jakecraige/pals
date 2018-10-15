use openssl;
use openssl::symm;
use set1::{bytes_to_16byte_blocks, num_duplicate_blocks};
use base64::decode as base64decode;

fn rand_bytes(bytes: usize) -> Vec<u8> {
    let mut buf = vec![0; bytes];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    buf.to_vec()
}

fn ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    symm::encrypt(cipher, key, None, input).expect("should work")
}

fn ecb_oracle(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut input_w_secret = input.to_vec();
    input_w_secret.append(&mut secret_data());
    ecb_encrypt(&input_w_secret, key)
}

fn is_ecb(ciphertext: &[u8]) -> bool {
    let dup_blocks = num_duplicate_blocks(&bytes_to_16byte_blocks(&ciphertext));
    dup_blocks > 1
}

fn find_byte(partial_block: &[u8], block_to_match: &[u8], key: &[u8], block_size: usize) -> Option<u8> {
    for byte in 0..=255u8 {
        // Add known byte to the known partial block
        let mut input = partial_block.to_vec();
        input.push(byte);

        // Encrypt known text and truncate into a single block
        let mut block = ecb_oracle(&input, key);
        block.truncate(block_size);

        if block == block_to_match {
            return Some(byte)
        }
    }

    None
}

fn num_zero_bytes(num: usize) -> Vec<u8> {
    (0..num).map(|_| 0u8).collect::<Vec<_>>()
}

// NOTE: Key is provided as param since I don't know how to do globals in Rust :|
fn ecb_decrypt_using_oracle(key: &[u8]) -> Vec<u8> {
    // 1. Find block size
    // TODO: Use the oracle function which makes this more difficult. This is cheating
    // Assuming > 1 byte, use length for size since padding will fill in the rest.
    let block_size = ecb_encrypt(b"A", key).len();
    println!("Block Size: {}", block_size);

    // 2. Detect it is using ECB
    // Utilize ECB duplicate blocks of same plaintext to detect ECB
    let input = num_zero_bytes(block_size*3);
    let is_ecb = is_ecb(&ecb_oracle(&input, key));
    println!("ECB?: {}", is_ecb);

    // 3. Decrypt a byte at a time to find the secret
    let mut known_input = num_zero_bytes(block_size - 1);
    let mut pt: Vec<u8> = vec![];
    // Naively loop util we can't decrypt anything anymore. Ideally this could be more precise.
    loop {
        // Select how many zero bytes (0-15) to prepend based on how far we are in the decryption
        let num_bytes = block_size - 1 - (pt.len() % block_size);
        let zero_bytes = num_zero_bytes(num_bytes);
        // Encrypt the block with the incomplete first block. This will end up shifting the secret
        // text left into the remaining bytes. We start with 1 missing, decrypt that byte, then 2,
        // etc until we decrypt the full first block.
        let enc_block = ecb_oracle(&zero_bytes, key);

        // Since we get back the full ciphertext, we need to select a single block since we're only
        // trying to decrypt a single byte. The offset is needed because after we decrypt the first
        // block (16 bytes), we must look ahead to the end of the second block to decrypt.
        let offset = (pt.len() / block_size) * block_size;
        let match_block = &enc_block[offset..(offset+block_size)];

        // Given a known input, starting a block-size - 1 zero bytes, we brute force the last byte
        // by attempting to match a known block (yay ECB). For each byte we find, we append the
        // found plaintext and shift left. `AAA?` becomes `AAB?`. With each iteration we end up
        // with one unknown byte until we find the full block. Once we do, everything still works
        // because now finding the next block, and the match is updated according to the offset.
        match find_byte(&known_input, match_block, key, block_size) {
            Some(byte) => {
                pt.push(byte);
                known_input.remove(0);
                known_input.push(byte);
            },
            None => break
        }
    }

    pt
}

fn secret_data() -> Vec<u8> {
    let data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    base64decode(data).unwrap()
}

#[cfg(test)]
mod tests {
    use set2::byte_decryption;
    use base64::decode as base64decode;

    #[test]
    fn ecb_decrypt_using_oracle() {
        let key = byte_decryption::rand_bytes(16);

        let plaintext = byte_decryption::ecb_decrypt_using_oracle(&key);

        let pt_str = String::from_utf8(plaintext).expect("valid string");
        assert!(pt_str.contains("Rollin' in my 5.0"));
    }

    fn secret_data() -> Vec<u8> {
        let data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        base64decode(data).unwrap()
    }
}
