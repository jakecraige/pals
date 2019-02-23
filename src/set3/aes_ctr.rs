use set2::aes_cbc::{openssl_ecb_encrypt_block};

const BYTES_IN_BLOCK: usize = 16;

// Encrypt with AES-CBC. Uses 16 byte blocks with a 64 bit nonce and incrementing counter.
pub fn encrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let mut output: Vec<u8> = vec![];
    let nonce_bytes = nonce.to_le_bytes();
    let mut ctr: u64 = 0;

    for input_block in input.chunks(BYTES_IN_BLOCK) {
        let mut input_pt: Vec<u8> = vec![];
        input_pt.append(&mut nonce_bytes.to_vec());
        input_pt.append(&mut ctr.to_le_bytes().to_vec());

        let keystream = openssl_ecb_encrypt_block(&input_pt, key).expect("encrypted");

        let mut ct_block: Vec<u8> = input_block
            .to_vec()
            .iter()
            .zip(keystream.iter())
            .map(|(left, right)| left ^ right)
            .collect();

        output.append(&mut ct_block);
        ctr += 1;
    }

    output
}

// Decrypt a ciphertext encrypted with AES-CBC. This is equivalent to calling encrypt with the same
// arguments but is provided for ease of readability.
fn decrypt(ciphertext: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    encrypt(ciphertext, key, nonce)
}

#[cfg(test)]
mod tests {
    use set3::aes_ctr;
    use base64::decode as base64decode;

    #[test]
    fn ctr_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let nonce: u64 = 0;
        let b64_ct = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let ct = base64decode(b64_ct).unwrap();

        let plaintext = aes_ctr::decrypt(&ct, key, nonce);

        let pt_str = String::from_utf8(plaintext).expect("valid pt");
        assert_eq!(pt_str, "Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ".to_string());
    }
}
