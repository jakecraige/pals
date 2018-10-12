use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;
use set2::pkcs_7_pad;

fn openssl_ecb_encrypt_block(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();

    // Must use this more complicated scheme to disable padding since we handle adding padding
    // ourselves.
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(false);
    let mut ciphertext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);

    Ok(ciphertext)
}

fn openssl_ecb_decrypt_block(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    crypter.pad(false);
    let mut plaintext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);

    Ok(plaintext)
}

fn xor_slices(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right.iter()).map(|(l, r)| l ^ r).collect()
}

// AES block size is 128 bits (16 bytes)
const BYTES_IN_BLOCK: usize = 16;

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut ciphertext: Vec<u8> = vec![];

    let mut prev_block = iv.to_vec();
    for block in data.chunks(BYTES_IN_BLOCK) {
        let padded_block = pkcs_7_pad(&block, BYTES_IN_BLOCK);
        let next_block = xor_slices(&padded_block, &prev_block);
        let mut encrypted_next_block = openssl_ecb_encrypt_block(&next_block, &key)?;

        ciphertext.append(&mut encrypted_next_block);
        prev_block = encrypted_next_block;
    }

    Ok(ciphertext)
}

fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let mut offset_data = iv.to_vec();
    offset_data.append(&mut data.to_vec());

    let plaintext: Vec<u8> = data.chunks(BYTES_IN_BLOCK)
        .zip(offset_data.chunks(BYTES_IN_BLOCK))
        .map(|(block, prev_block)| {
            // This is unsafe to unwrap. In a real impl we'd want to handle and return an err.
            let decrypted_block = openssl_ecb_decrypt_block(&block, &key).unwrap();
            xor_slices(&decrypted_block, &prev_block)
        }).flatten().collect();

    remove_padding(&plaintext)
}

#[derive(Debug, PartialEq)]
struct PaddingError(u8, u8); // expected, actual

fn remove_padding(data: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if data.len() == 0 {
        return Ok(data.to_vec());
    }

    let mut mdata = data.to_vec();
    let mut ctr = 1u8;
    let padding = mdata.pop().unwrap();

    // Walk backwards from the end and built up the counter of how many bytes of padding we find
    // that match what's expected.
    while let Some(byte) = mdata.pop() {
        // Increment counter iff it's the same, and we haven't already met the count needed
        if byte == padding && ctr != padding {
            ctr += 1;
        } else {
            // Since we pop it off in the let, but it was not padding, we need to add it back in
            // here.
            mdata.push(byte);
            break;
        }
    }

    if ctr == padding {
        Ok(mdata)
    } else {
        Err(PaddingError(padding, ctr))
    }
}

#[cfg(test)]
mod tests {
    use set2::aes_cbc;
    use std::fs::File;
    use std::io::Read;
    use base64::decode as base64decode;

    #[test]
    fn aes_cbc_encrypt_and_decrypt() {
        let data = b"Hellooooo";
        let key = b"YELLOW SUBMARINE";
        let iv = b"YELLOW SUBMARINE";

        let ciphertext = aes_cbc::encrypt(data, key, iv).unwrap();
        assert_eq!(
            ciphertext,
            b"\x3d\x88\xc2\x16\x5f\xf7\xa8\x09\x24\xe3\xb7\xae\x66\x90\x90\xa9"
        );

        let plaintext = aes_cbc::decrypt(&ciphertext, key, iv).unwrap();
        assert_eq!(plaintext, b"Hellooooo");
    }

    #[test]
    fn remove_padding() {
        // Valid padding of 7
        let plaintext = b"Hello\x07\x07\x07\x07\x07\x07\x07";
        let plaintext_no_pad = aes_cbc::remove_padding(plaintext).unwrap();
        assert_eq!(plaintext_no_pad, b"Hello");

        // Padding is 2, but there's 3 bytes of it. Should only remove two.
        let plaintext = b"Hello\x02\x02\x02";
        let plaintext_no_pad = aes_cbc::remove_padding(plaintext).unwrap();
        assert_eq!(plaintext_no_pad, b"Hello\x02");

        // Not enough padding
        let plaintext = b"Hello\x07\x07\x07\x07";
        let err = aes_cbc::remove_padding(plaintext).expect_err("expect padding error");
        assert_eq!(err, aes_cbc::PaddingError(7, 4));
    }

    #[test]
    fn aes_cbc_decrypt_example() {
        let file = read_file("src/data/challenge10.txt", true);
        let ciphertext = base64decode(&file).expect("should be decodable");
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let plaintext_bytes = aes_cbc::decrypt(&ciphertext, key, iv).unwrap();
        let plaintext = String::from_utf8(plaintext_bytes).expect("valid utf8 text");
        assert!(plaintext.contains("Lay down and boogie and play that funky music"));
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
