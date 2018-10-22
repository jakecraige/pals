use set2::aes_cbc;
use set2::{pkcs_7_pad};

const BLOCK_SIZE: usize = 16;

fn escape_input(input: &[u8]) -> Vec<u8> {
    // This is a _very_ inefficient way to do this, but should work.
    let mut input = String::from_utf8(input.to_vec()).expect("valid string");
    input = input.replace("=", "\\=");
    input = input.replace(";", "\\;");
    input.as_bytes().to_vec()
}

// Pad input to 16 byte then encrypt
fn encrypt_with_extra(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let mut plaintext: Vec<u8> = vec![];
    plaintext.append(&mut prefix.to_vec());
    let mut input = if input.len() < 16 { pkcs_7_pad(input, BLOCK_SIZE) } else { input.to_vec() };
    input = escape_input(&input);
    plaintext.append(&mut input);
    plaintext.append(&mut suffix.to_vec());

    aes_cbc::encrypt(&plaintext, key, iv).expect("encryption works")
}

fn is_admin(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let pt_bytes = aes_cbc::decrypt(&ciphertext, &key, &iv).expect("works");
    let mut pt_str = String::new();
    for byte in pt_bytes {
        pt_str.push(byte as char);
    }
    println!("PT: {:?}", pt_str);

    pt_str.contains(";admin=true;")
}

#[cfg(test)]
mod tests {
    use set2::cbc_bitflip;
    use set2::mode_detection::{rand_bytes};
    use set2::aes_cbc;

    #[test]
    fn encrypt_with_extra_works() {
        let key = rand_bytes(16);
        let iv = rand_bytes(16);
        let input = b";admin=true00000";

        let ciphertext = cbc_bitflip::encrypt_with_extra(input, &key, &iv);
        let pt_bytes = aes_cbc::decrypt(&ciphertext, &key, &iv).expect("works");


        let pt_str = String::from_utf8(pt_bytes).unwrap();
        let expected = "comment1=cooking%20MCs;userdata=\\;admin\\=true00000;comment2=%20like%20a%20pound%20of%20bacon";
        assert_eq!(pt_str, expected);
    }

    #[test]
    fn is_admin() {
        let key = rand_bytes(16);
        let iv = rand_bytes(16);

        let ciphertext = aes_cbc::encrypt(b";admin=true;", &key, &iv).expect("works");
        assert!(cbc_bitflip::is_admin(&ciphertext, &key, &iv));

        let ciphertext = aes_cbc::encrypt(b";admin=false;", &key, &iv).expect("works");
        assert!(!cbc_bitflip::is_admin(&ciphertext, &key, &iv));
    }

    #[test]
    fn bitflip_attack() {
        let key = &rand_bytes(16);
        let iv = &rand_bytes(16);
        // Since ; or = will be escaped, we provide x so that we can easily just flip two bytes
        // x is  1111000   x is 1111000
        //       1000011        1000101
        // ; is   111011   = is  111101
        // Index 0 and 6 of the prev block should be changed
        let input = b"xadminxtruex";

        let mut ciphertext = cbc_bitflip::encrypt_with_extra(input, key, iv);

        // Add in values to flip the x's to expected values.
        // TODO: Why XOR instead of set?
        ciphertext[16] ^= 67;
        ciphertext[22] ^= 69;
        ciphertext[27] ^= 67;

        assert!(cbc_bitflip::is_admin(&ciphertext, &key, &iv));
    }
}
