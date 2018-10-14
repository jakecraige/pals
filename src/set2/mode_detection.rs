use openssl;
use openssl::symm;
use rand::prelude::{thread_rng, Rng, random as randbool};
use set2::aes_cbc;
use set1::{bytes_to_16byte_blocks, num_duplicate_blocks};

fn rand_bytes(bytes: usize) -> Vec<u8> {
    let mut buf = vec![0; bytes];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    buf.to_vec()
}

// Generate number in range from min to max inclusive
fn rand_in_range(min: usize, max: usize) -> usize {
    let mut rng = thread_rng();
    rng.gen_range(min, max + 1)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode { ECB, CBC }

impl Mode {
    fn random() -> Mode {
        match randbool() {
            true => Mode::CBC,
            false => Mode::ECB,
        }
    }

    fn encrypt(&self, input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        match self {
            Mode::CBC => aes_cbc::encrypt(input, key, iv).expect("should work"),
            Mode::ECB => {
                let cipher = symm::Cipher::aes_128_ecb();
                symm::encrypt(cipher, key, None, input).expect("should work")
            }
        }
    }
}


fn detect_encryption_mode(ciphertext: &[u8]) -> Mode {
    let dup_blocks = num_duplicate_blocks(&bytes_to_16byte_blocks(&ciphertext));
    println!("CT: {:?}, {}", ciphertext, ciphertext.len());
    if dup_blocks > 1 {
        println!("Dups: {:?}", dup_blocks);
        Mode::ECB
    } else {
        Mode::CBC
    }
}

// Randomly encrypt input using either AES-128-ECB or AES-128-CBC.
//
// Returns the mode used so that we can write tests to verify detection.
fn encryption_oracle(input: &[u8]) -> (Mode, Vec<u8>) {
    let mut rand_input = vec![];
    rand_input.append(&mut rand_bytes(rand_in_range(5, 10)));
    rand_input.append(&mut input.to_vec());
    rand_input.append(&mut rand_bytes(rand_in_range(5, 10)));

    let key = rand_bytes(16);
    let iv = rand_bytes(16);
    let mode = Mode::random();

    (mode, mode.encrypt(&rand_input, &key, &iv))
}


#[cfg(test)]
mod tests {
    use set2::mode_detection;

    #[test]
    fn encryption_oracle() {
        let data = b"hiyo";

        let (_, ct1) = mode_detection::encryption_oracle(data);
        let (_, ct2) = mode_detection::encryption_oracle(data);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn detect_encryption() {
        // 3 16-byte blocks worth of the same data. Detection relies on detecting duplicate blocks
        //   which should not happen in CBC
        let data = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";

        // It's random, need to do it a few times or it may pass when it shouldn't
        for _ in 1..10 {
            let (mode, ct) = mode_detection::encryption_oracle(data);
            let detected_mode = mode_detection::detect_encryption_mode(&ct);
            assert_eq!(mode, detected_mode);
        }
    }
}
