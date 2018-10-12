use openssl;
use openssl::symm;
use rand::prelude::{thread_rng, Rng, random as randbool};
use set2::aes_cbc;

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

#[derive(Debug)]
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

// Randomly encrypt input using either AES-128-ECB or AES-128-CBC.
fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rand_input = vec![];
    rand_input.append(&mut rand_bytes(rand_in_range(5, 10)));
    rand_input.append(&mut input.to_vec());
    rand_input.append(&mut rand_bytes(rand_in_range(5, 10)));

    let key = rand_bytes(16);
    let iv = rand_bytes(16);
    let mode = Mode::random();

    mode.encrypt(&rand_input, &key, &iv)
}


#[cfg(test)]
mod tests {
    use set2::mode_detection;

    #[test]
    fn encryption_oracle() {
        let data = b"hiyo";

        let ct1 = mode_detection::encryption_oracle(data);
        let ct2 = mode_detection::encryption_oracle(data);
        assert_ne!(ct1, ct2);
    }
}
