mod aes_cbc;
mod mode_detection;

// Description from RFC-2315
//
// The method shall be to pad the input at the trailing end with k - (l mod k) octets all having
// value k - (l mod k), where l is the length of the input.
fn pkcs_7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let padding = (block_size - (input.len() % block_size)) as u8;

    let mut padded = input.to_vec();
    for _ in 0..padding {
        padded.push(padding);
    }
    padded
}

#[cfg(test)]
mod tests {
    use set2;

    #[test]
    fn pkcs_7_pad() {
        let input = "YELLOW SUBMARINE";

        let output = set2::pkcs_7_pad(input.as_bytes(), 20);

        let mut expected_output = input.as_bytes().to_vec();
        expected_output.push(4);
        expected_output.push(4);
        expected_output.push(4);
        expected_output.push(4);
        assert_eq!(output, expected_output);
    }
}
