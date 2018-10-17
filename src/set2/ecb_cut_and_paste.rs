use openssl;
use openssl::symm;

fn rand_bytes(bytes: usize) -> Vec<u8> {
    let mut buf = vec![0; bytes];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    buf.to_vec()
}

fn ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    symm::encrypt(cipher, key, None, input).expect("should work")
}

fn ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    symm::decrypt(cipher, key, None, input).expect("should work")
}

#[derive(Default)]
struct Profile {
    email: String,
    uid: String,
    role: String,
}

fn decode_cookie(cookie: &str) -> Profile {
    let mut profile = Profile::default();

    // We assume a perfectly formatted cookie
    for pair in cookie.split("&") {
        let mut kv_pair: Vec<&str> = pair.split("=").collect();
        let k = kv_pair.remove(0);
        let v = kv_pair.remove(0).to_string();

        match k {
            "email" => profile.email = v,
            "uid" => profile.uid = v,
            "role" => profile.uid = v,
            _ => unreachable!()
        }
    }

    profile
}

fn encode_cookie(profile: Profile) -> String {
    let mut encoded = String::new();

    encoded.push_str("email");
    encoded.push('=');
    encoded.push_str(&profile.email);
    encoded.push('&');
    encoded.push_str("uid");
    encoded.push('=');
    encoded.push_str(&profile.uid);
    encoded.push('&');
    encoded.push_str("role");
    encoded.push('=');
    encoded.push_str(&profile.role);

    encoded
}

fn profile_for(email: &str) -> String {
    let profile = Profile {
        email: email.to_string(),
        uid: "10".to_string(),
        role: "user".to_string()
    };

    encode_cookie(profile)
}

#[cfg(test)]
mod tests {
    use set2::ecb_cut_and_paste;

    #[test]
    fn profile_for() {
        let email = "foo@bar.com";

        // NOTE: Should not allow chars like & and =. Email `foo@bar.com&role=admin` is invalid.
        let data = ecb_cut_and_paste::profile_for(&email);

        assert_eq!(data, "email=foo@bar.com&uid=10&role=user");
    }

    #[test]
    fn gen_admin_cookie() {
        let key = b"YELLOW SUBMARINE";
        let email = "foo@bar.com";
        let cookie = ecb_cut_and_paste::profile_for(&email);
        let ct = ecb_cut_and_paste::ecb_encrypt(&cookie.as_bytes(), key);
        // NOTE: We're assuming 16 bytes blocks. It would be easy to extend this for dynamic sizing
        // using block size detection.

        // Generate admin block with valid padding. This will be used to replace the last block.
        let mut email_for_admin = "foo@bar.coadmin".to_string();
        // Add in valid PKCS#7 padding to fill our the block
        for _ in 0..11 { email_for_admin.push(11 as char); }
        let profile = ecb_cut_and_paste::profile_for(&email_for_admin);
        let ct = ecb_cut_and_paste::ecb_encrypt(&profile.as_bytes(), key);
        // Get the block, we know it's the second one since we know the input pt
        let admin_block = &ct[16..32];

        // This email is chosen so that known PT ends up being 48 bytes, putting only user role in the
        // last block with padding.
        let email_for_attack = "foofoofoofoo@barbarbarbar.com";
        let profile = ecb_cut_and_paste::profile_for(&email_for_attack);
        let mut ct = ecb_cut_and_paste::ecb_encrypt(&profile.as_bytes(), key);

        // Drop last block and add in our admin role
        ct.drain(48..);
        ct.append(&mut admin_block.to_vec());

        let pt_bytes = ecb_cut_and_paste::ecb_decrypt(&ct, key);
        let pt = String::from_utf8(pt_bytes).expect("valid plaintext");

        assert_eq!(pt, "email=foofoofoofoo@barbarbarbar.com&uid=10&role=admin");
    }
}
