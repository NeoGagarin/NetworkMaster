use russh::{cipher, kex, keys::ssh_key::Algorithm, mac, Preferred};

pub fn preferred(legacy: bool) -> Preferred {
    let mut p = Preferred::DEFAULT;
    if legacy {
        p.kex.to_mut().extend([kex::DH_G1_SHA1, kex::DH_G14_SHA1]);
        p.key.to_mut().push(Algorithm::Rsa { hash: None });
        p.cipher
            .to_mut()
            .extend([cipher::AES_128_CBC, cipher::TRIPLE_DES_CBC]);
        p.mac.to_mut().push(mac::HMAC_SHA1);
    }
    p
}
