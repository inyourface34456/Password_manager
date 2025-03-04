#![allow(unused)]
use std::marker::PhantomData;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use rand_core::OsRng;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, Key, KeyInit, Nonce, AeadCore
};
use rs_sha512::{Sha512State, HasherContext};

pub fn digest(subject: &str) -> String {
    let mut hasher = Sha512State::default().build_hasher();
    hasher.write(subject.as_bytes());
    let bytes_res = HasherContext::finish(&mut hasher);
    format!("{bytes_res:02x}")
}

pub struct PwMan {
   master_pass: String,
   /// Maps hashes of websites to encrypted passwords
   pw_table: HashMap<String, Vec<u8>>,
   key: Vec<u8>
}

impl<'a> PwMan {
    pub fn init(passwd: &str) -> Self {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let master_pass = argon2.hash_password(passwd.as_bytes(), &salt).expect("failed to hash password").to_string();
        
        let key: &mut [u8; 32] = &mut [0u8; 32];
        argon2.hash_password_into(passwd.as_bytes(), salt.as_str().as_bytes(), key).expect("failed to gen key mat");

        Self {
            master_pass,
            pw_table: HashMap::new(),
            key: key.to_vec(),
        }
    }

    pub fn add_pw(&mut self, website: &str, passwd: &str) {
       let hash = digest(website);
       let key = &self.key[..];
       let key: &Key<Aes256Gcm> = key.into();
       let cipher = Aes256Gcm::new(key);
       //let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
       let nonce = &hash.as_bytes()[..12];
       let ciphertext = cipher.encrypt(nonce.into(), passwd.as_bytes()).expect("encryption failed");
       self.pw_table.insert(hash.to_string(), ciphertext);
    }

    pub fn get_pw_enc(&self, website: &str) -> Option<Vec<u8>> {
        self.pw_table.get(&digest(website)).cloned()
    }
}

