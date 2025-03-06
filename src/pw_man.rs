#![allow(unused)]
use crate::serialize;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand_core::OsRng;
use rs_sha512::{HasherContext, Sha512State};
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;

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
    key: Vec<u8>,
}

impl<'a> PwMan {
    pub fn init(passwd: &str) -> Self {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let master_pass = argon2
            .hash_password(passwd.as_bytes(), &salt)
            // TODO: change to result
            .expect("failed to hash password")
            .to_string();

        let key: &mut [u8; 32] = &mut [0u8; 32];
        argon2
            .hash_password_into(passwd.as_bytes(), salt.as_str().as_bytes(), key)
            // TODO: change to result
            .expect("failed to gen key mat");

        Self {
            master_pass,
            pw_table: HashMap::new(),
            key: key.to_vec(),
        }
    }

    pub fn add_pw(&mut self, website: &str, passwd: &str) {
        let hash = digest(website);
        let cipher = Aes256Gcm::new(self.get_key());
        //let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = &hash.as_bytes()[..12];
        let ciphertext = cipher
            .encrypt(nonce.into(), passwd.as_bytes())
            // TODO: change to result
            .expect("encryption failed");
        self.pw_table.insert(hash.to_string(), ciphertext);
    }

    pub fn get_pw_enc(&self, website: &str) -> Option<Vec<u8>> {
        self.pw_table.get(&digest(website)).cloned()
    }

    pub fn get_pw(&self, website: &str) -> Option<String> {
        let hash = digest(website);
        let enc_data = self.pw_table.get(&hash)?;
        let nonce = &hash.as_bytes()[..12];
        let cipher = Aes256Gcm::new(self.get_key());
        let plaintext = cipher
            .decrypt(nonce.into(), enc_data.as_ref())
            // TODO: change to result
            .expect("decryption failed");
        Some(plaintext.iter().map(|s| *s as char).collect::<String>())
    }

    pub fn write_to_file(&self) {
        serialize(self.master_pass.clone(), self.pw_table.clone());
    }

    fn get_key(&self) -> &Key<Aes256Gcm> {
        let key = &self.key[..];
        key.into()
    }
}
