#![allow(unused)]
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{
    password_hash::{PasswordHasher, SaltString}, Argon2, PasswordHash, PasswordVerifier,
};
use rand_core::{OsRng, SeedableRng};
use rs_sha512::{HasherContext, Sha512State};
use std::{collections::HashMap, io::Read};
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::io::Write;
use std::fs::File;
use serde::{Serialize, Deserialize};
use serde_json::{to_string, from_str};


pub fn digest(subject: &str) -> String {
    let mut hasher = Sha512State::default().build_hasher();
    hasher.write(subject.as_bytes());
    let bytes_res = HasherContext::finish(&mut hasher);
    format!("{bytes_res:02x}")
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct PwMan {
    master_pass: String,
    /// Maps hashes of websites to encrypted passwords
    pw_table: HashMap<String, Vec<u8>>,
    #[serde(skip_serializing)]
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

    pub fn write_to_file(self) {
        let mut f = File::create("savefile").expect("could not open file");
        let bytes = to_string(&self).expect("cannot serialze");

        f.write_all(bytes.as_bytes());
    }

    pub fn read_from_file(master_pw: &str) -> Self {
        let mut f = File::open("savefile").expect("could not open file");
        let len = f.metadata().unwrap().len();
        let mut buf = Vec::with_capacity(len.try_into().unwrap());
        f.read_to_end(&mut buf);

        let data = &buf.iter().map(|u| *u as char).collect::<String>();

        let mut data: serde_json::Value = from_str(data).expect("cannot deserlize");
        let parsed_hash = PasswordHash::new(data["master_pass"].as_str().unwrap()).expect("bad hash");
        Argon2::default().verify_password(master_pw.as_bytes(), &parsed_hash).expect("bad password");

        let salt = parsed_hash.salt.unwrap();
        
        let key: &mut [u8; 32] = &mut [0u8; 32]; 
        Argon2::default()
            .hash_password_into(master_pw.as_bytes(), salt.as_str().as_bytes(), key)
            // TODO: change to result
            .expect("failed to gen key mat");

        data["key"] = (*key).into();

        from_str(&data.to_string()).expect("cannot deserialze")
    }

    fn get_key(&self) -> &Key<Aes256Gcm> {
        let key = &self.key[..];
        key.into()
    }
}
