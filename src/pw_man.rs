#![allow(unused)]
use crate::error::Error;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString},
};
use rand_core::{OsRng, SeedableRng};
use rs_sha512::{HasherContext, Sha512State};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::marker::PhantomData;
use std::{collections::HashMap, io::Read};
use crate::message::Message;

pub fn digest(subject: &str) -> String {
    let mut hasher = Sha512State::default().build_hasher();
    hasher.write(subject.as_bytes());
    let bytes_res = HasherContext::finish(&mut hasher);
    format!("{bytes_res:02x}")
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct PwMan {
    #[serde(alias = "masterPass")]
    master_pass: String,
    /// Maps hashes of websites to encrypted passwords
    #[serde(alias = "pwTable")]
    pw_table: HashMap<String, Vec<u8>>,
    #[serde(alias = "msgTable")]
    msg_table: HashMap<String, Message>,
    #[serde(skip_serializing)]
    key: Vec<u8>,
}

impl<'a> PwMan {
    pub fn init(passwd: &str) -> Result<Self, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let master_pass = argon2
            .hash_password(passwd.as_bytes(), &salt)
            .map_err(|e| Error::HashFailure(e))?
            .to_string();

        let key: &mut [u8; 32] = &mut [0u8; 32];
        argon2
            .hash_password_into(passwd.as_bytes(), salt.as_str().as_bytes(), key)
            .map_err(|e| Error::KeyGenFialure(e))?;

        Ok(Self {
            master_pass,
            pw_table: HashMap::new(),
            msg_table: HashMap::new(),
            key: key.to_vec(),
        })
    }

    pub fn add_pw(&mut self, website: &str, passwd: &str) -> Result<(), Error> {
        let hash = digest(website);
        let cipher = Aes256Gcm::new(self.get_key());
        //let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = &hash.as_bytes()[..12];
        let ciphertext = cipher
            .encrypt(nonce.into(), passwd.as_bytes())
            .map_err(|_| Error::EncryptionFailure)?;

        self.pw_table.insert(hash.to_string(), ciphertext);
        Ok(())
    }

    pub fn get_pw_enc(&self, website: &str) -> Option<Vec<u8>> {
        self.pw_table.get(&digest(website)).cloned()
    }

    pub fn get_pw(&self, website: &str) -> Result<Option<String>, Error> {
        let hash = digest(website);
        let enc_data = match self.pw_table.get(&hash) {
            Some(v) => v,
            None => return Ok(None),
        };
        let nonce = &hash.as_bytes()[..12];
        let cipher = Aes256Gcm::new(self.get_key());
        let plaintext = cipher
            .decrypt(nonce.into(), enc_data.as_ref())
            .map_err(|_| Error::DecryptionFailure)?;

        Ok(Some(
            plaintext.iter().map(|s| *s as char).collect::<String>(),
        ))
    }

    pub fn write_to_file(self) -> Result<(), Error> {
        let mut f = File::create("savefile").map_err(|e| Error::FileCreate(e))?;
        let bytes = to_string(&self).map_err(|e| Error::SerializationFailure(e))?;

        f.write_all(bytes.as_bytes());
        Ok(())
    }

    pub fn read_from_file(master_pw: &str) -> Result<Self, Error> {
        let mut f = File::open("savefile").map_err(|e| Error::FileOpen(e))?;
        let len = f.metadata().unwrap().len();
        let mut buf = Vec::with_capacity(len.try_into().unwrap());
        f.read_to_end(&mut buf);

        let data = &buf.iter().map(|u| *u as char).collect::<String>();

        let mut data: serde_json::Value =
            from_str(data).map_err(|e| Error::DeserializationFailure(e))?;

        let parsed_hash = PasswordHash::new(data["master_pass"].as_str().unwrap())
            .map_err(|e| Error::HashFailure(e))?;

        Argon2::default()
            .verify_password(master_pw.as_bytes(), &parsed_hash)
            .map_err(|e| Error::BadPassword(e))?;

        let salt = parsed_hash.salt.unwrap();

        let key: &mut [u8; 32] = &mut [0u8; 32];
        Argon2::default()
            .hash_password_into(master_pw.as_bytes(), salt.as_str().as_bytes(), key)
            .map_err(|e| Error::KeyGenFialure(e))?;

        data["key"] = (*key).into();

        from_str(&data.to_string()).map_err(|e| Error::DeserializationFailure(e))
    }

    pub fn rm_pw(&mut self, site: &str) -> Result<Option<String>, Error> {
        let hash = digest(site);
        let enc_data = match self.pw_table.remove(&hash) {
            Some(d) => d,
            None => return Ok(None),
        };
        let nonce = &hash.as_bytes()[..12];
        let cipher = Aes256Gcm::new(self.get_key());
        let plaintext = cipher
            .decrypt(nonce.into(), enc_data.as_ref())
            .map_err(|_| Error::DecryptionFailure)?;

        Ok(Some(
            plaintext.iter().map(|s| *s as char).collect::<String>(),
        ))
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.get_key();
        let cipher = Aes256Gcm::new(key);
        cipher.encrypt(nonce.into(), data).map_err(|_| Error::EncryptionFailure)
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.get_key();
        let cipher = Aes256Gcm::new(key);
        cipher.decrypt(nonce.into(), data).map_err(|_| Error::DecryptionFailure)
        
    }

    fn get_key(&self) -> &Key<Aes256Gcm> {
        let key = &self.key[..];
        key.into()
    }
}
