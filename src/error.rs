use std::error::Error as ErrTrait;
use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    HashFailure(argon2::password_hash::errors::Error),
    KeyGenFialure(argon2::Error),
    EncryptionFailure,
    DecryptionFailure,
    SerializationFailure(serde_json::error::Error),
    DeserializationFailure(serde_json::error::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashFailure(error) => write!(f, "Hashing Failed: {}", error.to_string()),
            Self::KeyGenFialure(error) => write!(f, "Key Generation Failed: {}", error.to_string()),
            Self::EncryptionFailure => write!(f, "Encryption failed"),
            Self::DecryptionFailure => write!(f, "Decryption Failed"),
            Self::SerializationFailure(error) => write!(
                f,
                "Serialation failed: line: {}\ncolumn: {}\nkind: {:?}",
                error.line(),
                error.column(),
                error.classify()
            ),
            Self::DeserializationFailure(error) => write!(
                f,
                "Serialation failed: line: {}\ncolumn: {}\nkind: {:?}",
                error.line(),
                error.column(),
                error.classify()
            ),
        }
    }
}

impl ErrTrait for Error {}
