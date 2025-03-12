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
    FileOprationError(std::io::Error),
    BadPassword(argon2::password_hash::errors::Error),
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
            Self::FileOprationError(error) => {
                write!(f, "File Operation Error: {}", error.to_string())
            }
            Self::BadPassword(error) => write!(f, "Bassword Verifacation Error: {}", error),
        }
    }
}

impl ErrTrait for Error {}

impl Eq for Error {}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
       match (self, other) {
           (Self::BadPassword(_), Self::BadPassword(_)) => true,
           (Self::BadPassword(_), _) => false,
           (Self::FileOprationError(_), Self::FileOprationError(_)) => true,
           (Self::FileOprationError(_), _) => false,
           (Self::DeserializationFailure(_), Self::DeserializationFailure(_)) => true,
           (Self::DeserializationFailure(_), _) => false,
           (Self::HashFailure(_), Self::HashFailure(_)) => true,
           (Self::HashFailure(_), _) => false,
           (Self::EncryptionFailure, Self::EncryptionFailure) => true,
           (Self::EncryptionFailure, _) => false,
           (Self::DecryptionFailure, Self::DecryptionFailure) => true,
           (Self::DecryptionFailure, _) => false,
           (Self::KeyGenFialure(_), Self::KeyGenFialure(_)) => true,
           (Self::KeyGenFialure(_), _) => false,
           (Self::SerializationFailure(_), Self::SerializationFailure(_)) => true,
           (Self::SerializationFailure(_), _) => false,
       }
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}
