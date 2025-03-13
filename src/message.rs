use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::fs::File;
use crate::error::Error;
use crate::PwMan;
use crate::pw_man::digest;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Message {
    content: String,
    files: HashMap<String, Vec<u8>>
}

impl Message {
    pub fn new(content: &str, file_list: Vec<&str>, pw_man: &PwMan) -> Result<Self, Error> {
        let mut files = HashMap::new();

        for i in file_list {
            let hash = digest(i);
            let mut f = File::open(i).map_err(|e| Error::FileOpen(e))?;
            let mut content = Vec::new();
            f.read_to_end(&mut content).map_err(|e| Error::FileRead(e))?;
            let content = pw_man.encrypt(&content, &hash.as_bytes()[..12]).map_err(|_| Error::EncryptionFailure)?;
            files.insert(hash, content);
        }

        Ok(Self {
            content: content.to_string(),
            files,
        })
    }

    pub fn get_file(&self, ctx: &PwMan, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let enc_data = match self.files.get(&digest(name)) {
            Some(f) =>f,
            None => return Ok(None),
        };
        match ctx.decrypt(enc_data, &digest(name).as_bytes()[..12]) {
            Err(e) => Err(e),
            Ok(e) => Ok(Some(e))
        }
    }
}
