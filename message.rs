use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::fs::File;

#[derise(Serialize, Deserialize)]
pub struct Message {
    content: String,
    files: HashMap<String, Vec<u8>> 
}

impl Message {
    pub fn new(content: String, file_list: Vec<String>) -> Self {
        
    }
}
