#![allow(unused)]
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

pub fn serialize(master_pw_hash: String, data: HashMap<String, Vec<u8>>) {
    let keys: Vec<&String> = data
        .keys() /*.map(|s| s.clone())*/
        .collect();
    let mut file = File::create("savefile").unwrap();
    file.write_all(
        format!(
            "{}{}",
            (master_pw_hash.len() as i8)
                .to_le_bytes()
                .iter()
                .map(|u| *u as char)
                .collect::<String>(),
            master_pw_hash
        )
        .as_bytes(),
    );
}
