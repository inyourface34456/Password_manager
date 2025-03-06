#![allow(unused)]
use rs_n_bit_words;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

fn num_to_string(num: u16) -> String {
    num.to_le_bytes().iter().map(|u| *u as char).collect()
}

fn digest_to_bytes(digest: String) -> Vec<u8> {
    digest
        .as_bytes()
        .chunks(2)
        .map(|byte| {
            u8::from_str_radix(&byte.iter().map(|u| *u as char).collect::<String>(), 16).unwrap()
        })
        .collect()
}

pub fn serialize(master_pw_hash: String, data: HashMap<String, Vec<u8>>) {
    let mut file = File::create("savefile").unwrap();
    file.write_all(
        format!(
            "{}{}",
            num_to_string(master_pw_hash.len() as u16),
            master_pw_hash
        )
        .as_bytes(),
    );

    for (key, value) in data {
        file.write_all(
            "begin".as_bytes()
                .iter()
                .chain((key.len() as u16).to_le_bytes().iter())
                .chain("end hsah len".as_bytes().iter())
                .chain(digest_to_bytes(key).iter())
                .chain("end digest bytes".as_bytes().iter())
                .chain((value.len() as u16).to_le_bytes().iter())
                .chain("end value len".as_bytes().iter())
                .chain(value.iter())
                .chain("end pw_enc".as_bytes().iter())
                .map(|u| *u as char)
                .collect::<String>()
                .as_bytes(),
        );
    }
}
