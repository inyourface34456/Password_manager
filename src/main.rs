mod pw_man;
mod serializeer;

use pw_man::PwMan;
use serializeer::serialize;
use argon2::password_hash::rand_core::{OsRng, RngCore};

fn main() {
    let mut pw_man = PwMan::init("why tf");
    println!("adding pw");
    pw_man.add_pw("google.com", "this is pw");
    let mut rng = OsRng;
    
    for _ in 0..100 {
        let mut page = [0u8; 30];
        let mut passwd = [0u8; 15];
        rng.fill_bytes(&mut page);
        rng.fill_bytes(&mut passwd);
        pw_man.add_pw(&page.iter().map(|u| *u as char).collect::<String>(), &passwd.iter().map(|u| *u as char).collect::<String>())
    }

    println!("done, {:?}", pw_man.get_pw("google.com"));
    pw_man.write_to_file();
}
