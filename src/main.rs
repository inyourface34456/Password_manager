mod pw_man;
mod pw_gen;
mod charsets;

use pw_gen::PwGen;
use pw_man::PwMan;
use std::io::Write;
use std::fs::File;

fn main() {
    let mut pw_man = PwMan::init("why tf");
    println!("adding pw");
    pw_man.add_pw("google.com", "this is pw");

    println!("done, {:?}", pw_man.get_pw("google.com"));
    pw_man.write_to_file();

    let pw_man_from_file = PwMan::read_from_file("why tf");
    println!("read from file: {:?}", pw_man_from_file.get_pw("google.com"));

    let pw_gen = PwGen::new(true, true, true, true, true, true);
    println!("pw: {}", pw_gen.gen_rand_pw(30));

    let pw_gen = PwGen::default();
    println!("pw: {}", pw_gen.gen_rand_pw(30));

    let pw_gen = PwGen::new(true, true, true, true, true, false);
    println!("pw: {}", pw_gen.gen_rand_pw(30));
}
