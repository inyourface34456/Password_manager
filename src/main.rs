mod charsets;
mod error;
mod pw_gen;
mod pw_man;
mod tests;

use pw_gen::PwGen;
use pw_man::PwMan;

fn main() {
    let mut pw_man = PwMan::init("why tf").unwrap();
    println!("adding pw");
    pw_man.add_pw("google.com", "this is pw").unwrap();

    pw_man.add_msg("test", "test").unwrap();
    println!("added message");

    println!("message test reads: {:?}", pw_man.retrive_message("test"));

    println!("done, {:?}", pw_man.get_pw("google.com"));
    pw_man.write_to_file().unwrap();

    let pw_man_from_file = PwMan::read_from_file("why tf").unwrap();
    println!(
        "read from file: {:?}",
        pw_man_from_file.get_pw("google.com").unwrap()
    );

    let pw_gen = PwGen::default();
    println!("pw: {}", pw_gen.gen_rand_pw(30));

    let pw_gen = PwGen::new(true, true, true, true, true, false);
    println!("pw: {}", pw_gen.gen_rand_pw(30));

    let pw_gen = PwGen::new(true, true, true, true, true, true);
    println!("pw: {}", pw_gen.gen_rand_pw(30));

    let pw_gen = PwGen::default();
    println!("pw: {}", pw_gen.gen_rem_pw(5));
}
