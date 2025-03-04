mod pw_man;

use pw_man::PwMan;

fn main() {
    let mut pw_man = PwMan::init("why tf");
    println!("adding pw");
    pw_man.add_pw("google.com", "this is pw");
    println!("done, {:?}", pw_man.get_pw("google.com"));
}
