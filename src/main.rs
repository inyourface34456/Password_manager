mod pw_man;
mod serializeer;

use pw_man::PwMan;
use serializeer::serialize;

fn main() {
    let mut pw_man = PwMan::init("why tf");
    println!("adding pw");
    pw_man.add_pw("google.com", "this is pw");
    println!("done, {:?}", pw_man.get_pw("google.com"));
    pw_man.write_to_file();
}
