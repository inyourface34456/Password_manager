#![allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn creation() {
        let _pw_man = PwMan::init("pw_one").unwrap();
    }

    #[test]
    fn store_recall() {
        let mut pw_man = PwMan::init("pw_one").unwrap();
        pw_man.add_pw("example.com", "example_pw").unwrap();
        assert_eq!(
            Ok(Some("example_pw".to_owned())),
            pw_man.get_pw("example.com")
        );
    }

    #[test]
    fn write_to_disk() {
        let mut pw_man = PwMan::init("pw_one").unwrap();
        pw_man.add_pw("example.com", "example_pw").unwrap();
        pw_man.write_to_file().unwrap();
    }

    #[test]
    fn load_from_disk() {
        let pw_man = PwMan::read_from_file("pw_one").unwrap();
        assert_eq!(
            Ok(Some("example_pw".to_owned())),
            pw_man.get_pw("example.com")
        );
    }

    #[test]
    #[should_panic]
    fn load_from_disk_wrong_pw() {
        let _pw_man = PwMan::read_from_file("wrong_pw").unwrap();
    }

    #[test]
    fn rm_pw() {
        let mut pw_man = PwMan::read_from_file("pw_one").unwrap();
        assert_eq!(
            Ok(Some("example_pw".to_owned())),
            pw_man.rm_pw("example.com")
        );
        assert_eq!(Ok(None), pw_man.get_pw("exmaple.com"));
    }
}
