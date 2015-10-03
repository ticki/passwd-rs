
extern crate termios;
extern crate libc;
extern crate crypto;


mod prompt;
mod passstr;

pub fn read_password() -> &[u8] {
    prompt::read_password().unwrap().unsecure()
}

