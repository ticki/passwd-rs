// Based on code from conradkleinespel/rustastic-password

use passstr::SecStr;
use libc::consts::os::posix88::STDIN_FILENO;
use std::io::prelude::*;
use std::io::{ stdin, Stdin, BufReader, Error, ErrorKind };
use std::io::Result as IoResult;
use std::io;
use std::ptr;
use std::fs::File;
use termios;

trait MutableByteVector {
    fn set_memory(&mut self, value: u8);
}

impl MutableByteVector for Vec<u8> {
    #[inline]
    fn set_memory(&mut self, value: u8) {
        unsafe { ptr::write_bytes(self.as_mut_ptr(), value, self.len()) };
    }
}

/// Read the password
pub fn read_password() -> IoResult<SecStr> {
    let mut term = try!(termios::Termios::from_fd(STDIN_FILENO));
    let term_orig = term;

    // Hide the password
    term.c_lflag &= !termios::ECHO;
    term.c_lflag |= termios::ECHONL;

    try!(termios::tcsetattr(STDIN_FILENO, termios::TCSANOW, &term));

    let mut password = SecStr::new();
    for ch in stdin().chars() {
        if let Ok(c) = ch {
            match c {
                '\n' => {
                    break;
                },
                '\x08' => {
                    password = SecStr::new();
                    println!("[retype password]");
                },
                _ => {
                    password.push(c);
                },
            }
        } else {
            println!("Stdin failed. Retype password");
            password = SecStr::new();
        }
    }

    termios::tcsetattr(STDIN_FILENO, termios::TCSANOW, &term_orig);

    Ok(password)
}
